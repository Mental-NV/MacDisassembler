"""Read job manifests and request cancellation from their live supervisor."""
import fcntl
import json
import os
import re
import stat

from . import worker_lifecycle
from .errors import Error
from .macho import read_regular
from .storage import MAX_SNAPSHOT_BYTES, atomic, canonical, identity


JOB_ID = re.compile(r"[0-9a-f]{32}")
ACTIVE = {"starting", "running"}
STATUSES = ACTIVE | {"complete", "failed", "timeout", "cancelled"}
RECENT = 100
SCAN_LIMIT = 4096
SUMMARY = ("job_id", "mode", "image_id", "elapsed_seconds", "started_unix", "returncode", "error")
DETAILS = ("analysis_profile", "limits", "sandbox_sha256", "selected_entry", "source_analysis_id",
           "resumed_from", "boundary_recovery")
ANALYSIS_REQUEST = "macscope-analysis-request/1"
IMPORT_REQUEST = "macscope-import-request/1"
QUERY_REQUEST = "macscope-query-request/1"
SIGNATURE_RECOVERY_FIELDS = ("dispatch_return_recovery", "direct_signature_recovery", "scalar_signature_recovery",
                             "callee_parameter_recovery", "forwarded_return_recovery", "switch_table_recovery")
QUERY_RECEIPT = "macscope-query-receipt/1"
PUBLISH = """
CREATE TABLE IF NOT EXISTS analysis_publications (
    job_id TEXT PRIMARY KEY,
    analysis_id TEXT NOT NULL REFERENCES analyses(id),
    resumed_from TEXT UNIQUE
)
"""
PUBLISH_IMPORT = """
CREATE TABLE IF NOT EXISTS import_publications (
    job_id TEXT PRIMARY KEY,
    image_id TEXT NOT NULL REFERENCES images(id),
    resumed_from TEXT UNIQUE
)
"""


def claim(manifest):
    fd = os.open(manifest.with_suffix(".owner.lock"),
                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Error("job_lease", "Expected a regular job ownership file", 8)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    return fd


def leased(manifest):
    try:
        fd = os.open(manifest.with_suffix(".owner.lock"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise Error("job_lease", "Could not verify the job ownership file", 8) from error
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(fd)
    return False


def cancellation_path(manifest, token):
    return manifest.with_name("cancel-" + token)


def cancel_requested(manifest, token):
    try:
        return stat.S_ISREG(cancellation_path(manifest, token).lstat().st_mode)
    except FileNotFoundError:
        return False


def load(path):
    try:
        record = json.loads(read_regular(path, 1024 * 1024))
    except (ValueError, RecursionError) as error:
        raise Error("job_manifest", "Invalid job manifest JSON") from error
    if (not isinstance(record, dict) or record.get("job_id") != path.parent.name
            or not isinstance(record.get("status"), str) or record["status"] not in STATUSES):
        raise Error("job_manifest", "Job manifest identity or state is invalid")
    return record


def token_for(record):
    token = record.get("ownership_token")
    return token if isinstance(token, str) and JOB_ID.fullmatch(token) else None


def record_for_resume(path, record):
    if leased(path):
        raise Error("job_resume_ownership", "Cannot verify that the previous worker stopped", 8)
    # An owner could have released the launch gate and exited after the
    # caller first read "starting". Read again once its lease is gone.
    if record["status"] in ACTIVE:
        record = load(path)
        if record["status"] in ACTIVE and not worker_lifecycle.disconnected_exit_confirmed(record):
            raise Error("job_resume_ownership", "Cannot verify that the previous worker stopped", 8)
    return record


def view(path, record, *, detail=False):
    lease = record["status"] in ACTIVE and leased(path)
    if not lease and record["status"] in ACTIVE and record.get("launch_protocol") == worker_lifecycle.PROTOCOL:
        record = load(path)
    fields = SUMMARY + DETAILS if detail else SUMMARY
    summary = {key: record[key] for key in fields if key in record}
    token = token_for(record)
    active = record["status"] in ACTIVE
    owned = bool(token and lease)
    status = record["status"]
    if active and not owned:
        if not lease and worker_lifecycle.disconnected_exit_confirmed(record):
            status = "stopped_after_disconnect"
        else:
            status = "unknown_after_disconnect"
    summary["status"] = status
    summary["cancellation_requested"] = bool(owned and cancel_requested(path, token))
    if detail:
        deps = record.get("dependencies", {})
        if not isinstance(deps, dict):
            raise Error("job_manifest", "Invalid job dependency metadata")
        summary["engine"] = {key: value for key, value in deps.items()
                             if key.endswith("_sha256") or key in ("ghidra_version", "jdk_version", "host_arch")}
    return summary


def get(project, job_id):
    if not JOB_ID.fullmatch(job_id):
        raise Error("job_id", "Expected an exact 32-character job ID", 2)
    path = project.path / "jobs" / job_id / "job.json"
    try:
        return path, load(path)
    except Error as error:
        if error.code == "path_unavailable":
            raise Error("job_missing", "Job manifest is unavailable in this project", 2) from error
        raise


def recent(project):
    manifests, gaps = [], set()
    with os.scandir(project.path / "jobs") as entries:
        for index, entry in enumerate(entries):
            if index == SCAN_LIMIT:
                gaps.add("job_scan_limit")
                break
            if not JOB_ID.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                continue
            path = project.path / "jobs" / entry.name / "job.json"
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue  # A supervisor may still be preparing this job.
            manifests.append((info.st_mtime_ns, path))
    if len(manifests) > RECENT:
        gaps.add("job_history_limit")
    rows = []
    for _, path in sorted(manifests, reverse=True)[:RECENT]:
        try:
            rows.append(view(path, load(path)))
        except (Error, OSError):
            gaps.add("job_manifest_unavailable")
    return rows, sorted(gaps)


def request_cancel(path, record):
    if record["status"] == "cancelled":
        return {"job_id": record["job_id"], "status": "cancelled"}
    token = token_for(record)
    if record["status"] not in ACTIVE or token is None or not leased(path):
        raise Error("job_not_active", "The job has no active owner to accept cancellation", 8)
    marker = cancellation_path(path, token)
    try:
        atomic(marker, b"")
    except Error as error:
        if error.code != "output_exists" or not cancel_requested(path, token):
            raise
    return {"job_id": record["job_id"], "status": "cancellation_requested"}


def analysis_request(project, image, recovery=None):
    request = {
        "schema": ANALYSIS_REQUEST,
        "project_id": project.project_id,
        "image_id": image["image_id"],
        "artifact_sha256": image["artifact_sha256"],
        "slice_sha256": image["sha256"],
        "import_baseline_sha256": image["engine_baseline_sha256"],
        "previous_analysis_id": image["active_analysis"],
    }
    if recovery is not None:
        request["boundary_recovery"] = recovery
    return request


def query_request(project, image, function, source, revision, hints, *, signature_recovery=None):
    program_sha256 = source.get("analysis_program_sha256")
    if not isinstance(program_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", program_sha256):
        raise Error("analysis_program_integrity", "Saved analyzed Program identity is missing; rerun analyze")
    request = {
        "schema": QUERY_REQUEST,
        "project_id": project.project_id,
        "image_id": image["image_id"],
        "slice_sha256": image["sha256"],
        "artifact_sha256": image["artifact_sha256"],
        "source_analysis_id": image["active_analysis"],
        "source_snapshot_sha256": source["snapshot_sha256"],
        "source_program_sha256": program_sha256,
        "function_id": function["function_id"],
        "entry_va": function["entry_va"],
        "annotation_revision": revision,
        "type_hint_view_id": identity({"source_analysis_id": image["active_analysis"], "hints": hints})
        if hints is not None else None,
    }
    if signature_recovery is not None:
        key, recovery = signature_recovery
        request[key] = recovery
    return request


def query_receipt(project, job_id, request):
    if not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id) or not isinstance(request, dict):
        raise Error("query_receipt", "Invalid recorded query result identity")
    path = project.path / "jobs" / job_id / "query-result.json"
    if not path.exists() and not path.is_symlink():
        return None
    try:
        receipt = json.loads(read_regular(path, MAX_SNAPSHOT_BYTES))
        result = receipt["result"]
        origin = result["data"]["origin"]
        producer_id = origin["job_id"]
    except (ValueError, KeyError, TypeError, RecursionError) as error:
        raise Error("query_receipt", "Invalid recorded query result") from error
    if (receipt.get("schema") != QUERY_RECEIPT or receipt.get("request_sha256") != identity(request)
            or receipt.get("result_sha256") != identity(result)
            or not isinstance(producer_id, str) or not JOB_ID.fullmatch(producer_id)
            or result["data"].get("image_id") != request.get("image_id")
            or result["data"].get("function_id") != request.get("function_id")
            or result["data"].get("entry_va") != request.get("entry_va")
            or result.get("analysis_id") != request.get("source_analysis_id")):
        raise Error("query_receipt", "Recorded query result differs from its request")
    for field in SIGNATURE_RECOVERY_FIELDS:
        recovery = request.get(field)
        reported = origin.get(field)
        if (recovery is None and reported is not None or recovery is not None and (
                not isinstance(recovery, dict) or not isinstance(reported, dict)
                or any(reported.get(key) != value for key, value in recovery.items()))):
            raise Error("query_receipt", "Recorded signature decision differs from its query request")
    _, producer = get(project, producer_id)
    if (producer.get("mode") != "query" or producer["status"] != "complete"
            or producer.get("query_request") != request
            or (producer_id != job_id and producer.get("resumed_from") != job_id)):
        raise Error("query_receipt", "Recorded query result differs from its producing job")
    return result


def publish_query(project, job_id, request, result):
    path = project.path / "jobs" / job_id / "query-result.json"
    receipt = {"schema": QUERY_RECEIPT, "request_sha256": identity(request),
               "result_sha256": identity(result), "result": result}
    payload = canonical(receipt) + b"\n"
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise Error("query_result_limit", "Fresh query result exceeds its read limit", 7,
                    partial={"job_id": job_id})
    try:
        atomic(path, payload, mode=0o400)
    except Error as error:
        if error.code != "output_exists":
            raise
        existing = query_receipt(project, job_id, request)
        if existing is None:
            raise
        return existing
    return result


def publication(project, job_id, mode="analyze"):
    if mode == "import":
        table, columns = "import_publications", ("job_id", "image_id", "resumed_from")
    else:
        table, columns = "analysis_publications", ("job_id", "analysis_id")
    with project.db() as db:
        db.execute("BEGIN")
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name=? AND type='table'", (table,)).fetchone():
            return None
        row = db.execute(
            f"SELECT {', '.join(columns)} FROM {table} WHERE job_id=? OR resumed_from=?",
            (job_id, job_id),
        ).fetchone()
    return dict(zip(columns, row)) if row else None
