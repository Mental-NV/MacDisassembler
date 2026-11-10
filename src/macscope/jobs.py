"""Read job manifests and request cancellation from their live supervisor."""
from contextlib import contextmanager
import fcntl
import json
import os
import re
import stat

from . import worker_lifecycle
from .errors import Error
from .macho import read_regular
from .storage import MAX_SNAPSHOT_BYTES, atomic, canonical, identity, write_json


JOB_ID = re.compile(r"[0-9a-f]{32}")
ACTIVE = {"starting", "running"}
STATUSES = ACTIVE | {"complete", "failed", "timeout", "cancelled"}
RECENT = 100
SCAN_LIMIT = 4096
SUMMARY = ("job_id", "mode", "image_id", "elapsed_seconds", "started_unix", "returncode", "error")
DETAILS = ("analysis_profile", "limits", "startup", "decompiler_timing", "sandbox_sha256", "selected_entry", "source_analysis_id",
           "resumed_from", "boundary_recovery")
ANALYSIS_REQUEST = "macscope-analysis-request/1"
IMPORT_REQUEST = "macscope-import-request/1"
QUERY_REQUEST = "macscope-query-request/1"
RESTART_REQUESTS = {"analyze": ("analysis_request", ANALYSIS_REQUEST),
                    "import": ("import_request", IMPORT_REQUEST), "query": ("query_request", QUERY_REQUEST)}
SIGNATURE_RECOVERY_FIELDS = ("dispatch_return_recovery", "direct_signature_recovery", "scalar_signature_recovery",
                             "callee_parameter_recovery", "forwarded_return_recovery", "switch_table_recovery")
QUERY_RECEIPT = "macscope-query-receipt/1"
RESTART_PROTOCOL = "macscope-restart-attempt/1"
RESTART_RECORD = "restart-attempt.json"
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
    if "resumed_from" in record:
        original = record["resumed_from"]
        if not isinstance(original, str) or not JOB_ID.fullmatch(original) or original == record["job_id"]:
            raise Error("job_manifest", "Job manifest has an invalid restart origin")
    return record


def token_for(record):
    token = record.get("ownership_token")
    return token if isinstance(token, str) and JOB_ID.fullmatch(token) else None


def restart_request(record):
    mode = record.get("mode")
    spec = RESTART_REQUESTS.get(mode) if isinstance(mode, str) else None
    if spec is None:
        return None
    key, schema = spec
    request = record.get(key)
    return request if isinstance(request, dict) and request.get("schema") == schema else None


@contextmanager
def result_publication(mode, job_id, resumed_from=None):
    location = {"job_id": resumed_from or job_id}
    if resumed_from is not None and resumed_from != job_id:
        location["attempt_job_id"] = job_id
    try:
        yield
    except Error as error:
        if error.partial is None:
            error.partial = location
        elif isinstance(error.partial, dict):
            error.partial = {**error.partial, **location}
        raise
    except OSError as error:
        raise Error(mode + "_publication", f"Could not publish the {mode} result", 8,
                    retryable=True, partial=location) from error


def record_for_resume(path, record, *, allow_reboot=False):
    if leased(path):
        raise Error("job_resume_ownership", "Cannot verify that the previous worker stopped", 8,
                    partial={"job_id": record["job_id"]})
    # An owner could have released the launch gate and exited after the
    # caller first read "starting". Read again once its lease is gone.
    if record["status"] in ACTIVE:
        record = load(path)
        if record["status"] in ACTIVE and not worker_lifecycle.disconnected_exit_confirmed(record, allow_reboot=allow_reboot):
            raise Error("job_resume_ownership", "Cannot verify that the previous worker stopped", 8,
                        partial={"job_id": record["job_id"]})
    return record


def ownership_history(project, error_code):
    with os.scandir(project.path / "jobs") as entries:
        for index, entry in enumerate(entries):
            if index == SCAN_LIMIT:
                raise Error(error_code, "Worker ownership check exceeded its job history limit", 8)
            if not JOB_ID.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                continue
            candidate = project.path / "jobs" / entry.name / "job.json"
            try:
                try:
                    candidate.lstat()
                except FileNotFoundError:
                    continue  # A job without a manifest has not reached its launch gate.
                record = load(candidate)
            except (Error, OSError) as error:
                raise Error(error_code, "Cannot verify worker ownership from the job history", 8,
                            partial={"job_id":entry.name}) from error
            yield candidate, record


def verify_engine_writer_stopped(project):
    """Check previous engine writers while the caller holds the project writer lock."""
    for path, record in ownership_history(project, "writer_history"):
        if record["status"] not in ACTIVE or record.get("mode") == "query":
            continue
        try:
            record_for_resume(path, record, allow_reboot=True)
        except Error as error:
            if error.code != "job_resume_ownership":
                raise
            raise Error("writer_conflict", "An earlier headless project writer may still be running", 8,
                        retryable=True, partial=error.partial) from error


def record_restart_attempt(path, attempt):
    original = attempt.get("resumed_from")
    if original is None:
        return
    if not isinstance(original, str) or not JOB_ID.fullmatch(original) or original == attempt["job_id"]:
        raise Error("job_restart_record", "Invalid original job for restart")
    source = path.parent.parent / original / "job.json"
    root = load(source)
    if ("resumed_from" in root or root.get("mode") != attempt.get("mode")
            or root.get("image_id") != attempt.get("image_id")):
        raise Error("job_restart_record", "Restart attempt does not match the original job")
    write_json(source.with_name(RESTART_RECORD), {
        "schema": RESTART_PROTOCOL, "original": original, "attempt": attempt["job_id"],
    }, force=True)


def verify_restart_stopped(project, path, original):
    root = original["job_id"]
    restart = path.with_name(RESTART_RECORD)
    try:
        restart.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise Error("job_restart_record", "Cannot access the recorded restart attempt") from error
    else:
        try:
            link = json.loads(read_regular(restart, 4096))
        except (Error, OSError, ValueError, RecursionError) as error:
            raise Error("job_restart_record", "Cannot verify the recorded restart attempt") from error
        if (not isinstance(link, dict) or link.keys() != {"schema", "original", "attempt"}
                or link["schema"] != RESTART_PROTOCOL or link["original"] != root
                or not isinstance(link["attempt"], str) or not JOB_ID.fullmatch(link["attempt"])):
            raise Error("job_restart_record", "Invalid recorded restart attempt")
        try:
            attempt_path, attempt = get(project, link["attempt"])
        except (Error, OSError) as error:
            raise Error("job_restart_record", "Recorded restart attempt is unavailable") from error
        if (attempt.get("resumed_from") != root or attempt.get("mode") != original.get("mode")
                or attempt.get("image_id") != original.get("image_id")):
            raise Error("job_restart_record", "Recorded restart attempt does not match the original job")
        record_for_resume(attempt_path, attempt)
    if original.get("restart_protocol") == RESTART_PROTOCOL:
        return

    # Earlier launches recorded their parent only on the attempt itself.
    descendants = {}
    for candidate, record in ownership_history(project, "job_resume_ownership"):
        if "resumed_from" in record:
            state = {key: record[key] for key in ("job_id", "status")}
            descendants.setdefault(record["resumed_from"], []).append((candidate, state))
    pending = [root]
    while pending:
        for candidate, record in descendants.get(pending.pop(), ()):
            record_for_resume(candidate, record)
            pending.append(record["job_id"])


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


def query_request(project, image, function, source, revision, hints, *, signature_recovery=None,
                  address_selection=None):
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
    if address_selection is not None:
        request["address_selection"] = address_selection
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
            or result.get("address_selection") != request.get("address_selection")
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
