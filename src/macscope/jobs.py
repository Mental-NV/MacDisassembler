"""Read job manifests and request cancellation from their live supervisor."""
import fcntl
import json
import os
import re
import stat

from .errors import Error
from .macho import read_regular
from .storage import atomic


JOB_ID = re.compile(r"[0-9a-f]{32}")
ACTIVE = {"starting", "running"}
STATUSES = ACTIVE | {"complete", "failed", "timeout", "cancelled"}
RECENT = 100
SCAN_LIMIT = 4096
SUMMARY = ("job_id", "mode", "image_id", "elapsed_seconds", "started_unix", "returncode", "error")
DETAILS = ("analysis_profile", "limits", "sandbox_sha256", "selected_entry", "source_analysis_id")


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


def view(path, record, *, detail=False):
    fields = SUMMARY + DETAILS if detail else SUMMARY
    summary = {key: record[key] for key in fields if key in record}
    token = token_for(record)
    active = record["status"] in ACTIVE
    owned = bool(active and token and leased(path))
    summary["status"] = "unknown_after_disconnect" if active and not owned else record["status"]
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
