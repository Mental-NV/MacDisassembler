"""Immutable slice import requests and crash-recoverable baseline publication."""
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import sqlite3

from . import engine, jobs
from .errors import Error
from .macho import checked_path, inspect_bytes, read_regular
from .storage import atomic, canonical, write_json


SHA256 = re.compile(r"[0-9a-f]{64}")
LOADER_FIELDS = ("executable_format", "language_id", "compiler_spec_id", "executable_sha256")


def request_for(project, image):
    return {
        "schema": jobs.IMPORT_REQUEST,
        "project_id": project.project_id,
        "image_id": image["image_id"],
        "artifact_sha256": image["artifact_sha256"],
        "slice_sha256": image["sha256"],
        "input_name": image["input_name"],
        "bundle_image": image.get("bundle_image"),
    }


def restore_request(project, request, image_id):
    if (request.get("project_id") != project.project_id or request.get("image_id") != image_id
            or not all(isinstance(request.get(k), str) and SHA256.fullmatch(request[k])
                       for k in ("image_id", "artifact_sha256", "slice_sha256"))):
        raise Error("job_resume_inputs", "The import request belongs to a different project or image", 8)
    name = request.get("input_name")
    origin = request.get("bundle_image")
    if (not isinstance(name, str) or not name or name in (".", "..") or "/" in name or "\0" in name):
        raise Error("job_manifest", "Invalid recorded import filename")
    if origin is not None:
        if (not isinstance(origin, dict) or set(origin) != {"relative_path", "main_executable"}
                or not isinstance(origin["relative_path"], str) or type(origin["main_executable"]) is not bool):
            raise Error("job_manifest", "Invalid recorded bundle image")
        relative = PurePosixPath(origin["relative_path"])
        if (relative.is_absolute() or ".." in relative.parts or relative.name != name
                or relative.as_posix() != origin["relative_path"]):
            raise Error("job_manifest", "Invalid recorded bundle image path")
    original = read_regular(project.path / "inputs" / (request["artifact_sha256"] + ".artifact"))
    if hashlib.sha256(original).hexdigest() != request["artifact_sha256"]:
        raise Error("input_integrity", "Immutable artifact digest differs from the recorded import")
    inspected = inspect_bytes(original, allow_arm64e=True)
    matching = [s for s in inspected["slices"] if s["image_id"] == image_id]
    if len(matching) != 1:
        raise Error("job_resume_inputs", "The recorded slice is absent from the immutable artifact", 8)
    image = dict(matching[0], artifact_sha256=request["artifact_sha256"], input_name=name)
    if image["arch"] == "arm64e":
        raise Error("unsupported_arch", "arm64e is available for data-only inspection", 3)
    if origin is not None:
        image["bundle_image"] = origin
    if request_for(project, image) != request:
        raise Error("job_resume_inputs", "Immutable slice metadata differs from the recorded import", 8)
    return image, original


def stage_inputs(project, image, original):
    artifact = project.path / "inputs" / (image["artifact_sha256"] + ".artifact")
    if not artifact.exists():
        atomic(artifact, original, mode=0o400)
    elif hashlib.sha256(read_regular(artifact)).hexdigest() != image["artifact_sha256"]:
        raise Error("input_integrity", "Existing immutable artifact is corrupt")
    snap = project.path / "inputs" / (image["image_id"] + ".macho")
    if not snap.exists():
        start, size = int(image["offset"], 16), int(image["size"], 16)
        atomic(snap, original[start:start + size], mode=0o400)
    elif hashlib.sha256(read_regular(snap)).hexdigest() != image["sha256"]:
        raise Error("input_integrity", "Existing immutable slice is corrupt")


def publish(project, image, journal, destination, resumed_from):
    job_id = journal["job_id"]
    source = project.path / "jobs" / job_id / "program"
    if destination.is_symlink() or source.is_symlink():
        raise Error("import_baseline_conflict", "A prepared import Program is a symbolic link", 8)
    if destination.exists() and source.exists():
        raise Error("import_baseline_conflict", "Both staged and promoted import Programs exist", 8)
    baseline = destination if destination.exists() else source
    checked_path(baseline, directory=True)
    digest = journal["program_sha256"]
    if engine.tree_digest(baseline) != digest:
        raise Error("baseline_integrity", "The prepared import Program differs from its recorded digest")
    try:
        if baseline == source:
            os.rename(source, destination)
        for parent in (source.parent, destination.parent):
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    except OSError as error:
        raise Error("import_publication", "Could not promote the prepared import Program", 8, retryable=True) from error
    image = dict(image, loader_evidence=journal["loader_evidence"],
                 import_dependencies=journal["dependencies"], engine_baseline_sha256=digest)
    try:
        with project.db(False) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(jobs.PUBLISH_IMPORT)
            changed = db.execute(
                "INSERT INTO images(id,arch,metadata,imported) VALUES(?,?,?,1) "
                "ON CONFLICT(id) DO UPDATE SET arch=excluded.arch, metadata=excluded.metadata, imported=1 "
                "WHERE images.imported=0 AND images.active_analysis IS NULL",
                (image["image_id"], image["arch"], canonical(image).decode()),
            )
            if changed.rowcount != 1:
                raise Error("import_publication", "The image already has a committed import", 8)
            db.execute("INSERT INTO import_publications(job_id,image_id,resumed_from) VALUES(?,?,?)",
                       (job_id, image["image_id"], resumed_from))
    except sqlite3.Error as error:
        raise Error("import_publication", "Could not commit the import and its receipt", 8, retryable=True) from error
    return job_id


def import_slice(project, image, original, args, deps, *, resumed_from=None):
    """Stage one verified slice, or finish an already prepared publication."""
    stage_inputs(project, image, original)
    request = request_for(project, image)
    destination = project.path / "engine" / image["image_id"]
    journal_path = destination.with_suffix(".import.json")
    sandbox_sha256 = hashlib.sha256(engine.profile(project, deps).encode()).hexdigest()
    if journal_path.exists() or journal_path.is_symlink():
        try:
            journal = json.loads(read_regular(journal_path, 1024 * 1024))
        except (ValueError, RecursionError) as error:
            raise Error("import_journal", "Invalid prepared import journal") from error
        if (not isinstance(journal, dict) or journal.get("request") != request
                or journal.get("dependencies") != deps
                or journal.get("sandbox_sha256") != sandbox_sha256
                or journal.get("limits") != engine.worker_limits(args, args.max_functions)):
            raise Error("import_baseline_conflict", "The prepared import has a different input or worker request", 8)
        job_id, digest = journal.get("job_id"), journal.get("program_sha256")
        evidence = journal.get("loader_evidence")
        prior = journal.get("resumed_from")
        if (not isinstance(job_id, str) or not jobs.JOB_ID.fullmatch(job_id)
                or not isinstance(digest, str) or not SHA256.fullmatch(digest)
                or not isinstance(evidence, dict) or set(evidence) != set(LOADER_FIELDS)
                or evidence["executable_sha256"] != image["sha256"]
                or (prior is not None and (not isinstance(prior, str) or not jobs.JOB_ID.fullmatch(prior)))):
            raise Error("import_journal", "Invalid prepared import provenance")
        if resumed_from is not None and resumed_from not in (job_id, prior):
            raise Error("import_baseline_conflict", "The prepared import belongs to a different attempt", 8)
        if prior is not None and resumed_from == job_id:
            raise Error("job_resume_conflict", "Resume the original attempt to finish this prepared import", 8,
                        partial={"job_id": prior})
        return publish(project, image, journal, destination, prior or resumed_from)
    if destination.exists() or destination.is_symlink():
        raise Error("engine_project_exists", "An import baseline exists without a verified publication journal", 8)
    raw, job = engine.run(project, image, "import", args, deps, import_request=request, resumed_from=resumed_from)
    if raw.get("validation", {}).get("headless_analysis_enabled") is not False:
        raise Error("import_analysis", "Import did not disable autoanalysis", 10)
    source = project.path / "jobs" / job["job_id"] / "program"
    checked_path(source, directory=True)
    journal = {
        "request": request, "dependencies": deps, "limits": engine.worker_limits(args, args.max_functions),
        "sandbox_sha256": sandbox_sha256,
        "job_id": job["job_id"], "resumed_from": resumed_from,
        "program_sha256": engine.tree_digest(source), "loader_evidence": {k: raw[k] for k in LOADER_FIELDS},
    }
    write_json(journal_path, journal)
    return publish(project, image, journal, destination, resumed_from)
