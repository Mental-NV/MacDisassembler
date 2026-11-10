"""Portable, append-only transfer of a selected image's annotation history."""
from datetime import datetime
import json
import re
import sqlite3

from . import annotations
from .errors import Error
from .macho import read_regular
from .storage import canonical


SCHEMA = "macscope-annotations/1"
MAX_BYTES = 64 * 1024 * 1024
PROVENANCE_TABLE = """
CREATE TABLE IF NOT EXISTS annotation_transfer_sources (
    revision INTEGER PRIMARY KEY REFERENCES annotation_revisions(revision),
    source_project_id TEXT NOT NULL,
    source_revision INTEGER NOT NULL
)
"""
FIELDS = (
    "engine_entry", "instruction", "kind", "analysis_id", "value", "previous_value", "author", "created_at",
    "source_project_id", "source_revision",
)


def fingerprint(image):
    return {key: image[key] for key in ("image_id", "arch", "sha256")}


def read_history(db, project, image_id):
    tables = {name for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "annotation_revisions" not in tables:
        return []
    imported = "annotation_transfer_sources" in tables
    provenance = ("COALESCE(s.source_project_id, ?), COALESCE(s.source_revision, r.revision)"
                  if imported else "?, r.revision")
    source = ("LEFT JOIN annotation_transfer_sources s ON s.revision=r.revision" if imported else "")
    rows = []
    for row in db.execute(
        "SELECT r.engine_entry, r.instruction, r.kind, r.analysis_id, r.value, r.previous_value, "
        f"r.author, r.created_at, {provenance} FROM annotation_revisions r {source} "
        "WHERE r.image_id=? ORDER BY r.revision",
        (project.project_id, image_id),
    ):
        portable = dict(zip(FIELDS, row))
        portable["instruction"] = portable["instruction"] or None
        rows.append(portable)
    return rows


def export(project, image):
    with project.db() as db:
        db.execute("BEGIN")
        rows = read_history(db, project, image["image_id"])
    # Include space for the pretty-printed envelope and indentation.
    if sum(len(canonical(row)) + 256 for row in rows) > MAX_BYTES - 4096:
        raise Error("annotation_transfer_limit", "Annotation history exceeds the portable file limit", 7)
    return {"schema": SCHEMA, "image": fingerprint(image), "revisions": rows}


def load(path):
    def unique_fields(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("Duplicate field in annotation file")
        return result

    try:
        envelope = json.loads(read_regular(path, MAX_BYTES), object_pairs_hook=unique_fields)
    except (ValueError, RecursionError) as error:
        raise Error("annotation_transfer_format", "Invalid annotation JSON") from error
    if (not isinstance(envelope, dict) or envelope.get("command") != "annotations export"
            or envelope.get("status") != "complete"):
        raise Error("annotation_transfer_format", "Expected a complete annotations export")
    bundle = envelope.get("data")
    if (not isinstance(bundle, dict) or bundle.get("schema") != SCHEMA
            or set(bundle) != {"schema", "image", "revisions"} or not isinstance(bundle["revisions"], list)):
        raise Error("annotation_transfer_format", "Unsupported annotation transfer format")
    if len(bundle["revisions"]) > annotations.MAX_REVISIONS:
        raise Error("annotation_transfer_limit", "Too many annotation revisions", 7)
    return bundle


def validate(rows):
    sources, latest = set(), {}
    for row in rows:
        if not isinstance(row, dict) or row.keys() != set(FIELDS):
            raise Error("annotation_transfer_format", "Invalid annotation revision fields")
        if (not isinstance(row["source_project_id"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", row["source_project_id"])
                or type(row["source_revision"]) is not int or not 0 < row["source_revision"] < 1 << 63
                or not isinstance(row["analysis_id"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", row["analysis_id"])):
            raise Error("annotation_transfer_format", "Invalid annotation provenance")
        source = row["source_project_id"], row["source_revision"]
        if source in sources:
            raise Error("annotation_transfer_format", "Duplicate annotation revision provenance")
        sources.add(source)
        kind, entry, instruction = row["kind"], row["engine_entry"], row["instruction"]
        if (kind not in ("name", "comment", *annotations.TYPE_HINT_KINDS) or not isinstance(entry, str)
                or (instruction is not None and (kind != "comment" or not isinstance(instruction, str)
                    or not re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})", instruction)))):
            raise Error("annotation_transfer_format", "Invalid annotation scope")
        annotations.valid_text(entry, "engine entry", 256)
        if not isinstance(row["author"], str) or not isinstance(row["created_at"], str):
            raise Error("annotation_transfer_format", "Invalid annotation author or timestamp")
        annotations.valid_text(row["author"], "author", 128)
        timestamp = annotations.valid_text(row["created_at"], "timestamp", 64)
        try:
            if datetime.fromisoformat(timestamp).tzinfo is None:
                raise ValueError("Missing timezone")
        except ValueError as error:
            raise Error("annotation_transfer_format", "Invalid annotation timestamp") from error
        scope = entry, instruction, kind
        prior = latest.get(scope, {}).get("value")
        value = row["value"]
        if prior != row["previous_value"] or value == prior or (value is not None and not isinstance(value, str)):
            raise Error("annotation_transfer_format", "Invalid annotation revision chain")
        if value is not None:
            if kind == "return_type":
                annotations.return_type(value)
            elif kind == "parameter_types":
                annotations.parameter_types(value)
            else:
                annotations.valid_text(value, kind, 256 if kind == "name" else 4096,
                                       multiline=kind == "comment")
        latest[scope] = row
    return [row for row in latest.values() if row["value"] is not None]


def apply(project, image, snapshot, bundle, accept_type_hints):
    """Append the exact missing suffix while the caller holds the project lock."""
    if bundle["image"] != fingerprint(image):
        raise Error("annotation_transfer_image", "Annotation export belongs to a different imported image", 3)
    incoming = bundle["revisions"]
    active = validate(incoming)
    with project.db(False) as db:
        db.execute("BEGIN IMMEDIATE")
        existing = read_history(db, project, image["image_id"])
        shared = min(len(existing), len(incoming))
        if existing[:shared] != incoming[:shared]:
            raise Error("annotation_transfer_conflict", "Destination annotation history has diverged", 8)
        suffix = incoming[len(existing):]
        if not suffix:
            return 0
        if any(row["source_project_id"] == project.project_id for row in suffix):
            raise Error("annotation_transfer_conflict", "Incoming revisions claim missing destination history", 8)
        if not accept_type_hints and any(row["kind"] in annotations.TYPE_HINT_KINDS for row in suffix):
            raise Error("type_hint_acceptance", "Pass --accept-type-hints to import type hint revisions", 2)
        functions = {f["engine_entry"]: f for f in snapshot["functions"]}
        hints = [row for row in active if row["kind"] in annotations.TYPE_HINT_KINDS]
        if len(hints) > annotations.MAX_TYPE_HINTS:
            raise Error("type_hint_limit", "Image type hint limit reached", 7)
        for row in active:
            function = functions.get(row["engine_entry"])
            if function is None:
                raise Error("annotation_transfer_target", "An active annotation has no matching function", 3)
            if row["kind"] in annotations.TYPE_HINT_KINDS and (
                function["entry_va"] is None or function["is_external"] or function["is_thunk"]
            ):
                raise Error("type_hint_function", "Type hints require a non-thunk function in the image", 3)
            annotations.instruction_at(function, row["instruction"])
        db.execute(annotations.SCHEMA)
        db.execute(annotations.INDEX)
        db.execute(PROVENANCE_TABLE)
        if db.execute("SELECT COUNT(*) FROM annotation_revisions").fetchone()[0] + len(suffix) > annotations.MAX_REVISIONS:
            raise Error("annotation_limit", "Project annotation revision limit reached", 7)
        for row in suffix:
            revision = db.execute(
                annotations.INSERT,
                (image["image_id"], row["engine_entry"], row["instruction"] or "", row["kind"],
                 row["analysis_id"], row["value"], row["previous_value"], row["author"], row["created_at"]),
            ).lastrowid
            db.execute("INSERT INTO annotation_transfer_sources VALUES (?,?,?)",
                       (revision, row["source_project_id"], row["source_revision"]))
    return len(suffix)
