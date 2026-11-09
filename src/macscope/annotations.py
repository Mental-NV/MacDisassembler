"""Append-only user labels and comments, separate from engine snapshots."""
from datetime import datetime, timezone
import re
import sqlite3

from .errors import Error


MAX_REVISIONS = 10000
MAX_TYPE_HINTS = 128
RETURN_TYPES = {"void","bool",*(f"{sign}int{width}_t" for sign in ("","u") for width in (8,16,32,64))}

SCHEMA = """
CREATE TABLE IF NOT EXISTS annotation_revisions (
    revision INTEGER PRIMARY KEY,
    image_id TEXT NOT NULL,
    analysis_id TEXT NOT NULL,
    engine_entry TEXT NOT NULL,
    instruction TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT,
    previous_value TEXT,
    author TEXT NOT NULL,
    created_at TEXT NOT NULL
)
"""
INDEX = """
CREATE INDEX IF NOT EXISTS annotation_scope
ON annotation_revisions(image_id, engine_entry, instruction, kind, revision)
"""


def valid_text(value, field, limit, *, multiline=False):
    allowed = "\n\t" if multiline else ""
    if (not value.strip() or any(not char.isprintable() and char not in allowed for char in value)
            or len(value.encode("utf-8")) > limit):
        raise Error("annotation_text", f"Invalid {field}; expected printable text within {limit} bytes", 2)
    return value


def record(row):
    result = dict(row)
    result["instruction"] = result["instruction"] or None
    result["origin"] = "user_supplied"
    return result


def revise(project, image_id, analysis_id, engine_entry, instruction, kind, value, author):
    """Append one revision while the caller holds the project writer lock."""
    scope = (image_id, engine_entry, instruction or "", kind)
    with project.db(False) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        db.execute(SCHEMA)
        db.execute(INDEX)
        old = db.execute(
            "SELECT * FROM annotation_revisions WHERE image_id=? AND engine_entry=? "
            "AND instruction=? AND kind=? ORDER BY revision DESC LIMIT 1", scope,
        ).fetchone()
        previous = old["value"] if old else None
        if previous == value:
            return record(old) if old else None, False
        if db.execute("SELECT COUNT(*) FROM annotation_revisions").fetchone()[0] >= MAX_REVISIONS:
            raise Error("annotation_limit", "Project annotation revision limit reached", 7)
        revision = db.execute(
            "INSERT INTO annotation_revisions "
            "(image_id,engine_entry,instruction,kind,analysis_id,value,previous_value,author,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (*scope, analysis_id, value, previous, author, datetime.now(timezone.utc).isoformat()),
        ).lastrowid
        new = db.execute("SELECT * FROM annotation_revisions WHERE revision=?", (revision,)).fetchone()
        return record(new), True


def read(project, image_id, *, engine_entry=None, kind=None, history=False):
    """Return a consistent image revision and matching records, including legacy workspaces."""
    with project.db() as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='annotation_revisions'"
        ).fetchone()
        if table is None:
            return 0, []
        revision = db.execute(
            "SELECT COALESCE(MAX(revision),0) FROM annotation_revisions WHERE image_id=?", (image_id,),
        ).fetchone()[0]
        conditions, params = ["image_id=?"], [image_id]
        if engine_entry is not None:
            conditions.append("engine_entry=?")
            params.append(engine_entry)
        if kind is not None:
            conditions.append("kind=?")
            params.append(kind)
        where = " AND ".join(conditions)
        if history:
            query = f"SELECT * FROM annotation_revisions WHERE {where} ORDER BY revision"
        else:
            query = ("SELECT * FROM annotation_revisions WHERE value IS NOT NULL AND revision IN "
                     f"(SELECT MAX(revision) FROM annotation_revisions WHERE {where} "
                     "GROUP BY engine_entry,instruction,kind) ORDER BY revision")
        return revision, [record(row) for row in db.execute(query, params)]


def with_labels(functions, rows):
    labels = {row["engine_entry"]: row for row in rows if row["kind"] == "name"}
    if not labels:
        return functions
    result = []
    for function in functions:
        label = labels.get(function["engine_entry"])
        if label and label["value"] is not None:
            name = {"name": label["value"], "origin": "user_supplied",
                    "annotation_revision": label["revision"]}
            function = dict(function, names=[*function["names"], name])
        result.append(function)
    return result


def instruction_at(function, requested, *, prior=()):
    if requested is None:
        return None
    if not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", requested):
        raise Error("annotation_address", "Instruction requires an unslid hexadecimal VA", 2)
    address = hex(int(requested, 16))
    if any(row["addr"] == address for row in function["instructions"]):
        return address
    if any(row["engine_entry"] == function["engine_entry"] and row["instruction"] == address
           and row["kind"] == "comment" for row in prior):
        return address
    raise Error("annotation_address", "Address is absent from the function's saved instructions", 2)


def return_type(value):
    if value not in RETURN_TYPES:
        raise Error("type_hint_type", "Use void, bool, or a fixed-width signed or unsigned integer type", 2)
    return value


def type_hints(rows, functions):
    available = {f["engine_entry"] for f in functions
                 if f["entry_va"] is not None and not f["is_external"] and not f["is_thunk"]}
    hints = []
    for row in rows:
        if row["kind"] != "return_type":
            continue
        entry = row["engine_entry"]
        if entry not in available:
            raise Error("type_hint_stale", "An accepted type hint has no matching function in this analysis", 3)
        hints.append({"entry_va":entry,"return_type":return_type(row["value"]),"revision":row["revision"]})
    if not hints:
        raise Error("type_hints_missing", "No accepted return-type hints for the selected image", 3)
    if len(hints)>MAX_TYPE_HINTS:
        raise Error("type_hint_limit", "Image return-type hint limit reached", 7)
    return sorted(hints,key=lambda hint:int(hint["entry_va"],16))
