"""Explicit function-body corrections and their checked worker request."""
import hashlib
import json
import re

from .errors import Error
from .storage import canonical


KIND = "function_boundary"
POLICY = "macscope-manual-function-boundaries/1"
MAX_EDITS = 32
MAX_RANGES = 16
MAX_BODY_BYTES = 65536
VA = re.compile(r"0x[0-9a-fA-F]{1,16}")


def address(value):
    if not isinstance(value, str) or not VA.fullmatch(value):
        raise Error("boundary_edit_address", "Use an unslid hexadecimal address", 2)
    return hex(int(value, 16))


def body_ranges(ranges, entry):
    if not isinstance(ranges, list) or not 1 <= len(ranges) <= MAX_RANGES:
        raise Error("boundary_edit_body", "A function body requires one to 16 address ranges", 2)
    intervals = []
    for pair in ranges:
        if not isinstance(pair, list) or len(pair) != 2:
            raise Error("boundary_edit_body", "Use inclusive START:END ranges", 2)
        lo, hi = (int(address(value), 16) for value in pair)
        if hi < lo:
            raise Error("boundary_edit_body", "A body range ends before its start", 2)
        intervals.append((lo, hi))
    merged = []
    for lo, hi in sorted(intervals):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
        else:
            merged.append((lo, hi))
    start = int(entry, 16)
    if (not any(lo <= start <= hi for lo, hi in merged)
            or sum(hi - lo + 1 for lo, hi in merged) > MAX_BODY_BYTES):
        raise Error("boundary_edit_body", "The body must contain the entry and cover at most 64 KiB", 2)
    return [[hex(lo), hex(hi)] for lo, hi in merged]


def parse_body(text, entry):
    if len(text) > MAX_RANGES * 38:
        raise Error("boundary_edit_body", "Body range list exceeds its length limit", 2)
    return body_ranges([pair.split(":") for pair in text.split(",")], entry)


def value(before, body):
    if before == body:
        raise Error("boundary_edit_no_change", "The proposed body matches the unedited function", 2)
    return canonical({"before": before, "body": body}).decode()


def read_value(entry, text):
    if not isinstance(text, str) or len(text) > 2048:
        raise Error("boundary_edit_body", "Stored function boundary exceeds its size limit", 2)
    try:
        edit = json.loads(text)
    except (TypeError, ValueError, RecursionError) as error:
        raise Error("boundary_edit_body", "Invalid stored function boundary", 2) from error
    if (entry != address(entry) or not isinstance(edit, dict) or edit.keys() != {"before", "body"}
            or any(ranges is not None and ranges != body_ranges(ranges, entry) for ranges in edit.values())
            or value(edit["before"], edit["body"]) != text):
        raise Error("boundary_edit_body", "Stored function boundary is not canonical", 2)
    return edit


def saved_body(snapshot, entry):
    for edit in snapshot["engine"].get("manual_boundaries", {}).get("edits", ()):
        if edit["entry"] == entry:
            return edit["before"]
    function = next((row for row in snapshot["functions"] if row["entry_va"] == entry), None)
    if function is None:
        if snapshot["engine"].get("functions_truncated") or snapshot["engine"].get("analysis_timed_out"):
            raise Error("boundary_edit_target", "The saved analysis cannot establish whether the entry exists", 3)
        return None
    if (function["is_external"] or function["is_thunk"]
            or function.get("coverage", {}).get("body_ranges", {}).get("status") != "complete"):
        raise Error("boundary_edit_target", "Boundary edits require a complete internal non-thunk function body", 3)
    return body_ranges(function["body_ranges"], entry)


def active_edits(history):
    latest = {row["engine_entry"]: row for row in history}
    return [row for _, row in sorted(latest.items()) if row["value"] is not None]


def request(history, image):
    rows = active_edits(history)
    if not rows:
        raise Error("boundary_edits_missing", "No accepted function boundary edits for the selected image", 3)
    if len(rows) > MAX_EDITS:
        raise Error("boundary_edit_limit", "At most 32 active function boundary edits are supported", 7)
    edits = [dict(read_value(row["engine_entry"], row["value"]),
                  entry=row["engine_entry"], revision=row["revision"]) for row in rows]
    intervals = sorted((int(lo, 16), int(hi, 16)) for row in edits for lo, hi in (row["body"] or ()))
    if any(lo <= prior_hi for (_, prior_hi), (lo, _) in zip(intervals, intervals[1:])):
        raise Error("boundary_edit_overlap", "Proposed function bodies overlap each other", 2)
    return {"policy": POLICY, "input_sha256": image["sha256"], "revision": history[-1]["revision"], "edits": edits}


def request_identity(plan):
    return {"policy": POLICY, "annotation_revision": plan["revision"],
            "request_sha256": hashlib.sha256(canonical(plan) + b"\n").hexdigest()}


def verify(result, plan):
    report = result.get("manual_boundaries")
    if plan is None:
        if report is None:
            return
    elif report == dict(request_identity(plan), edits=plan["edits"]):
        # A bounded export may omit a corrected entry. Every emitted edited entry must agree.
        actual = {row.get("entry_va"): row for row in result.get("functions", ())}
        capped = result.get("functions_truncated") or result.get("output_budget_reached")
        for row in plan["edits"]:
            observed = actual.get(row["entry"])
            if ((observed is not None and observed.get("body_ranges") != row["body"])
                    or (observed is None and row["body"] is not None and not capped)):
                break
        else:
            return
    raise Error("boundary_edit_result", "Worker did not report the exact accepted function boundaries", 10)
