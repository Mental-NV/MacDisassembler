"""Compare bounded committed exports and report the basis of each pairing."""
from collections import Counter, defaultdict
import hashlib
from itertools import zip_longest
import json
import re

from .errors import Error
from .macho import read_regular
from .metadata import VA
from .schema import validate_envelope
from .storage import MAX_SNAPSHOT_BYTES, canonical, identity


POLICY = "macscope-export-diff/1"
DIGEST = re.compile(r"[a-f0-9]{64}")
AUTO_NAME = re.compile(r"(?:entry|(?:thunk_)?(?:FUN|LAB|SUB|DAT|EXT)_[a-fA-F0-9]+)")
ENCODING = re.compile(r"(?:[a-f0-9]{2}){1,15}")
METADATA_FIELDS = ("arch", "cpu_type", "cpu_subtype", "file_type", "flags", "uuid", "size", "load_commands",
                   "segments", "sections")
COLLECTIONS = ("imports", "exports", "symbols", "strings")
FUNCTION_FIELDS = ("entry_va", "body_ranges", "names", "signature", "calling_convention", "is_thunk", "is_external")


def read_export(path, side):
    raw = read_regular(path, MAX_SNAPSHOT_BYTES + 16384)
    try:
        envelope = json.loads(raw)
        validate_envelope(envelope)
        snapshot = envelope["data"]
        image = snapshot["image"]
        if (envelope["command"] != "export" or envelope["status"] not in ("complete", "partial")
                or snapshot["analysis_id"] != envelope["analysis_id"]
                or not all(DIGEST.fullmatch(value) for value in (
                    snapshot["analysis_id"], image["image_id"], image["sha256"], image["artifact_sha256"]))
                or image["arch"] not in ("arm64", "x86_64") or not isinstance(snapshot["engine"], dict)
                or not isinstance(snapshot["functions"], list) or len(snapshot["functions"]) > 10000):
            raise ValueError("invalid snapshot identity")
    except (ValueError, KeyError, TypeError, RecursionError) as error:
        raise Error("diff_export", f"{side} must be a valid committed macscope JSON export") from error
    return snapshot, hashlib.sha256(raw).hexdigest()


def descriptor(snapshot, digest):
    image = snapshot["image"]
    return {"export_sha256": digest, "analysis_id": snapshot["analysis_id"],
            "image_id": image["image_id"], "arch": image["arch"], "slice_sha256": image["sha256"],
            "artifact_sha256": image["artifact_sha256"], "profile": snapshot.get("analysis_profile")}


def facet_complete(record, key, rows):
    coverage = record.get("coverage", {}).get(key, {})
    return (coverage.get("status") == "complete" and not coverage.get("truncated")
            and not coverage.get("error") and coverage.get("emitted") == len(rows))


def preview(value):
    if isinstance(value, (list, dict)):
        payload = canonical(value)
        if len(payload) > 1024:
            return {"sha256": hashlib.sha256(payload).hexdigest(), "items": len(value)}
    if isinstance(value, str) and len(value) > 512:
        return {"sha256": identity(value), "characters": len(value)}
    return value


def metadata_rows(left, right):
    def fields(snapshot):
        image, engine = snapshot["image"], snapshot["engine"]
        result = {f"image.{key}": (image.get(key), key in image) for key in METADATA_FIELDS}
        for key, value in image.get("loader", {}).items():
            complete = not isinstance(value, dict) or value.get("status", "complete") == "complete"
            result[f"loader.{key}"] = value, complete
        for key in COLLECTIONS:
            value = engine.get(key, [])
            result[f"ghidra.{key}"] = value, facet_complete(engine, key, value)
        return result

    a, b = fields(left), fields(right)
    rows = []
    for key in sorted(a.keys() | b.keys()):
        first, first_complete = a.get(key, (None, False))
        second, second_complete = b.get(key, (None, False))
        status = "unchanged" if first == second else "changed"
        if not first_complete or not second_complete:
            status = "incomplete"
        rows.append({"field": key, "status": status, "left": preview(first), "right": preview(second)})
    gaps = [side + "_loader_metadata_unavailable" for side, snapshot in (("left", left), ("right", right))
            if "loader" not in snapshot["image"]]
    return rows, gaps


def instruction_evidence(record):
    entry = record["entry_va"]
    if entry is None:
        return None, {}
    entry = int(entry, 16)
    rows = record["instructions"]
    decoded = {}
    for row in rows:
        if not VA.fullmatch(row["addr"]) or not ENCODING.fullmatch(row["bytes"]):
            raise ValueError("invalid instruction")
        offset = int(row["addr"], 16) - entry
        if offset in decoded:
            raise ValueError("duplicate instruction address")
        decoded[offset] = {key: row.get(key) for key in ("bytes", "flow", "text")}
    digest = record.get("instruction_bytes_sha256")
    if digest is not None and digest != hashlib.sha256(bytes.fromhex("".join(row["bytes"] for row in rows))).hexdigest():
        raise ValueError("instruction bytes disagree with the recorded digest")
    if (not decoded or not facet_complete(record, "instructions", rows)
            or not facet_complete(record, "body_ranges", record["body_ranges"]) or record.get("control_flow_gaps")):
        return None, decoded
    instructions = iter(sorted(decoded.items()))
    for lo, hi in record["body_ranges"]:
        if not VA.fullmatch(lo) or not VA.fullmatch(hi) or int(lo, 16) > int(hi, 16):
            raise ValueError("invalid function body range")
        position, end = int(lo, 16) - entry, int(hi, 16) - entry + 1
        while position < end:
            row = next(instructions, None)
            if row is None or row[0] != position:
                return None, decoded
            position += len(row[1]["bytes"]) // 2
        if position != end:
            return None, decoded
    if next(instructions, None) is not None:
        return None, decoded
    return identity([[offset, row["bytes"]] for offset, row in sorted(decoded.items())]), decoded


def function_facts(snapshot):
    image = snapshot["image"]
    facts = {}
    for record in snapshot["functions"]:
        fid, entry, name = (record[key] for key in ("function_id", "entry_va", "name"))
        if (not DIGEST.fullmatch(fid) or fid in facts or record["image_id"] != image["image_id"]
                or record["analysis_id"] != snapshot["analysis_id"] or record["arch"] != image["arch"]
                or (entry is not None and not VA.fullmatch(entry)) or not isinstance(name, str)):
            raise ValueError("invalid function identity")
        fingerprint, decoded = instruction_evidence(record)
        keys = {}
        if name and not AUTO_NAME.fullmatch(name):
            keys["engine_name"] = (entry is None, record.get("namespace"), name)
        if fingerprint is not None:
            keys["instruction_bytes"] = fingerprint
        if entry is not None:
            keys["same_slice_entry"] = (record["address_space"], int(entry, 16))
        facts[fid] = record, keys, decoded
    return facts


def pair_functions(left, right, same_slice):
    def index(facts):
        result = defaultdict(list)
        for fid, (_, keys, _) in facts.items():
            for key in keys.items():
                result[key].append(fid)
        return result

    a, b = index(left), index(right)
    pairs, used = {}, set()
    if same_slice:
        for (basis, key), ids in a.items():
            matches = b.get((basis, key), [])
            if basis == "same_slice_entry" and len(ids) == len(matches) == 1:
                pairs[ids[0]] = matches[0], [basis]
                used.add(matches[0])

    candidates, reverse = defaultdict(dict), defaultdict(set)
    for key, ids in a.items():
        basis, _ = key
        matches = b.get(key, [])
        if (basis != "same_slice_entry" and len(ids) == len(matches) == 1
                and ids[0] not in pairs and matches[0] not in used):
            candidates[ids[0]].setdefault(matches[0], []).append(basis)
            reverse[matches[0]].add(ids[0])
    for fid, options in candidates.items():
        if len(options) == 1:
            target, basis = next(iter(options.items()))
            if len(reverse[target]) == 1:
                pairs[fid] = target, sorted(basis)
                used.add(target)
    return pairs, used, a, b


def function_summary(record):
    return {key: record[key] for key in ("function_id", "entry_va", "engine_entry", "name")}


def observed_changes(left, right, scope):
    a, left_keys, left_instructions = left
    b, right_keys, right_instructions = right
    if scope == "pseudocode":
        if all(record.get("decompile_status") == "not_requested" and
               (record.get("is_thunk") or record.get("is_external")) for record in (a, b)):
            return {"status": "not_applicable", "pseudocode": {"left": None, "right": None}}
        texts = a.get("pseudocode"), b.get("pseudocode")
        complete = all(isinstance(text, str) and text and record.get("decompile_status") == "complete"
                       and not record.get("pseudocode_truncated") and not record.get("decompile_error")
                       for text, record in zip(texts, (a, b), strict=True))
        evidence = {side: {"sha256": hashlib.sha256(text.encode()).hexdigest(), "characters": len(text)}
                    if isinstance(text, str) else None for side, text in zip(("left", "right"), texts, strict=True)}
        status = "incomplete" if not complete else "unchanged" if texts[0] == texts[1] else "changed"
        result = {"status": status, "pseudocode": evidence}
        if status == "changed":
            lines = zip_longest(*(text.splitlines(keepends=True) for text in texts))
            line, (first, second) = next((n, pair) for n, pair in enumerate(lines, 1) if pair[0] != pair[1])
            result["first_line_difference"] = {"line": line, "left": preview(first), "right": preview(second)}
        return result

    changes = [key for key in FUNCTION_FIELDS if a.get(key) != b.get(key)]
    differences = [offset for offset in sorted(left_instructions.keys() | right_instructions.keys())
                   if left_instructions.get(offset) != right_instructions.get(offset)]
    if differences:
        changes.append("instructions")
    complete = ((a.get("is_external") and b.get("is_external")) or
                "instruction_bytes" in left_keys and "instruction_bytes" in right_keys)
    result = {"status": "incomplete" if not complete else "changed" if changes else "unchanged",
              "changed_fields": changes, "instruction_differences": len(differences),
              "left_body_sha256": left_keys.get("instruction_bytes"),
              "right_body_sha256": right_keys.get("instruction_bytes")}
    if differences:
        offset = differences[0]
        result["first_instruction_difference"] = {"entry_offset": hex(offset),
            "left": left_instructions.get(offset), "right": right_instructions.get(offset)}
    return result


def function_rows(left, right, scope):
    if left["image"]["arch"] != right["image"]["arch"]:
        raise Error("diff_architecture", "Function and pseudocode comparisons require the same architecture", 3)
    same_slice = left["image"]["sha256"] == right["image"]["sha256"]
    a, b = function_facts(left), function_facts(right)
    pairs, used, left_index, right_index = pair_functions(a, b, same_slice)
    rows = []
    unmatched_incomplete = False
    for side, own, paired, index in (("left", a, set(pairs), right_index), ("right", b, used, left_index)):
        for fid, (record, keys, _) in own.items():
            if fid in paired:
                continue
            if record["entry_va"] is not None and "instruction_bytes" not in keys:
                unmatched_incomplete = True
            options = {basis: {"count": len(ids), "sample_function_ids": ids[:8]}
                       for basis, key in keys.items() if (same_slice or basis != "same_slice_entry")
                       and (ids := index.get((basis, key)))}
            rows.append({side: function_summary(record), "status": "uncertain" if options else "unmatched_" + side,
                         "candidates": options})
    for fid, (target, basis) in pairs.items():
        rows.append({"left": function_summary(a[fid][0]), "right": function_summary(b[target][0]),
                     "match": {"basis": basis, "status": "same_slice_entry" if basis == ["same_slice_entry"] else "candidate"},
                     **observed_changes(a[fid], b[target], scope)})
    def order(row):
        entry = row.get("left") or row["right"]
        va = entry["entry_va"]
        return (va is None, int(va, 16) if va is not None else 0, entry["engine_entry"], entry["function_id"])

    rows.sort(key=order)
    gaps = [side + "_function_inventory_incomplete" for side, snapshot in (("left", left), ("right", right))
            if snapshot["engine"].get("functions_truncated") or snapshot["engine"].get("analysis_timed_out")
            or snapshot["engine"].get("coverage", {}).get("functions", {}).get("status", "complete") != "complete"]
    if unmatched_incomplete:
        gaps.append("unmatched_instruction_evidence_incomplete")
    return rows, gaps


def compare(left_path, right_path, scope):
    left, left_digest = read_export(left_path, "LEFT")
    right, right_digest = read_export(right_path, "RIGHT")
    try:
        rows, gaps = metadata_rows(left, right) if scope == "metadata" else function_rows(left, right, scope)
        summary = dict(Counter(row["status"] for row in rows))
        if summary.get("incomplete"):
            gaps.append("evidence_incomplete")
        if summary.get("uncertain"):
            gaps.append("ambiguous_function_matches")
        data = {"policy": POLICY, "scope": scope, "left": descriptor(left, left_digest),
                "right": descriptor(right, right_digest), "summary": summary, "gaps": gaps}
        return data, rows, identity([left_digest, right_digest, scope])
    except (ValueError, KeyError, TypeError, RecursionError) as error:
        raise Error("diff_export", "An export has malformed evidence for the requested scope") from error
