#!/usr/bin/env python3
"""Standalone export benchmark comparison harness (synthetic receipts only).

Compares one saved isolated timing receipt against one saved bulk timing
receipt recorded on the exact same immutable image/address selection.
No engine execution, no TickTick/Ghidra invocation, no batch implementation.

Frozen artifact contract for every record this module accepts or returns:
plain JSON-compatible values only, ``schema_version`` equal to ``1``,
image identity (image identifier, architecture, input hash), coverage
copied from the input, and explicit limitations. Raw evidence travels by
reference only; this module never accepts or emits pseudocode text and
never asserts complete discovery.
"""

import argparse
import copy
import json
import math
import re
import sys

SCHEMA_VERSION = 1

RECEIPT_KINDS = ("isolated", "bulk")
ARCHES = ("arm64", "x86_64")
STATUSES = ("complete", "partial", "failed", "timeout", "cancelled")
FORBIDDEN_RAW_KEYS = ("pseudocode", "raw_c", "raw_text", "decompiled_text")

_HEX64 = re.compile(r"[0-9a-f]{64}")
_VA = re.compile(r"0x[0-9a-fA-F]{1,16}")


def _is_json_value(value, depth=0):
    if depth > 32:
        return False
    if value is None or isinstance(value, (bool, int, float, str)):
        if isinstance(value, float) and not math.isfinite(value):
            return False
        return True
    if isinstance(value, list):
        return all(_is_json_value(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and key not in FORBIDDEN_RAW_KEYS
                   and _is_json_value(item, depth + 1)
                   for key, item in value.items())
    return False


def _is_nonneg_number(value):
    try:
        return (type(value) in (int, float) and math.isfinite(value) and value >= 0)
    except OverflowError:
        return False


def _finite_ratio(left, right):
    if left is None or right is None or right <= 0:
        return None
    ratio = left / right
    return ratio if math.isfinite(ratio) and not (left > 0 and ratio == 0) else None


def summarize_samples(values):
    """Deterministic summary of repeated wall-clock samples.

    Median/minimum/maximum over sorted values. Nearest-rank p95 only when
    at least 20 samples are present, matching the existing focused-import
    benchmark convention; fewer samples make no percentile claim.
    """
    if not isinstance(values, list) or not values:
        raise ValueError("Expected a non-empty list of samples")
    if any(not _is_nonneg_number(value) for value in values):
        raise ValueError("Samples must be finite nonnegative numbers")
    ordered = sorted(values)
    lower, upper = ordered[(len(ordered) - 1) // 2], ordered[len(ordered) // 2]
    median = lower if lower == upper else max(lower, min(upper, lower + (upper - lower) / 2))
    result = {"samples": len(ordered), "minimum_seconds": ordered[0],
              "median_seconds": median,
              "maximum_seconds": ordered[-1]}
    if len(ordered) >= 20:
        result["p95_seconds"] = ordered[math.ceil(len(ordered) * 0.95) - 1]
    return result


def validate_receipt(record):
    """Validate one synthetic timing receipt; return a normalized copy."""
    if not isinstance(record, dict):
        raise ValueError("Receipt must be a JSON object")
    for key in FORBIDDEN_RAW_KEYS:
        if key in record:
            raise ValueError("Receipt must preserve raw evidence by reference; "
                             "rewrite key %r is not accepted" % (key,))
    if record.get("schema_version") != SCHEMA_VERSION or \
            type(record.get("schema_version")) is not int:
        raise ValueError("Receipt schema_version must be integer 1")
    kind = record.get("receipt_kind")
    if kind not in RECEIPT_KINDS:
        raise ValueError("receipt_kind must be one of %s" % (list(RECEIPT_KINDS),))
    image = record.get("image")
    if not isinstance(image, dict):
        raise ValueError("image must be an object")
    if not isinstance(image.get("image_id"), str) or not image["image_id"]:
        raise ValueError("image.image_id must be a non-empty string")
    if image.get("arch") not in ARCHES:
        raise ValueError("image.arch must be one of %s" % (list(ARCHES),))
    if not isinstance(image.get("input_sha256"), str) or \
            not _HEX64.fullmatch(image["input_sha256"]):
        raise ValueError("image.input_sha256 must be 64 lowercase hex characters")
    if "slice_sha256" in image and (
            not isinstance(image["slice_sha256"], str) or
            not _HEX64.fullmatch(image["slice_sha256"])):
        raise ValueError("image.slice_sha256 must be 64 lowercase hex characters")
    selection = record.get("selection")
    if not isinstance(selection, dict):
        raise ValueError("selection must be an object")
    addresses = selection.get("addresses")
    if (not isinstance(addresses, list) or not addresses or
            any(not isinstance(item, str) or not _VA.fullmatch(item)
                for item in addresses)):
        raise ValueError("selection.addresses must be a non-empty list of hex addresses")
    addresses = [hex(int(address, 16)) for address in addresses]
    if len(set(addresses)) != len(addresses):
        raise ValueError("selection.addresses must not contain duplicates")
    counts = record.get("counts")
    if not isinstance(counts, dict):
        raise ValueError("counts must be an object")
    parts = {}
    for key in ("attempted", "succeeded", "partial", "failed"):
        value = counts.get(key)
        if type(value) is not int or value < 0:
            raise ValueError("counts.%s must be a nonnegative integer" % key)
        parts[key] = value
    if parts["attempted"] > len(addresses):
        raise ValueError("counts.attempted exceeds the unique selection")
    if parts["attempted"] != parts["succeeded"] + parts["partial"] + parts["failed"]:
        raise ValueError("counts.attempted must equal succeeded + partial + failed")
    wall = record.get("wall_seconds")
    if not _is_nonneg_number(wall):
        raise ValueError("wall_seconds must be a finite nonnegative number")
    intervals = record.get("intervals")
    if not isinstance(intervals, dict) or not intervals:
        raise ValueError("intervals must be a non-empty object")
    for name, value in intervals.items():
        if not isinstance(name, str) or not name:
            raise ValueError("interval names must be non-empty strings")
        if value is not None and not _is_nonneg_number(value):
            raise ValueError("interval %r must be a finite nonnegative number or null" % (name,))
    coverage = record.get("coverage")
    if not isinstance(coverage, dict):
        raise ValueError("coverage must be an object copied from the input")
    if not _is_json_value(coverage):
        raise ValueError("coverage must hold plain JSON-compatible values")
    limitations = record.get("limitations")
    if (not isinstance(limitations, list) or not limitations or
            any(not isinstance(item, str) or not item for item in limitations)):
        raise ValueError("limitations must be a non-empty list of strings")
    evidence_refs = record.get("evidence_refs")
    if (not isinstance(evidence_refs, list) or
            any(not isinstance(item, str) or not item for item in evidence_refs)):
        raise ValueError("evidence_refs must be a list of reference strings")
    status = record.get("status", "complete")
    if status not in STATUSES:
        raise ValueError("status must be one of %s" % (list(STATUSES),))
    if not _is_json_value(record):
        raise ValueError("Receipt must hold plain JSON-compatible values")
    normalized = copy.deepcopy(record)
    normalized["selection"] = dict(selection, addresses=sorted(addresses, key=lambda address: int(address, 16)))
    return normalized


def _image_identity(image):
    identity = {"image_id": image["image_id"], "arch": image["arch"],
                "input_sha256": image["input_sha256"]}
    if "slice_sha256" in image:
        identity["slice_sha256"] = image["slice_sha256"]
    return identity


def compare_receipts(isolated, bulk):
    """Compare two validated receipts on the same selection.

    Returns a plain JSON-compatible comparison record with
    ``schema_version`` 1. ``speedup`` is reported only when the receipts
    are comparable and both wall times are positive; otherwise it is
    None and the reason is listed. Named intervals are carried side by
    side and never summed across names, because they may nest/overlap.
    """
    first = validate_receipt(isolated)
    second = validate_receipt(bulk)
    reasons = []
    if first["receipt_kind"] != "isolated":
        reasons.append("first receipt_kind is %r, expected 'isolated'" % (first["receipt_kind"],))
    if second["receipt_kind"] != "bulk":
        reasons.append("second receipt_kind is %r, expected 'bulk'" % (second["receipt_kind"],))
    if _image_identity(first["image"]) != _image_identity(second["image"]):
        reasons.append("image identity differs (image_id/arch/input hash/slice)")
    if first["selection"]["addresses"] != second["selection"]["addresses"]:
        reasons.append("address selection differs")
    first_id = first["selection"].get("selection_id")
    second_id = second["selection"].get("selection_id")
    if first_id != second_id:
        reasons.append("selection_id differs")
    if first["counts"] != second["counts"]:
        reasons.append("attempted/succeeded/partial/failed counts differ")
    if first["coverage"] != second["coverage"]:
        reasons.append("coverage differs")
    for label, receipt in (("isolated", first), ("bulk", second)):
        if receipt.get("status", "complete") not in ("complete", "partial"):
            reasons.append(label + " run did not finish successfully")
        if receipt["counts"]["failed"]:
            reasons.append(label + " run contains failed functions")
        if receipt["counts"]["attempted"] != len(receipt["selection"]["addresses"]):
            reasons.append(label + " run did not attempt its entire selection")
        if not receipt["evidence_refs"]:
            reasons.append(label + " run has no evidence references")
    comparable = not reasons
    wall_isolated = first["wall_seconds"]
    wall_bulk = second["wall_seconds"]
    speedup = None
    if comparable:
        if wall_isolated > 0 and wall_bulk > 0:
            speedup = _finite_ratio(wall_isolated, wall_bulk)
            if speedup is None:
                reasons.append("wall-time ratio is outside the finite numeric range")
                comparable = False
        else:
            reasons.append("zero wall time is not a measurable speedup")
            comparable = False
    names = sorted(set(first["intervals"]) | set(second["intervals"]))
    table = {}
    for name in names:
        left = first["intervals"].get(name)
        right = second["intervals"].get(name)
        ratio = None
        if comparable:
            ratio = _finite_ratio(left, right)
        table[name] = {"isolated_seconds": left, "bulk_seconds": right,
                       "ratio_isolated_over_bulk": ratio}
    limitations = list(first["limitations"]) + list(second["limitations"]) + [
        "Named timing intervals may nest or overlap and must not be summed.",
        "A comparison is not complete discovery and reports only the attempted selection.",
        "A smaller output is not a valid speedup; equal coverage is required.",
        "Comparability validates recorded metadata, not semantic equivalence or the referenced artifacts.",
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "image": _image_identity(first["image"]),
        "selection": {"addresses": first["selection"]["addresses"]},
        "coverage": copy.deepcopy(first["coverage"]),
        "coverages_match": first["coverage"] == second["coverage"],
        "comparable": comparable,
        "reasons": reasons,
        "counts_isolated": dict(first["counts"]),
        "counts_bulk": dict(second["counts"]),
        "wall": {"isolated_wall_seconds": wall_isolated,
                 "bulk_wall_seconds": wall_bulk,
                 "speedup_isolated_over_bulk": speedup,
                 "speedup_reported": speedup is not None},
        "intervals": table,
        "status": {"isolated": first.get("status", "complete"),
                   "bulk": second.get("status", "complete")},
        "limitations": limitations,
        "evidence_refs": {"isolated": list(first["evidence_refs"]),
                          "bulk": list(second["evidence_refs"])},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare saved isolated/bulk export timing receipts.")
    parser.add_argument("isolated", help="Path to isolated receipt JSON")
    parser.add_argument("bulk", help="Path to bulk receipt JSON")
    parser.add_argument("--output", default=None, help="Write comparison JSON here")
    args = parser.parse_args(argv)
    try:
        with open(args.isolated, "r", encoding="utf-8") as handle:
            isolated = json.load(handle)
        with open(args.bulk, "r", encoding="utf-8") as handle:
            bulk = json.load(handle)
        comparison = compare_receipts(isolated, bulk)
    except (OSError, ValueError) as error:
        print("export_benchmark: %s" % (error,), file=sys.stderr)
        return 2
    text = json.dumps(comparison, indent=2, sort_keys=True, allow_nan=False) + "\n"
    try:
        if args.output is not None:
            with open(args.output, "x", encoding="utf-8") as handle:
                handle.write(text)
        else:
            sys.stdout.write(text)
    except OSError as error:
        print("export_benchmark: %s" % (error,), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
