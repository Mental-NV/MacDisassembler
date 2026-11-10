#!/usr/bin/env python3
"""Pair native-printer captures and strict behavior reports for the owned core."""
import argparse
from collections import Counter
import json
from pathlib import Path

from compare_heldout_aggregates import BUILDS, PROFILES, ROUTINES, STATES
from evaluate import CORE_ROUTINES
from score_discovery import verified_captures
from validate_decompiler_evidence import compare_results, index_functions, read_bytes, read_json, sha, write_new_json


def capture_key(row):
    return tuple(row[key] for key in ("case", "symbols", "profile"))


def check_capture(control, candidate):
    prior, before, *_ = control
    later, after, *_ = candidate
    if capture_key(prior) != capture_key(later) or prior["input_sha256"] != later["input_sha256"]:
        raise ValueError("Capture pairing differs by input, profile or symbol state")
    before_engine, after_engine = (snapshot["identity"]["engine"] for snapshot in (before, after))
    native = "native_decompiler_sha256"
    tree = "ghidra_tree_sha256"
    changed_identity = {native, tree}
    if (before_engine[native] == after_engine[native]
            or before_engine[tree] == after_engine[tree]
            or {k: v for k, v in before_engine.items() if k not in changed_identity}
            != {k: v for k, v in after_engine.items() if k not in changed_identity}):
        raise ValueError("Expected the same bridge and dependencies with a distinct native engine")
    comparison = compare_results(dict(before["engine"], functions=before["functions"]),
                                 dict(after["engine"], functions=after["functions"]))
    changes = comparison["changes"]
    if (not comparison["unchanged_machine_facets"] or comparison["option_deltas"]
            or changes["signature"] or changes["calling_convention"]):
        raise ValueError("Native printer changed machine facets, signatures or analyzer options")
    originals = index_functions(before["functions"])
    for entry, row in index_functions(after["functions"]).items():
        if any(row[key] != originals[entry][key] for key in (
            "xrefs_to_entry", "xrefs_to_entry_count", "xrefs_to_entry_truncated",
            "xrefs_from_sample", "xrefs_from_total", "xrefs_from_truncated",
        )):
            raise ValueError("Native printer changed cross references")
    return {
        "key": list(capture_key(prior)), "input_sha256": prior["input_sha256"],
        "control_export_sha256": prior["export_sha256"], "candidate_export_sha256": later["export_sha256"],
        "control_analysis_id": before["analysis_id"], "candidate_analysis_id": after["analysis_id"],
        "control_native_sha256": before_engine[native], "candidate_native_sha256": after_engine[native],
        "control_tree_sha256": before_engine[tree], "candidate_tree_sha256": after_engine[tree],
        "functions": comparison["function_count"], "changed_pseudocode": changes["pseudocode"],
    }


def result_rows(paths, pairs, side):
    """Overlay the aggregate and operation reports on the initial inventory."""
    records = {}
    for path in paths:
        report = read_json(path)
        if report["status"] not in ("partial", "passed") or len(report["captures"]) != len(pairs):
            raise ValueError("Incomplete behavior report")
        seen = set()
        for capture in report["captures"]:
            key = capture_key(capture)
            paired = pairs[key]
            if (key in seen or paired[side + "_export_sha256"] != capture["export_sha256"]
                    or paired[side + "_analysis_id"] != capture["analysis_id"]):
                raise ValueError("Behavior report does not match the paired capture")
            seen.add(key)
            for routine, row in capture["routines"].items():
                index = (*key, routine)
                measured = "results" in row
                if (measured and not row.get("pseudocode_sha256")
                        or row["status"] == "passed" and not measured):
                    raise ValueError("Measured behavior lacks its result or pseudocode provenance")
                previous = records.get(index)
                if previous is not None:
                    # Missing or incomplete recovery can appear in both inventories.
                    if (row.get("pseudocode_sha256") != previous.get("pseudocode_sha256")
                            or row["llvm_instruction_bytes"] != previous["llvm_instruction_bytes"]):
                        raise ValueError("Behavior reports disagree about the source evidence")
                    if "results" in previous:
                        if routine != "calc_engine_sign_toggle":
                            raise ValueError("Reports overlap already measured behavior")
                        row = dict(row, initial_domain=previous["status"])
                records[index] = row
    if records.keys() != {(*key, routine) for key in pairs for routine in CORE_ROUTINES}:
        raise ValueError("Behavior report does not cover the full calculator core")
    return records


def verdict(row):
    if row.get("initial_domain") not in (None, "passed"):
        return row["initial_domain"]
    if "results" in row and row.get("wide_counter", {}).get("status", "passed") != "passed":
        return "wide_" + row["wide_counter"]["status"]
    return row["status"]


def summarize(records):
    values = list(records)
    tested = [row for row in values if "results" in row]
    passed = [row for row in values if verdict(row) == "passed"]
    return {
        "cases": len(values), "instruction_bytes": sum(row["llvm_instruction_bytes"] for row in values),
        "complete": len(tested), "complete_bytes": sum(row["llvm_instruction_bytes"] for row in tested),
        "passed": len(passed), "passed_bytes": sum(row["llvm_instruction_bytes"] for row in passed),
        "verdicts": dict(Counter(verdict(row) for row in values)),
    }


def condition_summaries(records):
    """Keep blind symbol states and analyzer profiles independently scored."""
    profiles = sorted({key[2] for key in records})
    conditions = {}
    for state, label in (("stripped", "binary_only"), ("sym", "embedded_symbols")):
        conditions[label] = {}
        for profile in profiles:
            modes = {}
            for build, optimization in (("DebugAnalysis", "O0"), ("ReleaseAnalysis", "O2")):
                by_arch = {
                    arch: summarize(row for key, row in records.items()
                                    if key[:3] == (f"{build}-{arch}", state, profile))
                    for arch in ("arm64", "x86_64")
                }
                total = summarize(row for key, row in records.items()
                                  if key[0].startswith(build + "-") and key[1:3] == (state, profile))
                modes[optimization] = {"total": total, "by_arch": by_arch}
            conditions[label][profile] = modes
    return conditions


def heldout_evidence(root, plan):
    manifest = root / "frozen-captures.json"
    report = root / "report.json"
    behavior = read_json(report)
    if (behavior["status"] not in ("passed", "partial")
            or behavior["plan_sha256"] != sha(read_bytes(root / "frozen-plan.json"))
            or behavior["captures_sha256"] != sha(read_bytes(manifest))):
        raise ValueError("Held-out behavior report does not match its frozen plan and captures")
    expected = {(f"{arch}-{opt}", state, profile) for arch, opt in BUILDS
                for state in STATES for profile in PROFILES}
    captures = {}
    for row in read_json(manifest):
        key = tuple(row[field] for field in ("variant", "symbols", "profile"))
        if key in captures or key not in expected or row["file"] != "-".join(key) + ".json":
            raise ValueError("Unexpected or duplicate held-out export")
        raw = read_bytes(root / row["file"])
        snapshot = json.loads(raw)["data"]
        binary = plan["inputs"][key[0]][key[1]]
        if (sha(raw) != row["sha256"] or snapshot["image"]["sha256"] != binary
                or snapshot["identity"]["profile"] != key[2] + "/1"
                or snapshot["identity"]["engine"]["native_decompiler_sha256"] != plan["native_sha256"]):
            raise ValueError("Held-out export differs from its frozen identity")
        captures[key] = (dict(row, case=key[0], input_sha256=binary, export_sha256=row["sha256"]), snapshot)
    if captures.keys() != expected:
        raise ValueError("Incomplete held-out export population")
    rows = {}
    for row in behavior["results"]:
        key = tuple(row[field] for field in ("variant", "symbols", "profile"))
        index = (*key, row["routine"])
        provenance, snapshot = captures[key]
        if (index in rows or row["sha256"] != provenance["export_sha256"]
                or row["analysis_id"] != snapshot["analysis_id"]):
            raise ValueError("Held-out verdict differs from its capture identity")
        if row["status"] == "passed":
            counts = row["results"]
            if (counts["directed"] != 256 or counts["seeded"] != 10000 or counts["mismatches"]
                    or counts["undefined_results"]):
                raise ValueError("Held-out pass does not cover the declared domain")
        rows[index] = row
    if rows.keys() != {(*key, routine) for key in expected for routine in ROUTINES}:
        raise ValueError("Incomplete held-out verdict population")
    return captures, rows


def compare_heldout(control, candidate):
    control, candidate = control.resolve(), candidate.resolve()
    plan_paths = [root / "frozen-plan.json" for root in (control, candidate)]
    before_plan, after_plan = (read_json(path) for path in plan_paths)
    fields = ("policy", "source", "inputs", "compiler_sha256", "sdk_version")
    launcher = "compare_heldout_aggregates.py"
    contract = [{name: digest for name, digest in plan["files_sha256"].items() if name != launcher}
                for plan in (before_plan, after_plan)]
    if (any(before_plan[key] != after_plan[key] for key in fields) or contract[0] != contract[1]
            or after_plan["input_plan_sha256"] != sha(read_bytes(plan_paths[0]))):
        raise ValueError("Held-out input or evaluator contract differs")
    profiles = list((candidate / "projects").glob("*/jobs/*/sandbox.sb"))
    denial = "(deny file-read-data (subpath " + json.dumps(str(control)) + "))"
    if len(profiles) != 3 * len(BUILDS) * len(STATES) or any(denial not in p.read_text() for p in profiles):
        raise ValueError("Candidate worker policy does not deny the original evaluator root")
    old_captures, old = heldout_evidence(control, before_plan)
    new_captures, new = heldout_evidence(candidate, after_plan)
    pairs = [check_capture(old_captures[key], new_captures[key]) for key in old_captures]
    changes = Counter()
    for key, before in old.items():
        after = new[key]
        if before["entry"] != after["entry"]:
            raise ValueError("Held-out evaluator entry differs between engines")
        changes[before["status"] + " -> " + after["status"]] += 1
    return {"captures": pairs, "verdicts": dict(changes), "sandbox_profiles_checked": len(profiles),
            "reports_sha256": [sha(read_bytes(root / "report.json")) for root in (control, candidate)]}


def run(args):
    pairs = {}
    controls = verified_captures(args.fixture_build_root, args.control_matrix)
    candidates = verified_captures(args.fixture_build_root, args.candidate_matrix)
    for control, candidate in zip(controls, candidates, strict=True):
        paired = check_capture(control, candidate)
        pairs[tuple(paired["key"])] = paired
    if len(pairs) != 16:
        raise ValueError("Incomplete or duplicate calculator capture population")
    for left, right in zip(args.control_results, args.candidate_results, strict=True):
        a, b = read_json(left), read_json(right)
        fields = {key for key in a.keys() | b.keys()
                  if key == "schema" or "policy" in key or key.endswith("_sha256")} - {"matrix_report_sha256"}
        if any(a.get(key) != b.get(key) for key in fields):
            raise ValueError("Control and candidate evaluator configuration differ")
    before = result_rows(args.control_results, pairs, "control")
    after = result_rows(args.candidate_results, pairs, "candidate")
    changes = []
    for index, left in before.items():
        right = after[index]
        if left["llvm_instruction_bytes"] != right["llvm_instruction_bytes"]:
            raise ValueError("Evaluator instruction denominator changed")
        if verdict(left) != verdict(right):
            changes.append({"key": list(index), "before": verdict(left), "after": verdict(right),
                            "instruction_bytes": left["llvm_instruction_bytes"]})
    sides = {"control": before, "candidate": after}
    report = {
        "schema": "macscope-fixed-width-printer-behavior/1", "captures": list(pairs.values()),
        "result_sha256": {side: [sha(read_bytes(path)) for path in paths] for side, paths in
                          (("control", args.control_results), ("candidate", args.candidate_results))},
        "all": {side: summarize(rows.values()) for side, rows in sides.items()},
        "O2": {side: summarize(row for key, row in rows.items() if key[0].startswith("ReleaseAnalysis-"))
               for side, rows in sides.items()},
        "conditions": {side: condition_summaries(rows) for side, rows in sides.items()},
        "changed_verdicts": changes,
    }
    if args.heldout_pair:
        heldout = compare_heldout(*args.heldout_pair)
        for side in ("control", "candidate"):
            fields = (side + "_native_sha256", side + "_tree_sha256")
            identities = {tuple(row[field] for field in fields) for row in pairs.values()}
            if len(identities) != 1 or identities != {
                tuple(row[field] for field in fields) for row in heldout["captures"]
            }:
                raise ValueError("Held-out engines differ from the paired calculator engines")
        report["heldout"] = heldout
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("fixture-build-root", "control-matrix", "candidate-matrix", "output"):
        parser.add_argument("--" + field, required=True, type=Path)
    for side in ("control", "candidate"):
        parser.add_argument("--" + side + "-results", nargs=3, metavar=("CORE", "AGGREGATE", "OPERATIONS"),
                            required=True, type=Path)
    parser.add_argument("--heldout-pair", nargs=2, metavar=("CONTROL", "CANDIDATE"), type=Path)
    args = parser.parse_args()
    report = run(args)
    write_new_json(args.output, report)
    print(json.dumps({key: report[key] for key in ("all", "O2")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
