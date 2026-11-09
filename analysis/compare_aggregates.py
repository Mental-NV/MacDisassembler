#!/usr/bin/env python3
"""Measure aggregate-return behavior after fixed mechanical compatibility lowering."""
import argparse
from collections import Counter
import json
from pathlib import Path

from aggregate_compat import POLICY, Unsupported, lower_closure
from audit_core_behavior import AGGREGATES, complete, core_extents, inventory, llvm_instructions, recovered_name
from prototype_experiment import ROOT
from recovered_compare import SOURCE_FILES, run_candidate
from reference_coverage import xcrun
from score_discovery import verified_captures
from validate_decompiler_evidence import read_bytes, sha, write_new_json
from macscope import engine


ROUTINES = (
    ("calc_add", 2, 400), ("calc_sub", 2, 400), ("calc_mul", 2, 400), ("calc_div", 2, 400),
    ("calc_negate", 1, 148), ("calc_abs_checked", 1, 148), ("calc_pow_checked", 2, 400),
    ("calc_apply_op", 3, 4800), ("calc_dispatch_table", 3, 4800), ("calc_parse_digits", 2, 271),
    ("calc_digit_append", 2, 240), ("calc_sign_toggle", 1, 148), ("calc_history_sum", 1, 661),
)
COMPAT = ROOT / "analysis" / "aggregate_compat.h"
LOWERER = ROOT / "analysis" / "aggregate_compat.py"
HARNESS = ROOT / "analysis" / "compare_aggregate_harness.c"


def compare(directory, routine, kind, arity, directed, name, source, compiler, sdk, harness, references):
    try:
        lowered, linkage = lower_closure(name, source, arity)
    except Unsupported as error:
        return {"status": "not_testable", "reason": str(error)}
    directory.mkdir(mode=0o700)
    (directory / "candidate.c").write_bytes(lowered.encode())
    flags = ["-fsanitize=address", "-fno-strict-aliasing", f"-DRECOVERED={name}",
             f"-DREFERENCE={routine}", f"-DKIND={kind}"]
    result = run_candidate(directory, compiler, sdk, harness, references, flags)
    result.update(lowered_sha256=sha(lowered.encode()),
                  captured_definitions={callee: sha(source[callee].encode()) for callee in linkage})
    counts = result.get("results")
    if counts is not None:
        if counts["directed"] != directed or counts["seeded"] != 10000 or any(
            not 0 <= counts[key] <= directed + 10000 for key in ("mismatches", "undefined_results", "unspecified_padding")
        ):
            raise ValueError("Evaluator did not complete the declared aggregate domain")
        result["status"] = "passed"
        if counts["undefined_results"]:
            result["status"] = "undefined_result"
        elif counts["mismatches"]:
            result["status"] = "mismatch"
    return result


def run(args):
    output = args.output_dir.resolve()
    scratch = Path("/tmp").resolve()
    if output == scratch or not output.is_relative_to(scratch):
        raise ValueError("Choose a new output directory under canonical /tmp")
    if {row[0] for row in ROUTINES} != AGGREGATES:
        raise ValueError("The aggregate harness does not cover the full declared cohort")
    references = {name: read_bytes(ROOT / name) for name in SOURCE_FILES}
    source_hashes = {name: sha(content) for name, content in references.items()}
    references[COMPAT.name] = read_bytes(COMPAT)
    harness = read_bytes(HARNESS)
    compiler, decoder = xcrun("--find", "clang"), xcrun("--find", "llvm-objdump")
    sdk = xcrun("--sdk", "macosx", "--show-sdk-path")
    output.mkdir(mode=0o700)
    captures, decodes = [], {}
    report = {
        "schema": "macscope-aggregate-behavior/1", "policy": POLICY, "status": "failed",
        "source_sha256": source_hashes, "captures": captures,
        "matrix_report_sha256": sha(read_bytes(args.profile_matrix / "report.json")),
        "lowerer_sha256": sha(read_bytes(LOWERER)), "compat_sha256": sha(references[COMPAT.name]),
        "harness_sha256": sha(harness), "compiler_sha256": engine.digest(Path(compiler)),
    }
    try:
        for provenance, snapshot, truth, _, manifest in verified_captures(args.fixture_build_root, args.profile_matrix):
            if any(manifest["source"]["source_files_sha256"].get(name) != digest
                   for name, digest in source_hashes.items()):
                raise ValueError("Reference source differs from the fixture manifest")
            case, state, profile = (provenance[key] for key in ("case", "symbols", "profile"))
            extents = core_extents(truth)
            if case not in decodes:
                decodes[case] = llvm_instructions(args.fixture_build_root, case, decoder, extents)
            rows, records = inventory(snapshot, extents, decodes[case])
            names = {routine: recovered_name(record, routine) for routine, record in records.items() if complete(record)}
            if len(set(names.values())) != len(names):
                raise ValueError("Recovered names are ambiguous within the captured cohort")
            source = {name: records[routine]["pseudocode"] for routine, name in names.items()}
            results = {}
            for kind, (routine, arity, directed) in enumerate(ROUTINES, 1):
                row = results[routine] = dict(rows[routine])
                if routine not in names:
                    continue
                directory = output / f"{case}-{state}-{profile.replace('/', '-')}-{routine}"
                row.update(compare(directory, routine, kind, arity, directed, names[routine], source,
                                   compiler, sdk, harness, references))
            captures.append(dict(provenance, analysis_id=snapshot["analysis_id"], routines=results))
        rows = [row for capture in captures for row in capture["routines"].values()]
        report["counts"] = dict(Counter(row["status"] for row in rows))
        report["instruction_bytes"] = {
            "cohort": sum(row.get("llvm_instruction_bytes", 0) for row in rows),
            "completed_domains": sum(row["llvm_instruction_bytes"] for row in rows if "results" in row),
            "passed_domains": sum(row["llvm_instruction_bytes"] for row in rows if row["status"] == "passed"),
        }
        report["status"] = "passed" if rows and all(row["status"] == "passed" for row in rows) else "partial"
    finally:
        write_new_json(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-build-root", type=Path, required=True)
    parser.add_argument("--profile-matrix", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--experimental-trusted-input", action="store_true")
    args = parser.parse_args()
    if not args.experimental_trusted_input:
        parser.error("Explicit --experimental-trusted-input is required")
    report = run(args)
    print(json.dumps({key: report[key] for key in ("status", "counts", "instruction_bytes")}))
    return 0 if report["status"] == "passed" else 6


if __name__ == "__main__":
    raise SystemExit(main())
