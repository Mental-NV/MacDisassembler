#!/usr/bin/env python3
"""Validate opt-in joins against the complete owned patched calculator matrix."""
import argparse
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analysis"))
from score_discovery import verified_captures
from validate_decompiler_evidence import read_bytes, sha, write_new_json

from macscope import cli, engine, flow_boundaries
from macscope.schema import validate_envelope
from macscope.storage import Project


def evidence(snapshot):
    return {
        f["engine_entry"]: (
            f["body_ranges"], [(i["addr"], i["bytes"], i["flow"], i["fallthrough"]) for i in f["instructions"]],
            f["blocks"], f["signature"], f["pseudocode"], f["decompile_status"],
        )
        for f in snapshot["functions"]
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-build-root", type=Path, required=True)
    parser.add_argument("--profile-matrix", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--experimental-trusted-input", action="store_true")
    args = parser.parse_args()
    if not args.experimental_trusted_input:
        parser.error("Explicit --experimental-trusted-input is required")
    original = args.profile_matrix.resolve()
    output = args.output_dir.resolve()
    if not output.is_relative_to(Path("/tmp").resolve()) or output == Path("/tmp").resolve():
        raise ValueError("Choose a new output directory under canonical /tmp")
    output.mkdir(mode=0o700)
    deps = engine.dependencies(args.ghidra, full=True)
    captures = []
    report = {"status": "failed", "captures": captures,
              "matrix_sha256": sha(read_bytes(original / "report.json"))}

    def run(project, *argv):
        result = cli.execute(cli.parser().parse_args([*map(str, argv), "--project", str(project.path), "--json"]))
        validate_envelope(result)
        return result

    try:
        for kind in ("app", "tool"):
            for provenance, prior, _, _, _ in verified_captures(args.fixture_build_root, original, kind=kind):
                profile = provenance["profile"].split("/", 1)[0]
                label = f"{provenance['case']}-{provenance['symbols']}-{kind}"
                source = original / label
                copied = output / label
                if not copied.exists():
                    shutil.copytree(Project(source).path, copied)
                project = Project(copied)
                image = project.select()
                baseline = project.path / "engine" / image["image_id"]
                before = engine.tree_digest(baseline)
                if (before != image["engine_baseline_sha256"] or image["sha256"] != provenance["input_sha256"]
                        or deps["native_decompiler_sha256"] != prior["identity"]["engine"]["native_decompiler_sha256"]
                        or deps["ghidra_tree_sha256"] != prior["identity"]["engine"]["ghidra_tree_sha256"]):
                    raise ValueError("Fixture or engine differs from the frozen calculator matrix")
                analyzed = run(project, "analyze", "--profile", profile, "--ghidra", args.ghidra,
                               "--experimental-trusted-input", "--repair-split-boundaries")
                result = analyzed["data"]["boundary_recovery"]
                actual = [(row["owner"], row["competing"]) for row in result["candidates"]
                          if row["outcome"] == "joined"]
                expected = [(row["linker_entry_va"], row["to"]) for rows in flow_boundaries.gaps(prior).values()
                            for row in rows if row["reason"] == "fallthrough_into_unconfirmed_function"]
                if result["status"] != "complete" or actual != expected:
                    raise ValueError("Boundary repair differs from the known calculator cohort")
                snapshot = run(project, "export")["data"]
                old, new = evidence(prior), evidence(snapshot)
                for owner, competing in actual:
                    old.pop(owner)
                    old.pop(competing)
                    new.pop(owner)
                if old != new or engine.tree_digest(baseline) != before:
                    raise ValueError("Boundary repair changed an unrelated function or the pristine import")
                captures.append({
                    "case": label, "profile": profile, "joined": bool(actual), "peer_functions": len(new),
                    "analysis_id": snapshot["analysis_id"], "request_sha256": result["request_sha256"],
                })
                print(f"{label} {profile} {'joined' if actual else 'unchanged'}", flush=True)
        if len(captures) != 32 or sum(row["joined"] for row in captures) != 2:
            raise ValueError("Unexpected calculator recovery denominator")
        report["status"] = "passed"
    finally:
        write_new_json(output / "report.json", report)
    print(json.dumps({"status": report["status"], "captures": len(captures)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
