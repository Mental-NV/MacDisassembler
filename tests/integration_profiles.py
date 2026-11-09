#!/usr/bin/env python3
"""Opt-in public-CLI profile integration on the owned manifest-verified fixture matrix.

No builds, installs, input execution, UI, existing-workspace mutation or network.
Default matrix: both architectures, O0/O2, symbols/stripped, app main/tool (16 cases).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "analysis"))
from macscope import engine
from macscope.cli import parser as cli_parser
from macscope.schema import validate_envelope
from macscope.storage import Project
from validate_decompiler_evidence import compare_results, calculator_call_regression


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def comparison_view(snapshot):
    return dict(snapshot["engine"], functions=snapshot["functions"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-build-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--kind", choices=("all", "tool", "app"), default="all")
    parser.add_argument("--experimental-trusted-input", action="store_true")
    args = parser.parse_args(argv)
    if not args.experimental_trusted_input:
        parser.error("Explicit --experimental-trusted-input is required")
    build = args.fixture_build_root.resolve()
    manifest = json.loads((build / "manifest.json").read_text())
    if manifest.get("schema") != "macscope-phase1-manifest/2":
        raise ValueError("Requires source-recorded owned fixture manifest")
    matrix = []
    for record in manifest["artifacts"]:
        if (record["container"] != "thin" or record["name"] not in ("CorpusFixture", "CalculatorFixture")
                or record["arch"] not in ("arm64", "x86_64")):
            continue
        kind = "tool" if record["name"] == "CorpusFixture" else "app"
        if args.kind != "all" and kind != args.kind:
            continue
        directory = build / "analyst" / (record["config"] + "-" + record["arch"] + "-" + record["symbols"])
        source = directory / ("CorpusFixture" if kind == "tool" else "CalculatorFixture.app/Contents/MacOS/CalculatorFixture")
        if digest(source) != record["sha256"]:
            raise ValueError("Fixture input does not match manifest")
        label = "-".join((record["config"], record["arch"], record["symbols"], kind))
        matrix.append((label, source, record, kind))
    expected = 16 if args.kind == "all" else 8
    if len(matrix) != expected or len({row[0] for row in matrix}) != expected:
        raise ValueError("Incomplete or duplicate fixture matrix")
    output = args.output_dir.resolve()
    output.mkdir(mode=0o700)  # Never reuse earlier evidence.
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
    commands = []
    cases = []
    queries = []
    start = time.monotonic()

    def invoke(*arguments, expected=(0,)):
        if time.monotonic() - start > 1800:
            raise TimeoutError("Integration suite exceeded 30-minute aggregate budget")
        proc = subprocess.run([sys.executable, "-m", "macscope", *map(str, arguments)],
                              cwd=ROOT, env=env, capture_output=True, timeout=420)
        index = len(commands) + 1
        (output / f"{index:03}.stdout").write_bytes(proc.stdout)
        (output / f"{index:03}.stderr").write_bytes(proc.stderr)
        commands.append({"argv": list(map(str, arguments)), "exit": proc.returncode})
        if proc.returncode not in expected:
            raise RuntimeError(f"CLI exit {proc.returncode}: {proc.stderr.decode(errors='replace')}")
        response = json.loads(proc.stdout)
        validate_envelope(response)
        return response

    def exported(project):
        return invoke("export", "--project", project, "--json", expected=(0, 6))["data"]

    result = {"status": "failed"}
    try:
        invoke("version", "--json")
        for label, source, record, kind in matrix:
            project = output / label
            invoke("project", "create", project, "--json")
            invoke("import", source, "--project", project, "--arch", record["arch"],
                   "--experimental-trusted-input", "--json")
            workspace = Project(project)
            image = workspace.select()
            baseline_program = workspace.path / "engine" / image["image_id"]
            import_digest = engine.tree_digest(baseline_program)
            # Omitting --profile must continue to mean baseline.
            invoke("analyze", "--project", project, "--experimental-trusted-input", "--json",
                   expected=(0, 6))
            baseline = exported(project)
            baseline_raw, _ = workspace.snapshot(workspace.select())
            if baseline["identity"]["profile"] != "baseline/1":
                raise AssertionError("Default profile changed")
            invoke("analyze", "--project", project, "--profile", "parameter-inference",
                   "--experimental-trusted-input", "--json", expected=(0, 6))
            inferred = exported(project)
            inferred_raw, _ = workspace.snapshot(workspace.select())
            if (inferred["identity"]["profile"] != "parameter-inference/1"
                    or inferred["analysis_id"] == baseline["analysis_id"]
                    or inferred["analysis_profile"] != engine.analysis_profile("parameter-inference")):
                raise AssertionError("Profile identity/provenance not distinct")
            comparison = compare_results(comparison_view(baseline_raw), comparison_view(inferred_raw))
            comparison["engine_complete_pseudocode_count"] = comparison["complete_pseudocode_count"]
            comparison["complete_pseudocode_count"] = sum(
                f["decompile_status"] == "complete" for f in inferred["functions"]
            )
            comparison["control_flow_review"] = {
                "baseline": baseline.get("control_flow_review"), "parameter_inference": inferred.get("control_flow_review"),
            }
            if not comparison["unchanged_machine_facets"]:
                raise AssertionError("Fixture machine evidence changed")
            if comparison["option_deltas"] != {"Decompiler Parameter ID": ["false", "true"]}:
                raise AssertionError("Unexpected analysis option changes")
            cached = invoke("decompile", "--project", project, "--all", "--limit", "1000",
                            "--json", expected=(0, 6))
            expected_code = {f["function_id"]: f["pseudocode"] for f in inferred["functions"]}
            if {f["function_id"]: f["pseudocode"] for f in cached["data"]["functions"]} != expected_code:
                raise AssertionError("Cached query differs from inferred snapshot")
            regression = None
            if (record["config"], record["arch"], record["symbols"]) == ("DebugAnalysis", "arm64", "sym"):
                regression = calculator_call_regression(inferred["functions"])
                if (not calculator_call_regression(baseline["functions"])["known_extra_argument_observed"]
                        or not regression["expected_inferred_call_and_guard_observed"]):
                    raise AssertionError("Known source-aware regression not reproduced/improved")
            if record["config"] == "DebugAnalysis" and record["symbols"] == "sym" and kind == "tool":
                # Reopen the actual saved inferred Program through the production runner.
                active_image = workspace.select()
                snap, saved = workspace.snapshot(active_image)
                program = workspace.path / "jobs" / saved["job_id"] / "program"
                before = engine.tree_digest(program)
                query_args = cli_parser().parse_args(["analyze", "--project", str(project),
                                                     "--experimental-trusted-input"])
                raw, job = engine.run(workspace, active_image, "query", query_args,
                                      engine.dependencies(full=True))
                if (job["analysis_profile"]["name"] != "parameter-inference"
                        or engine.tree_digest(program) != before
                        or raw["validation"]["headless_analysis_enabled"] is not False):
                    raise AssertionError("Saved-profile query violated its provenance/read-only scope")
                target = next(f for f in inferred["functions"] if f["name"] == "_calc_add")
                fresh = invoke("decompile", "--fresh", "--project", project,
                               "--function-id", target["function_id"],
                               "--experimental-trusted-input", "--json")
                if (fresh["analysis_id"] != inferred["analysis_id"]
                        or fresh["data"]["pseudocode"] != target["pseudocode"]
                        or fresh["data"]["origin"]["analysis_profile"]["name"] != "parameter-inference"
                        or engine.tree_digest(program) != before
                        or workspace.snapshot(workspace.select()) != (snap, saved)):
                    raise AssertionError("Fresh decompilation violated saved profile or snapshot isolation")
                queries.append({"case": label, "source_program_sha256": before,
                                "job_id": job["job_id"], "profile": job["analysis_profile"]})
                invoke("analyze", "--project", project, "--profile", "parameter-inference",
                       "--experimental-trusted-input", "--json", expected=(0, 6))
                if exported(project) != inferred:
                    raise AssertionError("Repeated inference snapshot differs")
            # Switching back starts from the immutable no-analysis import, not the inferred Program.
            invoke("analyze", "--project", project, "--profile", "baseline",
                   "--experimental-trusted-input", "--json", expected=(0, 6))
            restored = exported(project)
            if restored != baseline or engine.tree_digest(baseline_program) != import_digest:
                raise AssertionError("Inference contaminated the baseline")
            if digest(source) != record["sha256"]:
                raise AssertionError("Source fixture input changed")
            cases.append({"case": label, "input_sha256": record["sha256"],
                          "baseline_analysis_id": baseline["analysis_id"],
                          "inference_analysis_id": inferred["analysis_id"],
                          "baseline_restored_exactly": True, "import_program_unchanged": True,
                          "comparison": comparison, "source_aware_regression": regression})
            print(f"{label}: passed ({comparison['function_count']} functions)", flush=True)
        result = {"status": "passed", "matrix_cases": len(cases), "command_checks": len(commands),
                  "fixture_manifest_sha256": digest(build / "manifest.json"),
                  "fixture_source": manifest["source"], "cases": cases,
                  "readonly_inferred_queries": queries, "commands": commands,
                  "scope": "Owned fixture matrix; profile provenance and static evidence, not semantic equivalence"}
    except BaseException as error:
        result.update(error=type(error).__name__ + ": " + str(error),
                      cases=cases, commands=commands, readonly_inferred_queries=queries)
        raise
    finally:
        (output / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": "passed", "matrix_cases": len(cases),
                      "command_checks": len(commands), "output": str(output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
