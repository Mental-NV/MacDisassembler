#!/usr/bin/env python3
"""Opt-in calculator-only Ghidra prototype experiments, never production defaults.

Creates fresh projects under the system temp directory. No input is executed.
Requires an existing schema-2 fixture build manifest and pinned dependencies.
"""
import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "analysis"))
from macscope import engine
from validate_decompiler_evidence import (read_bytes, read_json, sha, write_new_json,
    compare_results, calculator_call_regression, require_complete_measured_facets)

PROFILE = "macscope-prototype-experiment/1/"
CASES = ("DebugAnalysis-arm64", "ReleaseAnalysis-arm64",
         "DebugAnalysis-x86_64", "ReleaseAnalysis-x86_64")
MARKER = '"macscope-binary-only/1"'
OPTION_POINT = "            Map<String, String> effective = getCurrentAnalysisOptionsAndValues(currentProgram);"


def fixture_input(build, case):
    if case not in CASES:
        raise ValueError("Unsupported fixture case")
    build = Path(build).resolve()
    manifest = read_json(build / "manifest.json")
    if manifest.get("schema") != "macscope-phase1-manifest/2":
        raise ValueError("A source-recorded schema-2 fixture manifest is required")
    config, arch = case.split("-", 1)
    records = [r for r in manifest["artifacts"]
               if (r.get("name"), r.get("config"), r.get("arch"),
                   r.get("symbols"), r.get("container")) ==
                  ("CorpusFixture", config, arch, "sym", "thin")]
    if len(records) != 1:
        raise ValueError("Missing or ambiguous owned calculator artifact")
    path = build / "analyst" / (case + "-sym") / "CorpusFixture"
    if path.is_symlink() or not path.resolve().is_relative_to(build):
        raise ValueError("Fixture input must remain inside its build tree")
    data = read_bytes(path)
    if sha(data) != records[0]["sha256"]:
        raise ValueError("Fixture input differs from the build manifest")
    return path, data, manifest


def prepare_scripts(destination, mode):
    if mode not in ("default", "paramid", "callee"):
        raise ValueError("Unknown experiment mode")
    destination.mkdir()
    bridge = (ROOT / "src/macscope/bridge/MacscopeBridge.java").read_text()
    if bridge.count(MARKER) != 1:
        raise ValueError("Bridge profile marker changed; review the experiment adapter")
    bridge = bridge.replace(MARKER, json.dumps(PROFILE + mode))
    (destination / "MacscopeBridge.java").write_text(bridge)
    if mode == "callee":
        shutil.copyfile(ROOT / "analysis/scripts/InferCalleeParameters.java",
                        destination / "InferCalleeParameters.java")
    else:
        profile = (ROOT / "src/macscope/bridge/MacscopeProfile.java").read_text()
        if profile.count(MARKER) != 1 or profile.count(OPTION_POINT) != 1:
            raise ValueError("Production profile changed; review the experiment adapter")
        profile = profile.replace(MARKER, json.dumps(PROFILE + mode))
        if mode == "paramid":
            profile = profile.replace(OPTION_POINT,
                '            setAnalysisOption(currentProgram, "Decompiler Parameter ID", "true");\n'
                + OPTION_POINT)
        (destination / "MacscopeProfile.java").write_text(profile)
    return {p.name: sha(read_bytes(p)) for p in destination.glob("*.java")}


def validate_result(result, input_sha, mode):
    if (result.get("schema") != "macscope-bridge/1"
            or result.get("ghidra_version") != "12.2"
            or result.get("executable_sha256") != input_sha):
        raise ValueError("Engine result identity or schema mismatch")
    if (result.get("analysis_timed_out") is not False
            or result.get("functions_truncated") is not False
            or result.get("output_budget_reached") is not False
            or result.get("status") not in ("complete", "partial")
            or result.get("errors")):
        raise ValueError("Incomplete or failed engine result")
    profile = result.get("analysis_profile", {})
    if profile.get("name") != PROFILE + mode or profile.get("applied") is not True:
        raise ValueError("Experiment profile did not complete")
    opts = result["effective_analysis_options"]
    if opts.get("Decompiler Parameter ID") != ("true" if mode == "paramid" else "false"):
        raise ValueError("Unexpected parameter-inference option")
    if mode == "callee":
        # Reopening a saved Program can expose newly registered default options.
        # They are dormant: this path must be a -noanalysis query, never an analysis.
        if (result.get("mode") != "query"
                or result.get("validation", {}).get("headless_analysis_enabled") is not False):
            raise ValueError("Callee-only experiment unexpectedly enabled autoanalysis")
    else:
        if result.get("mode") != "analyze":
            raise ValueError("Expected a fresh analysis result")
        for name, value in opts.items():
            if re.search(r"dwarf|pdb|source|demangl|external|library|debug", name, re.I):
                if value.lower() == "true":
                    raise ValueError("Source/external analyzer unexpectedly enabled: " + name)
    functions = result["functions"]
    if not functions or len(functions) != result["function_count_enumerated"]:
        raise ValueError("Bad function population")
    for f in functions:
        require_complete_measured_facets(f)
        status = f["decompile_status"]
        if status not in ("complete", "not_requested"):
            raise ValueError("Native decompiler failed, timed out or was cancelled")
        if status == "complete" and not f.get("pseudocode"):
            raise ValueError("Completed decompile without pseudocode")


def run_case(output, label, mode, source, data, dependencies, timeout, copied_from=None):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", label):
        raise ValueError("Invalid case label")
    case = output / label
    case.mkdir()
    for name in ("home", "tmp", "scripts"):
        if name != "scripts":
            (case / name).mkdir()
    scripts = prepare_scripts(case / "scripts", mode)
    input_sha = sha(data)
    source_program_digest = None
    if copied_from:
        source_program_digest = engine.tree_digest(copied_from / "project")
        shutil.copytree(copied_from / "project", case / "project")
    else:
        (case / "project").mkdir()
        with (case / "CorpusFixture").open("xb") as stream:
            stream.write(data)
    # Ghidra sees only the copied binary/scripts. This is not a hostile-input sandbox.
    sandbox = case / "sandbox.sb"
    sandbox.write_text('(version 1)\n(allow default)\n(deny network*)\n'
                       '(deny file-read-data (subpath "/Users"))\n'
                       '(deny file-write* (subpath "/Users"))\n')
    argv = ["/usr/bin/sandbox-exec", "-f", str(sandbox),
            str(Path(dependencies["ghidra_path"]) / "support/analyzeHeadless"),
            str(case / "project"), "experiment"]
    if copied_from:
        argv += ["-process", "CorpusFixture", "-noanalysis",
                 "-preScript", "InferCalleeParameters.java", "_calc_latch_error",
                 PROFILE + mode, str(case / "inference.json")]
    else:
        argv += ["-import", str(case / "CorpusFixture"), "-loader", "MachoLoader",
                 "-loader-loadLibraries", "false", "-loader-linkExistingProjectLibraries",
                 "false", "-loader-reexport", "false", "-preScript", "MacscopeProfile.java"]
    argv += ["-scriptPath", str(case / "scripts"), "-postScript", "MacscopeBridge.java",
             str(case / "result.json"), "query" if copied_from else "analyze", "5000", "30",
             "-max-cpu", "1", "-analysisTimeoutPerFile", str(max(1, timeout - 10)),
             "-log", str(case / "engine.log"), "-scriptlog", str(case / "script.log")]
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(case / "home"),
           "USER": os.environ.get("USER", "macscope"), "TMPDIR": str(case / "tmp") + "/",
           "JAVA_HOME": dependencies["java_home"], "GHIDRA_HEADLESS_MAXMEM": "1024M",
           "LANG": "en_US.UTF-8", "JAVA_TOOL_OPTIONS":
           f"-Duser.home={case}/home -Djava.io.tmpdir={case}/tmp "
           f"-Dapplication.settingsdir={case}/settings -Dapplication.cachedir={case}/cache"}
    record = {"label": label, "mode": mode, "input_sha256": input_sha,
              "scripts": scripts, "sandbox_sha256": sha(read_bytes(sandbox)),
              "classification": "Source-aware regression selection; binary-derived types",
              "status": "failed"}
    try:
        engine.run_process(argv, cwd=case, env=env, timeout=timeout,
                           log_path=case / "launcher.log", manifest_path=case / "job.json",
                           manifest={"dependencies": dependencies, "mode": mode})
        if b"Skipping unsupported -loader-" in read_bytes(case / "launcher.log"):
            raise ValueError("Pinned loader rejected a safety option")
        result = read_json(case / "result.json")
        validate_result(result, input_sha, mode)
        if copied_from:
            inference = read_json(case / "inference.json")
            if (inference["parameter_count"] != 2
                    or inference["return_type_before"] != inference["return_type_after"]
                    or engine.tree_digest(copied_from / "project") != source_program_digest):
                raise ValueError("Callee experiment violated its narrow scope")
            record["inference_sha256"] = sha(read_bytes(case / "inference.json"))
            record["source_program_unchanged_sha256"] = source_program_digest
        if sha(read_bytes(source)) != input_sha:
            raise ValueError("Fixture source input changed during experiment")
        record.update(status="complete", result_sha256=sha(read_bytes(case / "result.json")),
                      function_count=len(result["functions"]))
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if (case / "job.json").is_file():
            record["job_sha256"] = sha(read_bytes(case / "job.json"))
        write_new_json(case / "case.json", record)
    return case


def summarize(output):
    output = Path(output)
    context = read_json(output / "context.json")
    cases = context.get("fixture_cases", [])
    if (context.get("schema") != "macscope-prototype-context/1" or not cases
            or len(set(cases)) != len(cases) or any(case not in CASES for case in cases)):
        raise ValueError("Invalid experiment context")
    planned = [case + "-" + mode for case in cases for mode in ("default", "paramid")]
    if "DebugAnalysis-arm64" in cases:
        planned += ["DebugAnalysis-arm64-callee", "DebugAnalysis-arm64-repeat"]
    if context.get("planned_cases") != planned:
        raise ValueError("Recorded experiment plan is incomplete")
    results = {}
    records = {}
    for label in context["planned_cases"]:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", label):
            raise ValueError("Invalid recorded case label")
        directory = output / label
        record = read_json(directory / "case.json")
        if record.get("label") != label or record.get("status") != "complete":
            raise ValueError("Case did not complete: " + label)
        if sha(read_bytes(directory / "result.json")) != record["result_sha256"]:
            raise ValueError("Result changed after recording: " + label)
        for name, expected in record["scripts"].items():
            if Path(name).name != name or sha(read_bytes(directory / "scripts" / name)) != expected:
                raise ValueError("Experiment script changed")
        if sha(read_bytes(directory / "sandbox.sb")) != record["sandbox_sha256"]:
            raise ValueError("Sandbox profile changed")
        if sha(read_bytes(directory / "job.json")) != record["job_sha256"]:
            raise ValueError("Recorded engine command/result changed")
        if record["mode"] == "callee":
            if sha(read_bytes(directory / "inference.json")) != record["inference_sha256"]:
                raise ValueError("Callee inference evidence changed")
            inference = read_json(directory / "inference.json")
            if (inference["parameter_count"] != 2
                    or inference["return_type_before"] != inference["return_type_after"]):
                raise ValueError("Callee inference changed return type or parameter count")
        result = read_json(directory / "result.json")
        validate_result(result, record["input_sha256"], record["mode"])
        results[label] = result
        records[label] = record
    comparisons = []
    for case in context["fixture_cases"]:
        baseline = case + "-default"
        candidate = case + "-paramid"
        diff = compare_results(results[baseline], results[candidate])
        if not diff["unchanged_machine_facets"]:
            raise ValueError("Machine facets changed: " + case)
        if diff["option_deltas"] != {"Decompiler Parameter ID": ["false", "true"]}:
            raise ValueError("More than one analysis option changed")
        comparisons.append({"case": case, **diff})
    narrow = repeat = None
    special = "DebugAnalysis-arm64"
    if special in context["fixture_cases"]:
        baseline = special + "-default"
        candidate = special + "-paramid"
        narrow_label = special + "-callee"
        repeat_label = special + "-repeat"
        if not calculator_call_regression(results[baseline]["functions"])["known_extra_argument_observed"]:
            raise ValueError("Known fixture defect was not reproduced; review input/version")
        for label in (candidate, narrow_label, repeat_label):
            if not calculator_call_regression(results[label]["functions"])["expected_inferred_call_and_guard_observed"]:
                raise ValueError("Known regression was not improved: " + label)
        narrow = compare_results(results[baseline], results[narrow_label])
        changed_signatures = [r["name"] for r in narrow["changes"]["signature"]]
        if not narrow["unchanged_machine_facets"] or changed_signatures != ["_calc_latch_error"]:
            raise ValueError("Callee-only experiment changed more than the intended signature")
        repeat = compare_results(results[candidate], results[repeat_label])
        if any(repeat["changes"].values()) or repeat["option_deltas"]:
            raise ValueError("Repeated candidate changed its measured facets")
    return {"schema": "macscope-prototype-summary/1", "status": "passed",
            "completed_cases": len(results), "fixture_provenance": context["fixture_provenance"],
            "paired_analysis": comparisons, "callee_only": narrow, "repeat": repeat,
            "result_sha256": {key: value["result_sha256"] for key, value in records.items()},
            "scope": "Owned symbol-bearing calculator only; operation completion and "
                     "a known call regression, not semantic equivalence or release qualification"}


def run(args):
    if not args.experimental_trusted_input:
        raise ValueError("Explicit --experimental-trusted-input is required")
    output = args.output_dir.resolve()
    temp_roots = {Path(tempfile.gettempdir()).resolve(), Path("/tmp").resolve()}
    if (not any(output.is_relative_to(root) and output != root for root in temp_roots)
            or any(c.isspace() or c in '\\\"' for c in str(output))):
        raise ValueError("Use a new whitespace/quote/backslash-free directory under the system temp directory")
    if output.exists():
        raise FileExistsError("Experiment output already exists")
    cases = args.case or list(CASES)
    if len(set(cases)) != len(cases):
        raise ValueError("Duplicate fixture case")
    inputs = {case: fixture_input(args.fixture_build_root, case) for case in cases}
    dependencies = engine.dependencies(full=True)
    # The installed engine and this research harness are trusted dependencies.
    os.umask(0o077)
    output.mkdir()
    planned = [case + "-" + mode for case in cases for mode in ("default", "paramid")]
    if "DebugAnalysis-arm64" in cases:
        planned += ["DebugAnalysis-arm64-callee", "DebugAnalysis-arm64-repeat"]
    manifest = next(iter(inputs.values()))[2]
    source = manifest.get("source", {})
    context = {"schema": "macscope-prototype-context/1", "fixture_cases": cases,
               "planned_cases": planned, "fixture_provenance": {
                   "manifest_sha256": sha(read_bytes(args.fixture_build_root / "manifest.json")),
                   "semantics_version": source.get("semantics_version"),
                   "git_revision": source.get("git_revision"),
                   "source_tree_sha256": source.get("source_tree_sha256")}}
    write_new_json(output / "context.json", context)
    try:
        for case in cases:
            path, data, _ = inputs[case]
            for mode in ("default", "paramid"):
                run_case(output, case + "-" + mode, mode, path, data, dependencies, args.timeout)
        if "DebugAnalysis-arm64" in cases:
            path, data, _ = inputs["DebugAnalysis-arm64"]
            run_case(output, "DebugAnalysis-arm64-callee", "callee", path, data, dependencies,
                     args.timeout, output / "DebugAnalysis-arm64-default")
            run_case(output, "DebugAnalysis-arm64-repeat", "paramid", path, data, dependencies, args.timeout)
        summary = summarize(output)
    except BaseException as error:
        write_new_json(output / "summary.json",
                       {"schema": "macscope-prototype-summary/1", "status": "failed",
                        "error": type(error).__name__ + ": " + str(error)})
        raise
    write_new_json(output / "summary.json", summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("run")
    create.add_argument("--fixture-build-root", type=Path, required=True)
    create.add_argument("--output-dir", type=Path, required=True)
    create.add_argument("--case", action="append", choices=CASES)
    create.add_argument("--timeout", type=int, default=120, choices=range(30, 601), metavar="30..600")
    create.add_argument("--experimental-trusted-input", action="store_true")
    review = sub.add_parser("summarize")
    review.add_argument("output_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run(args) if args.command == "run" else summarize(args.output_dir)
    except (OSError, ValueError, engine.Error) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
