#!/usr/bin/env python3
"""Freeze, capture and score a separate owned aggregate-return fixture."""
import argparse
from collections import Counter
from itertools import product
import json
from pathlib import Path
import subprocess

from aggregate_compat import POLICY, Unsupported, lower_closure
from audit_core_behavior import complete
from compare_heldout_switch import PROFILES, truth_for
from prototype_experiment import ROOT
from recovered_compare import run_candidate
from reference_coverage import xcrun
from validate_decompiler_evidence import read_bytes, read_json, sha, write_new_json
from macscope import cli, engine
from macscope.macho import thin


ROUTINES = ("heldout_packet", "heldout_checked")
BUILDS = tuple(product(("arm64", "x86_64"), ("O0", "O2")))
STATES = ("sym", "stripped")
SOURCES = {"aggregate": "heldout_aggregate.c", "arithmetic": "heldout_arithmetic.c"}
HEADER = "heldout_aggregate.h"
HARNESS = "compare_heldout_aggregate_harness.c"
COMPAT = "aggregate_compat.h"
FROZEN = (HEADER, HARNESS, COMPAT, "aggregate_compat.py", "compare_heldout_aggregates.py",
          "compare_heldout_switch.py", "recovered_compare.py")


def freeze(source):
    revision = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "HEAD"], text=True).strip()
    files = {}
    for name in (source, *FROZEN):
        committed = subprocess.check_output(["git", "-C", ROOT, "show", f"{revision}:analysis/{name}"])
        if committed != read_bytes(ROOT / "analysis" / name):
            raise ValueError("The held-out contract must match a committed revision: " + name)
        files[name] = committed
    return revision, files


def build(evaluator, inputs, files, source, compiler, sdk):
    for name in (source, HEADER):
        (evaluator / name).write_bytes(files[name])
    digests = {}
    for arch, opt in BUILDS:
        variant = f"{arch}-{opt}"
        directory = evaluator / variant
        directory.mkdir()
        flags = ["-arch", arch, "-isysroot", sdk]
        subprocess.run([compiler, *flags, "-std=c11", "-g", "-" + opt, "-DHELDOUT_LINK_IMAGE",
                        "-c", f"../{source}", "-o", "Fixture.o"], cwd=directory, check=True, timeout=30)
        subprocess.run([compiler, *flags, "Fixture.o", "-o", "Fixture"], cwd=directory, check=True, timeout=30)
        subprocess.run([xcrun("--find", "dsymutil"), "Fixture"], cwd=directory, check=True, timeout=30)
        target = inputs / variant
        target.mkdir()
        (target / "sym").write_bytes(read_bytes(directory / "Fixture"))
        subprocess.run([xcrun("--find", "strip"), "-o", target / "stripped", target / "sym"],
                       check=True, timeout=30)
        digests[variant] = {state: sha(read_bytes(target / state)) for state in STATES}
    return digests


def capture(output, evaluator, inputs, ghidra, java_home):
    projects = output / "projects"
    projects.mkdir()
    profile = engine.profile

    def isolated(project, dependencies):
        denials = "".join("(deny file-read-data (subpath " + json.dumps(str(path)) + "))\n"
                          for path in (evaluator, inputs, ROOT / "analysis"))
        siblings = ("(deny file-read-data (require-all (subpath " + json.dumps(str(projects))
                    + ") (require-not (subpath " + json.dumps(str(project.path)) + "))))\n")
        return profile(project, dependencies) + denials + siblings

    def invoke(destination, argv):
        if cli.main([*argv, "--json", "--output", str(destination)]) not in (0, 6):
            raise ValueError("CLI capture failed: " + destination.name)

    paths = []
    engine.profile = isolated
    try:
        for (arch, opt), state in product(BUILDS, STATES):
            variant = f"{arch}-{opt}"
            label = f"{variant}-{state}"
            project_path = str(projects / label)
            project = ["--project", project_path]
            worker = ["--ghidra", str(ghidra), "--java-home", str(java_home), "--timeout", "120",
                      "--experimental-trusted-input"]
            invoke(output / (label + "-create.json"), ["project", "create", project_path])
            invoke(output / (label + "-import.json"), ["import", str(inputs / variant / state), *project, *worker])
            for profile_name in PROFILES:
                invoke(output / (label + "-" + profile_name + "-analyze.json"),
                       ["analyze", "--profile", profile_name, *project, *worker])
                path = output / (label + "-" + profile_name + ".json")
                invoke(path, ["export", *project])
                paths.append((variant, state, profile_name, path.name))
    finally:
        engine.profile = profile
    return [{"variant": variant, "symbols": state, "profile": profile_name,
             "file": name, "sha256": sha(read_bytes(output / name))}
            for variant, state, profile_name, name in paths]


def evaluate(directory, routine, record, definitions, compiler, sdk, files, source):
    try:
        lowered, dependencies = lower_closure(record["name"], definitions, 2)
    except Unsupported as error:
        return {"status": "not_testable", "reason": str(error)}
    directory.mkdir()
    (directory / "candidate.c").write_text(lowered)
    flags = ["-fsanitize=address", f"-DRECOVERED={record['name']}", f"-DCHECKED={int(routine == ROUTINES[1])}"]
    result = run_candidate(directory, compiler, sdk, files[HARNESS], {n: files[n] for n in (source, HEADER, COMPAT)},
                           flags, reference_source=source)
    result.update(lowered_sha256=sha(lowered.encode()), captured_definitions=dependencies)
    counts = result.get("results")
    if counts is not None:
        if counts["directed"] != 256 or counts["seeded"] != 10000 or any(
            not 0 <= counts[key] <= 10256 for key in ("mismatches", "undefined_results", "unspecified_padding")
        ):
            raise ValueError("Evaluator did not complete the declared held-out domain")
        result["status"] = ("undefined_result" if counts["undefined_results"]
                            else "mismatch" if counts["mismatches"] else "passed")
    return result


def score(output, evaluator, inputs, compiler, sdk, files, source):
    plan = read_json(output / "frozen-plan.json")
    frozen = read_json(output / "frozen-captures.json")
    truth = {}
    for arch, opt in BUILDS:
        variant = f"{arch}-{opt}"
        addresses, digests = truth_for(evaluator, inputs, variant, ROUTINES)
        if digests != plan["inputs"][variant]:
            raise ValueError("Captured bytes differ from the frozen inputs")
        paths = [inputs / variant / state for state in STATES]
        starts = [thin(read_bytes(path))["loader"]["function_starts"] for path in paths]
        if starts[0] != starts[1]:
            raise ValueError("Stripping changed linker function starts")
        nm = xcrun("--find", "nm")
        names = [subprocess.check_output([nm, "-j", path], text=True, timeout=10).splitlines() for path in paths]
        if any("_" + routine not in names[0] or "_" + routine in names[1] for routine in ROUTINES):
            raise ValueError("Unexpected held-out symbol state")
        truth[variant] = addresses

    results = []
    for row in frozen:
        variant, state, profile_name = (row[key] for key in ("variant", "symbols", "profile"))
        raw = read_bytes(output / row["file"])
        snapshot = json.loads(raw)["data"]
        identity = snapshot["identity"]
        if (sha(raw) != row["sha256"] or identity["profile"] != profile_name + "/1"
                or identity["engine"]["native_decompiler_sha256"] != plan["native_sha256"]
                or snapshot["image"]["sha256"] != plan["inputs"][variant][state]):
            raise ValueError("Export differs from the frozen capture")
        records = {f["entry_va"]: f for f in snapshot["functions"] if complete(f)}
        addresses = truth[variant]
        definitions = {records[entry]["name"]: records[entry]["pseudocode"]
                       for entry in addresses.values() if entry in records}
        for routine, entry in addresses.items():
            record = records.get(entry)
            result = {"status": "not_testable", "reason": "Missing complete pseudocode"}
            if record is not None:
                directory = output / (Path(row["file"]).stem + "-" + routine)
                result = evaluate(directory, routine, record, definitions, compiler, sdk, files, source)
                result["pseudocode_sha256"] = sha(record["pseudocode"].encode())
            results.append(dict(row, analysis_id=snapshot["analysis_id"], routine=routine, entry=entry, **result))
    counts = dict(Counter(row["status"] for row in results))
    return {"schema": "macscope-heldout-aggregate/1", "counts": counts, "results": results,
            "status": "passed" if counts == {"passed": len(BUILDS)*len(STATES)*len(PROFILES)*len(ROUTINES)} else "partial",
            "plan_sha256": sha(read_bytes(output / "frozen-plan.json")),
            "captures_sha256": sha(read_bytes(output / "frozen-captures.json"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("output-dir", "ghidra", "java-home"):
        parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--fixture", choices=SOURCES, default="aggregate")
    parser.add_argument("--experimental-trusted-input", action="store_true")
    args = parser.parse_args()
    if not args.experimental_trusted_input:
        parser.error("Explicit --experimental-trusted-input is required")
    output = args.output_dir.resolve()
    scratch = Path("/tmp").resolve()
    if output == scratch or not output.is_relative_to(scratch):
        parser.error("Choose a new output directory under canonical /tmp")
    source = SOURCES[args.fixture]
    revision, files = freeze(source)
    compiler, sdk = xcrun("--find", "clang"), xcrun("--sdk", "macosx", "--show-sdk-path")
    ghidra, java_home = args.ghidra.resolve(), args.java_home.resolve()
    output.mkdir(mode=0o700)
    evaluator, inputs = output / "evaluator", output / "inputs"
    evaluator.mkdir()
    inputs.mkdir()
    digests = build(evaluator, inputs, files, source, compiler, sdk)
    write_new_json(output / "frozen-plan.json", {
        "revision": revision, "policy": POLICY, "source": source,
        "files_sha256": {name: sha(data) for name, data in files.items()},
        "compiler_sha256": engine.digest(Path(compiler)), "sdk_version": xcrun("--sdk", "macosx", "--show-sdk-version"),
        "native_sha256": engine.digest(ghidra / "Ghidra/Features/Decompiler/os/mac_arm_64/decompile"),
        "inputs": digests,
    })
    write_new_json(output / "frozen-captures.json", capture(output, evaluator, inputs, ghidra, java_home))
    report = score(output, evaluator, inputs, compiler, sdk, files, source)
    write_new_json(output / "report.json", report)
    print(json.dumps({key: report[key] for key in ("status", "counts")}))
    return 0 if report["status"] == "passed" else 6


if __name__ == "__main__":
    raise SystemExit(main())
