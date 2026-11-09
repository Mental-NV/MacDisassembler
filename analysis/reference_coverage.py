#!/usr/bin/env python3
"""Measure branch coverage of the owned calculator reference tests."""
import argparse
import json
from pathlib import Path
import platform
import re
import subprocess

from prototype_experiment import ROOT
from validate_decompiler_evidence import read_bytes, sha, write_new_json
from macscope import engine


SOURCES = ("fixture/src/calc_core.c", "fixture/src/calc_core.h", "fixture/tests/calc_core_tests.c")
MIN_BRANCH_PERCENT = 95


def xcrun(*args):
    return subprocess.check_output(["/usr/bin/xcrun", *args], text=True, timeout=15).strip()


def measure(output):
    output = output.resolve()
    scratch = Path("/tmp").resolve()
    if output == scratch or not output.is_relative_to(scratch):
        raise ValueError("Choose a new output directory under canonical /tmp")
    output.mkdir(mode=0o700)
    sources = {}
    for path in SOURCES:
        payload = read_bytes(ROOT / path)
        (output / Path(path).name).write_bytes(payload)
        sources[path] = sha(payload)
    tools = {name: xcrun("--find", name) for name in ("clang", "llvm-profdata", "llvm-cov")}
    sdk = xcrun("--sdk", "macosx", "--show-sdk-path")
    sdk_version = xcrun("--sdk", "macosx", "--show-sdk-version")
    sandbox = output / "sandbox.sb"
    sandbox.write_text(
        '(version 1) (allow default) (deny network*) (deny file-read-data (subpath "/Users")) '
        '(deny file-write* (require-not (subpath ' + json.dumps(str(output)) + ')))\n'
    )
    env = {"PATH": "/usr/bin:/bin", "HOME": str(output), "TMPDIR": str(output) + "/",
           "LANG": "en_US.UTF-8", "LLVM_PROFILE_FILE": str(output / "coverage.profraw")}

    def run(name, argv, log=None):
        engine.run_process(
            ["/usr/bin/sandbox-exec", "-f", str(sandbox), *argv],
            cwd=output, env=env, timeout=30, log_path=output / (log or name + ".log"),
            manifest_path=output / (name + ".json"), manifest={"phase": name},
        )

    run("compile", [tools["clang"], "-std=c11", "-O0", "-g", "-fprofile-instr-generate",
                    "-fcoverage-mapping", "-isysroot", sdk, "calc_core.c", "calc_core_tests.c",
                    "-o", "reference-tests"])
    run("reference", [str(output / "reference-tests")])
    run("merge", [tools["llvm-profdata"], "merge", "-sparse", "coverage.profraw", "-o", "coverage.profdata"])
    run("coverage", [tools["llvm-cov"], "export", "reference-tests", "-instr-profile", "coverage.profdata"],
        log="coverage-raw.json")

    status = re.fullmatch(r"core_tests: pass=([1-9][0-9]*) fail=0\n", (output / "reference.log").read_text())
    if not status:
        raise ValueError("Reference test count missing or incomplete")
    raw = read_bytes(output / "coverage-raw.json")
    record, = [f for f in json.loads(raw)["data"][0]["files"] if Path(f["filename"]).name == "calc_core.c"]
    branches = record["summary"]["branches"]
    if not branches["count"] or branches["covered"] + branches["notcovered"] != branches["count"]:
        raise ValueError("Invalid reference branch counts")
    passed = branches["covered"] * 100 >= MIN_BRANCH_PERCENT * branches["count"]
    report = {
        "schema": "macscope-reference-coverage/1", "status": "passed" if passed else "below_target",
        "scope": "Owned reference source and stateful tests, independent of recovered C",
        "assertions_passed": int(status[1]), "required_branch_percent": MIN_BRANCH_PERCENT,
        "branches": branches, "coverage_sha256": sha(raw), "sources_sha256": sources,
        "host_arch": platform.machine(), "sdk_version": sdk_version,
        "tools_sha256": {name: engine.digest(Path(path)) for name, path in tools.items()},
    }
    write_new_json(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--experimental-trusted-input", action="store_true")
    args = parser.parse_args()
    if not args.experimental_trusted_input:
        parser.error("Explicit --experimental-trusted-input is required")
    report = measure(args.output_dir)
    print(json.dumps({key: report[key] for key in ("status", "assertions_passed", "branches")}))
    return 0 if report["status"] == "passed" else 6


if __name__ == "__main__":
    raise SystemExit(main())
