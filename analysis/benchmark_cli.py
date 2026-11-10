#!/usr/bin/env python3
"""Measure the public CLI on a manifest-verified owned calculator tool."""
import argparse
from collections import defaultdict
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time

from prototype_experiment import ROOT, fixture_input
from validate_decompiler_evidence import read_bytes, read_json, require_complete_function_inventory, sha
from macscope.schema import validate_envelope
from macscope.storage import Project


TARGETS = {"inspect": 2, "analyze": 60, "decompile_cached": 5}


def summarize(samples):
    summary = {}
    for stage, elapsed in samples.items():
        ordered = sorted(elapsed)
        p95 = ordered[math.ceil(len(ordered) * .95) - 1]
        summary[stage] = {"samples": len(elapsed), "median_seconds": statistics.median(elapsed),
                          "p95_seconds": p95, "maximum_seconds": ordered[-1]}
        if stage in TARGETS:
            summary[stage].update(target_seconds=TARGETS[stage],
                                  target_met=p95 < TARGETS[stage] if len(elapsed) == 20 else None)
    return summary


def reported_times(log):
    stages = {}
    startup = re.findall(r"^INFO  Headless startup complete \((\d+) ms\) \(AnalyzeHeadless\) *$", log, re.M)
    analysis = re.findall(r"^ +Total Time +(\d+) secs *$", log, re.M)
    if len(startup) == 1:
        stages["headless_startup"] = int(startup[0]) / 1000
    if len(analysis) == 1:
        stages["autoanalysis_reported"] = int(analysis[0])
    return stages


def benchmark(args):
    binary, content, manifest = fixture_input(args.fixture_build_root, "DebugAnalysis-arm64")
    output = args.output_dir.resolve()
    if not any(output.is_relative_to(root) and output != root for root in
               (Path(tempfile.gettempdir()).resolve(), Path("/tmp").resolve())):
        raise ValueError("Use a new output directory under the system temporary directory")
    output.mkdir(mode=0o700)
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
    samples = defaultdict(list)
    commands = []
    host = {"arch": platform.machine(), "macos": platform.mac_ver()[0],
            "python": platform.python_version()}
    ram = subprocess.run(["/usr/sbin/sysctl", "-n", "hw.memsize"], capture_output=True,
                         text=True, check=False, timeout=5)
    if ram.returncode == 0 and ram.stdout.strip().isdigit():
        host["memory_bytes"] = int(ram.stdout)
    report = {"schema": "macscope-cli-benchmark/1", "status": "failed",
              "host": host, "fixture_sha256": sha(content),
              "fixture_source_tree_sha256": manifest["source"]["source_tree_sha256"],
              "manifest_sha256": sha(read_bytes(args.fixture_build_root / "manifest.json")),
              "commands": commands, "samples_seconds": samples}

    def invoke(stage, *argv, expected=(0,)):
        index = len(commands) + 1
        started = time.monotonic()
        proc = subprocess.run([sys.executable, "-m", "macscope", *map(str, argv), "--json"],
                              cwd=ROOT, env=env, capture_output=True, timeout=330)
        elapsed = time.monotonic() - started
        commands.append({"stage": stage, "argv": list(map(str, argv)), "exit": proc.returncode})
        (output / f"{index:03}.stdout").write_bytes(proc.stdout)
        (output / f"{index:03}.stderr").write_bytes(proc.stderr)
        if proc.returncode not in expected:
            raise RuntimeError(f"{stage} failed with exit {proc.returncode}; see capture {index:03}")
        result = json.loads(proc.stdout)
        validate_envelope(result)
        samples[stage].append(elapsed)
        return result

    def worker_time(stage, project, job_id):
        directory = project / "jobs" / job_id
        job = read_json(directory / "job.json")
        samples[stage + "_worker"].append(job["elapsed_seconds"])
        for metric, elapsed in reported_times(read_bytes(directory / "launcher.log").decode(errors="replace")).items():
            samples[stage + "_" + metric].append(elapsed)
        startup = job.get("startup", {})
        if startup.get("status") == "ready":
            samples[stage + "_launcher_to_ready"].append(startup["observed_seconds"])
        if "decompiler_timing" in job:
            raw = read_json(directory / "bridge.json")
            timing = raw["decompiler_timing"]
            opening = timing["open_program"]
            if opening is not None:
                samples[stage + "_decompiler_open_program"].append(opening["elapsed_ns"] / 1e9)
            samples[stage + "_decompile_call"].extend(call["elapsed_ns"] / 1e9 for call in timing["calls"])
        pinned = {k: v for k, v in job["dependencies"].items()
                  if k not in ("ghidra_path", "java_home")}
        if report.setdefault("engine", pinned) != pinned:
            raise RuntimeError("Worker dependencies changed during the benchmark")

    trust = "--experimental-trusted-input"
    try:
        for number in range(1, args.runs + 1):
            project = output / f"project-{number:02}"
            invoke("inspect", "inspect", binary)
            invoke("project_create", "project", "create", project)
            imported = invoke("import", "import", binary, "--project", project, trust)
            worker_time("import", project, imported["data"][0]["job_id"])
            analyzed = invoke("analyze", "analyze", "--project", project, trust, expected=(0, 6))
            worker_time("analyze", project, analyzed["data"]["job_id"])
            workspace = Project(project)
            snapshot, record = workspace.snapshot(workspace.select())
            require_complete_function_inventory(dict(snapshot["engine"], functions=snapshot["functions"]))
            selector = ("--project", project, "--name", "_calc_add")
            cached = invoke("decompile_cached", "decompile", *selector)
            fresh = invoke("decompile_fresh", "decompile", *selector, "--fresh", trust)
            worker_time("decompile_fresh", project, fresh["data"]["origin"]["job_id"])
            if (not cached["data"]["pseudocode"]
                    or fresh["data"]["pseudocode"] != cached["data"]["pseudocode"]
                    or fresh["analysis_id"] != snapshot["analysis_id"]
                    or workspace.snapshot(workspace.select()) != (snapshot, record)):
                raise RuntimeError("Fresh/cached evidence or committed snapshot differs")
            print(f"Benchmark round {number}/{args.runs} complete", flush=True)
        report.update(status="passed", rounds=args.runs, summary=summarize(samples))
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        with (output / "report.json").open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-build-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runs", type=int, choices=range(1, 21), default=20, metavar="1..20")
    parser.add_argument("--experimental-trusted-input", action="store_true")
    args = parser.parse_args()
    if not args.experimental_trusted_input:
        parser.error("Explicit --experimental-trusted-input is required")
    report = benchmark(args)
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
