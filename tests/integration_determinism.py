#!/usr/bin/env python3
"""Complete three real analysis runs per owned case/profile using verified prior runs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from macscope import engine, jobs
from macscope.cli import parser as cli_parser
from macscope.schema import validate_envelope
from macscope.storage import Project


ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("baseline", "parameter-inference")
REPEATS = 3


def sha(data):
    return hashlib.sha256(data).hexdigest()


def expected_limits(project):
    args = cli_parser().parse_args(["analyze", "--project", str(project)])
    return engine.worker_limits(args, args.max_functions)


def verify_job(project, response, dependencies, profile):
    job_id = response["data"]["job_id"]
    path, record = jobs.get(project, job_id)
    if (jobs.leased(path) or record["status"] != "complete" or record["mode"] != "analyze"
            or record["dependencies"] != dependencies or record["analysis_profile"] != engine.analysis_profile(profile)
            or record["limits"] != expected_limits(project.path) or record["image_id"] != project.select()["image_id"]
            or not (path.parent / "program" / "image.gpr").is_file()):
        raise ValueError("Analysis job did not use the pinned inputs and policy")
    return job_id


def previous_runs(matrix, build, dependencies):
    report_bytes = (matrix / "report.json").read_bytes()
    report = json.loads(report_bytes)
    manifest_bytes = (build / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    if (report["status"] != "passed" or report["fixture_manifest_sha256"] != sha(manifest_bytes)
            or manifest["schema"] != "macscope-phase1-manifest/2"):
        raise ValueError("Requires a completed profile matrix for the exact owned manifest")
    case_inputs = {}
    for row in manifest["artifacts"]:
        if row["container"] == "thin" and row["name"] in ("CalculatorFixture", "CorpusFixture"):
            kind = "tool" if row["name"] == "CorpusFixture" else "app"
            label = f"{row['config']}-{row['arch']}-{row['symbols']}-{kind}"
            if label in case_inputs:
                raise ValueError("Duplicate fixture case")
            case_inputs[label] = row["sha256"]
    if len(case_inputs) != 16 or case_inputs != {r["case"]: r["input_sha256"] for r in report["cases"]}:
        raise ValueError("Requires all 16 owned profile cases")
    projects = {label: Project(matrix / label) for label in case_inputs}
    pending = {}
    cases = {label: {profile: [] for profile in PROFILES} for label in case_inputs}
    for index, command in enumerate(report["commands"], 1):
        argv = command["argv"]
        if argv[0] not in ("analyze", "export"):
            continue
        path = Path(argv[argv.index("--project") + 1]).resolve()
        label = path.name
        if label not in projects or path != projects[label].path or command["exit"] not in (0, 6):
            raise ValueError("Profile command differs from the verified matrix")
        raw = (matrix / f"{index:03}.stdout").read_bytes()
        response = json.loads(raw)
        validate_envelope(response)
        if argv[0] == "analyze":
            profile = argv[argv.index("--profile") + 1] if "--profile" in argv else "baseline"
            if label in pending:
                raise ValueError("Missing export following the previous analysis")
            job_id = verify_job(projects[label], response, dependencies, profile)
            pending[label] = profile, response["analysis_id"], job_id
            continue
        profile, analysis_id, job_id = pending.pop(label)
        snapshot = response["data"]
        if (response["analysis_id"] != analysis_id or snapshot["analysis_id"] != analysis_id
                or snapshot["image"]["sha256"] != case_inputs[label]
                or snapshot["identity"]["profile"] != engine.analysis_profile(profile)["identity"]):
            raise ValueError("Profile export differs from the matching recorded analysis")
        cases[label][profile].append({"job_id": job_id, "analysis_id": analysis_id, "export_sha256": sha(raw)})
    if pending:
        raise ValueError("Some prior analysis commands have no verified export")
    return projects, case_inputs, cases, sha(report_bytes)


def run(args):
    build = args.fixture_build_root.resolve()
    matrix = args.profile_matrix.resolve()
    output = args.output_dir.resolve()
    scratch = Path("/tmp").resolve()
    if output == scratch or not output.is_relative_to(scratch):
        raise ValueError("Choose a new output directory under canonical /tmp")
    deps = engine.dependencies(args.ghidra, args.java_home, full=True)
    projects, inputs, cases, matrix_sha = previous_runs(matrix, build, deps)
    output.mkdir(mode=0o700)
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
    report = {"status": "failed", "schema": "macscope-profile-determinism/1", "cases": cases,
              "source_matrix_sha256": matrix_sha, "repeat_count": REPEATS,
              "prior_workers": 0, "new_workers": 0}

    def cli(project, *argv):
        result = subprocess.run([sys.executable, "-m", "macscope", *argv, "--project", str(project.path), "--json"],
                                cwd=ROOT, env=env, capture_output=True, timeout=420)
        if result.returncode not in (0, 6):
            raise RuntimeError(f"CLI {argv[0]} returned {result.returncode}: "
                               + result.stderr.decode(errors="replace"))
        response = json.loads(result.stdout)
        validate_envelope(response)
        return response, sha(result.stdout)

    try:
        for label, prior in projects.items():
            destination = output / label
            shutil.copytree(prior.path, destination)
            project = Project(destination)
            image = project.select()
            baseline = project.path / "engine" / image["image_id"]
            if (image["sha256"] != inputs[label] or engine.tree_digest(baseline) != image["engine_baseline_sha256"]):
                raise ValueError("Pristine Program or its selected input identity changed")
            for profile, runs in cases[label].items():
                if (not runs or len({row["job_id"] for row in runs}) != len(runs)
                        or len({(row["analysis_id"], row["export_sha256"]) for row in runs}) != 1):
                    raise ValueError("Missing, duplicate or disagreeing prior export")
                report["prior_workers"] += len(runs)
                while len(runs) < REPEATS:
                    analysis, _ = cli(project, "analyze", "--profile", profile,
                                      "--ghidra", deps["ghidra_path"], "--java-home", deps["java_home"],
                                      "--experimental-trusted-input")
                    job_id = verify_job(project, analysis, deps, profile)
                    snapshot, export_sha = cli(project, "export")
                    row = {"job_id": job_id, "analysis_id": snapshot["analysis_id"], "export_sha256": export_sha}
                    report["new_workers"] += 1
                    runs.append(row)
                    if (analysis["analysis_id"] != row["analysis_id"]
                            or row["analysis_id"] != runs[0]["analysis_id"]
                            or export_sha != runs[0]["export_sha256"]
                            or job_id in {earlier["job_id"] for earlier in runs[:-1]}):
                        raise ValueError("Repeated full headless analysis produced a different export")
            if engine.tree_digest(baseline) != image["engine_baseline_sha256"]:
                raise ValueError("Repeated analyses changed the pristine Program")
            print(label + " matched", flush=True)
        report["status"] = "passed"
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-build-root", type=Path, required=True)
    parser.add_argument("--profile-matrix", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--ghidra")
    parser.add_argument("--java-home")
    parser.add_argument("--experimental-trusted-input", action="store_true")
    args = parser.parse_args()
    if not args.experimental_trusted_input:
        parser.error("Explicit --experimental-trusted-input is required")
    report = run(args)
    print(json.dumps({key: report[key] for key in ("status", "prior_workers", "new_workers")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
