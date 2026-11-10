#!/usr/bin/env python3
"""Exercise a narrower worker profile on manifest-verified owned calculator tools."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from unittest.mock import patch

from evaluate import nm_map
from prototype_experiment import ROOT, fixture_input
from validate_decompiler_evidence import read_json, write_new_json
from macscope import cli, engine, focused, macho
from macscope.errors import Error
from macscope.storage import Project


def checked(condition, message):
    if not condition:
        raise ValueError(message)


def runtime_files():
    result = {}
    for name in engine.JDK_BREW_LIBRARIES:
        alias = Path("/opt/homebrew/opt") / name
        actual = alias.resolve(strict=True)
        checked(actual.is_relative_to("/opt/homebrew/Cellar") and actual.is_file(),
                "Unexpected JDK library path")
        result[str(alias)] = {"path": str(actual), "sha256": engine.digest(actual)}
    return result


def restriction(operation, *, paths=(), roots=()):
    filters = [f"(literal {json.dumps(str(path))})" for path in paths]
    filters += [f"(subpath {json.dumps(str(root))})" for root in roots]
    return f"(deny {operation} (require-not (require-any {' '.join(filters)})))\n"


def worker_profile(job, deps, libraries, *, staged=None, protected=()):
    ghidra, java = (Path(deps[key]) for key in ("ghidra_path", "java_home"))
    programs = engine.worker_launch_paths(deps)
    reads = set((*programs, *engine.SYSTEM_FILES))
    for alias, lib in libraries.items():
        real = Path(lib["path"])
        reads.update((alias, str(real), str(real.with_name(Path(alias).name))))
    if staged is not None:
        reads.add(str(staged))
    profile = ("(version 1)\n(allow default)\n(deny network*)\n"
               + restriction("file-read-data", paths=sorted(map(str, reads)),
                             roots=(job, ghidra, java, engine.BRIDGE.resolve(), *engine.SYSTEM_READS))
               + restriction("file-write*", paths=("/dev/null",), roots=(job,))
               + restriction("process-exec", paths=programs))
    if protected:
        # Ghidra checks writable project metadata and directories even with -readOnly.
        files = (job / "program" / path for path in protected)
        rules = " ".join(f"(literal {json.dumps(str(path))})" for path in files)
        profile += f"(deny file-write* {rules})\n"
    return profile


def call(*words):
    return cli.execute(cli.parser().parse_args([*map(str, words), "--json"]))


def run_scoped(project, deps, libraries, words, *, staged=None, protected=()):
    def scoped(workspace, actual, *, write_root, staged_image_id=None, read_only_program=False):
        selected = workspace.path / "inputs" / (staged_image_id + ".macho") if staged_image_id else None
        checked(workspace.path == project and write_root.parent == project / "jobs" and actual == deps,
                "Worker request differs from the owned experiment scope")
        checked(selected == staged, "Staged input differs from the owned experiment scope")
        checked(read_only_program == bool(protected), "Program protection differs from the owned experiment scope")
        return worker_profile(write_root, actual, libraries, staged=staged, protected=protected)

    with patch.object(engine, "profile", scoped):
        return call(*words)


def status_error(code, command):
    try:
        command()
    except Error as error:
        checked(error.code == code, f"Expected {code}, got {error.code}: {error}")
        return error
    raise ValueError(f"Expected {code}, command succeeded")


def probes(output, case, deps, libraries):
    project, import_job, query_job, staged = case
    results = {}

    def probe(label, args, policy=None, *, allowed):
        cmd = list(map(str, args))
        if policy is not None:
            cmd = ["/usr/bin/sandbox-exec", "-f", str(policy), *cmd]
        run = subprocess.run(cmd, capture_output=True, timeout=10, cwd=output)
        if allowed:
            checked(run.returncode == 0, f"{label} could not run: {run.stderr!r}")
        else:
            checked(run.returncode != 0 and
                    any(reason in run.stderr for reason in (b"not permitted", b"Permission denied")),
                    f"{label} did not report an access denial: {run.returncode} {run.stderr!r}")
        results[label] = {"exit": run.returncode, "expected": "allowed" if allowed else "denied"}
        return run.stdout

    original = output / "unrelated.txt"
    original.write_bytes(b"owned unrelated canary")
    read = "/bin/cat"
    importing, querying = import_job / "sandbox.sb", query_job / "sandbox.sb"
    checked(probe("import_exact_staged_read", (read, staged), importing, allowed=True) == staged.read_bytes(),
            "Worker did not read the exact staged slice")
    probe("focused_copy_read", (read, query_job / "program/image.gpr"), querying, allowed=True)
    for label, path in (
        ("focused_staged_read", staged), ("focused_sibling_read", import_job / "launcher.log"),
        ("focused_project_read", project / "index.sqlite"), ("focused_non_home_read", original),
        ("focused_source_read", ROOT / "fixture/src/calc_core.c"),
    ):
        probe(label, (read, path), querying, allowed=False)

    write = ("/bin/bash", "-c", 'printf canary > "$1"', "canary")
    probe("current_job_write", (*write, query_job / "write-control"), querying, allowed=True)
    probe("outside_job_write", (*write, output / "must-not-exist"), querying, allowed=False)
    database = next((query_job / "program/image.rep/idata").rglob("*.gbf"))
    before = engine.digest(database)
    probe("focused_database_write", ("/bin/bash", "-c", ': >> "$1"', "probe", database), querying, allowed=False)
    checked(not (output / "must-not-exist").exists() and engine.digest(database) == before,
            "A denied output changed the test workspace")

    # The script is a permission canary. It is never supplied to Ghidra.
    canary = output / "staged-exec-canary"
    canary.write_text("#!/bin/sh\nexit 0\n")
    canary.chmod(0o500)
    canary_job = output / "canary-job"
    canary_job.mkdir()
    canary_policy = canary_job / "sandbox.sb"
    canary_policy.write_text(worker_profile(canary_job, deps, libraries, staged=canary))
    probe("staged_execution_control", (canary,), allowed=True)
    probe("staged_canary_read", (read, canary), canary_policy, allowed=True)
    probe("staged_canary_execution", ("/bin/bash", "-c", 'exec "$1"', "probe", canary),
          canary_policy, allowed=False)

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        network = ("/bin/bash", "-c", 'exec 3<>"/dev/tcp/127.0.0.1/$1"', "probe", listener.getsockname()[1])
        probe("loopback_control", network, allowed=True)
        probe("worker_loopback", network, querying, allowed=False)
    return results


def capture(build, output, arch, deps, libraries):
    binary, data, _ = fixture_input(build, "DebugAnalysis-" + arch)
    image, = macho.inspect_bytes(data, for_engine=True)["slices"]
    entry = nm_map(binary)["calc_add"]
    project = output / arch
    call("project", "create", project)
    staged = project / "inputs" / (image["image_id"] + ".macho")
    opts = ("--project", project, "--experimental-trusted-input")
    commands = ("--timeout", "90", "--startup-timeout", "35")
    status_error("isolation_required", lambda: call("import", binary, "--project", project))
    checked(not list((project / "jobs").iterdir()), "Untrusted import started a worker")
    imported = run_scoped(project, deps, libraries,
                          ("import", binary, "--arch", arch, *opts, *commands), staged=staged)
    workspace = Project(project)
    saved = workspace.select()
    baseline = engine.imported_program(workspace, saved)
    digest = engine.tree_digest(baseline)
    protected = tuple(sorted(path.relative_to(baseline)
                             for path in (baseline / "image.rep/idata").rglob("*.gbf")))
    checked(protected, "Imported Program has no database file to protect")
    query = ("decompile", "--from-import", "--address", entry, *opts)
    fresh = run_scoped(project, deps, libraries, (*query, *commands), protected=protected)
    checked(fresh["data"]["pseudocode"] and fresh["data"]["decompile_status"] == "complete",
            "Focused decompilation did not complete")

    first = project / "jobs" / imported["data"][0]["job_id"]
    second = project / "jobs" / fresh["data"]["origin"]["job_id"]
    first_job, second_job = (read_json(job / "job.json") for job in (first, second))
    first_raw, second_raw = (read_json(job / "bridge.json") for job in (first, second))
    for path, job, raw in ((first, first_job, first_raw), (second, second_job, second_raw)):
        checked(job["status"] == "complete" and job["startup"]["status"] == "ready"
                and raw["executable_sha256"] == image["sha256"]
                and raw["validation"]["headless_analysis_enabled"] is False
                and engine.digest(path / "sandbox.sb") == job["sandbox_sha256"],
                "Worker result differs from the expected import or query")
    checked("-readOnly" in second_job["argv"] and len(second_raw["functions"]) == 1
            and engine.tree_digest(second / "program", ignore=focused.PROJECT_BACKUPS)
            == engine.tree_digest(baseline, ignore=focused.PROJECT_BACKUPS),
            "Focused copy differs from the saved Program")

    timeout = status_error("worker_timeout", lambda: run_scoped(
        project, deps, libraries, (*query, "--timeout", "1"), protected=protected))
    expired = project / "jobs" / timeout.partial["job_id"]
    timed = read_json(expired / "job.json")
    checked(timed["status"] == "timeout" and not (expired / "query-result.json").exists(),
            "Timed out query published a result")
    deadline = time.monotonic() + 3
    group = str(timed["process_group"])
    while group in subprocess.check_output(["/bin/ps", "-axo", "pgid="], text=True, timeout=5).split():
        checked(time.monotonic() < deadline, "Timed out worker process group still exists")
        time.sleep(0.05)

    before = set((project / "jobs").iterdir())
    with patch.object(engine, "dependencies", side_effect=ValueError("Unexpected engine probe")), \
         patch.object(engine, "run", side_effect=ValueError("Unexpected worker")):
        replay = call("jobs", "resume", second.name, *opts)
    replay_data = dict(replay["data"])
    checked(replay_data.pop("reused_restart") and replay_data.pop("resumed_from") == second.name
            and replay_data == fresh["data"] and set((project / "jobs").iterdir()) == before
            and engine.tree_digest(baseline) == digest,
            "Offline replay differs or modified the saved Program")
    return ({"arch": arch, "slice_sha256": image["sha256"], "entry_va": entry, "program_sha256": digest,
             "import_job": first.name, "focused_job": second.name, "status": fresh["status"],
             "instruction_count": len(fresh["data"]["instructions"]),
             "import_policy_sha256": first_job["sandbox_sha256"], "query_policy_sha256": second_job["sandbox_sha256"],
             "replayed_without_engine": True},
            {"trust_gate_before_launch": True, "timeout_job": expired.name, "timeout_exit": timeout.exit_code,
             "process_group_gone": True}, (project, first, second, staged))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-build-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--experimental-trusted-input", action="store_true")
    args = parser.parse_args()
    if not args.experimental_trusted_input:
        parser.error("Explicit --experimental-trusted-input is required for the owned fixture run")
    output = args.output_dir.resolve()
    if output == Path("/private/tmp") or not output.is_relative_to("/private/tmp"):
        parser.error("Use a new directory under /private/tmp")
    os.umask(0o077)
    output.mkdir(mode=0o700)
    deps = engine.dependencies(full=True)
    libraries = runtime_files()
    java_digest = engine.tree_digest(Path(deps["java_home"]))
    positive, negative = [], {}
    for arch in ("arm64", "x86_64"):
        success, rejection, case = capture(args.fixture_build_root, output, arch, deps, libraries)
        positive.append(success)
        negative[arch] = rejection
        print(f"{arch}: owned import, focused query, timeout and replay verified", flush=True)
    probe_output = output / "probes"
    probe_output.mkdir()
    negative["access_probes"] = probes(probe_output, case, deps, libraries)
    checked(engine.dependencies(full=True) == deps and runtime_files() == libraries
            and engine.tree_digest(Path(deps["java_home"])) == java_digest,
            "Runtime identity changed during the experiment")
    write_new_json(output / "positive.json", {"status": "passed", "engine": deps, "java_tree_sha256": java_digest,
                                            "library_reads": libraries, "system_read_roots": SYSTEM_READS,
                                            "system_read_files": engine.SYSTEM_FILES, "system_executables": engine.SYSTEM_EXEC,
                                            "cases": positive})
    write_new_json(output / "negative.json", negative)
    print(output)


if __name__ == "__main__":
    main()
