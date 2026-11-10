#!/usr/bin/env python3
"""Verify one-shot focused capture binding on the owned calculator fixtures."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import hmac
import os
from pathlib import Path
import secrets
from threading import Barrier, Lock
import time
from unittest.mock import patch

from evaluate import nm_map
from prototype_experiment import fixture_input
from validate_decompiler_evidence import read_json, write_new_json
from verify_job_isolation import call, checked, run_scoped, runtime_files, status_error
from macscope import cli, engine, focused, import_state, macho, metadata
from macscope.errors import Error
from macscope.storage import Project, canonical, strict_json


POLICY = "macscope-simulated-owned-focused-approval/1"
LIFETIME_NS = 300 * 10**9
BUDGET = ("--timeout", "90", "--startup-timeout", "35", "--function-timeout", "15",
          "--heap-mib", "1024", "--max-functions", "1")


class TestIssuer:
    """In-process authority for the explicitly opted-in owned fixture run."""

    def __init__(self):
        self._key = secrets.token_bytes(32)
        self._consumed = set()
        self._lock = Lock()

    def issue(self, scope, *, lifetime_ns=LIFETIME_NS):
        body = canonical({"policy": POLICY, "id": secrets.token_hex(16),
                          "expires_ns": time.monotonic_ns() + lifetime_ns, "scope": scope})
        return body, hmac.digest(self._key, body, "sha256")

    def consume(self, grant, expected):
        body, signature = grant
        if len(body) > 65536 or not hmac.compare_digest(signature, hmac.digest(self._key, body, "sha256")):
            raise Error("owned_grant_authentication", "The owned test supervisor did not issue this grant", 3)
        record = strict_json(body)
        if record["policy"] != POLICY or canonical(record["scope"]) != canonical(expected):
            raise Error("owned_grant_scope", "The exact capture request differs from the grant", 3)
        with self._lock:
            if record["expires_ns"] <= time.monotonic_ns():
                raise Error("owned_grant_expired", "The grant has expired", 3)
            if record["id"] in self._consumed:
                raise Error("owned_grant_reused", "The grant was already consumed", 3)
            self._consumed.add(record["id"])
        return hashlib.sha256(body).hexdigest()


def scope_for(project, binary, arch, entry, runtime):
    binary = macho.checked_path(binary)
    original = macho.read_regular(binary)
    artifact = macho.inspect_bytes(original, for_engine=True)
    images = [image for image in artifact["slices"] if image["arch"] == arch]
    if len(images) != 1:
        raise Error("owned_grant_scope", "The requested architecture is absent or ambiguous", 3)
    image, = images
    start, length = int(image["offset"], 16), int(image["size"], 16)
    extent, _ = focused.extent(original[start:start + length], image, entry)
    args = cli.parser().parse_args(["analyze", "--project", str(project.path), *BUDGET])
    return {"project": str(project.path), "project_id": project.project_id, "input": str(binary),
            "artifact_sha256": artifact["artifact_sha256"], "slice_sha256": image["sha256"],
            "image_id": image["image_id"], "arch": arch, "extent": extent,
            "runtime": runtime, "limits": engine.worker_limits(args, 1)}


def live_capture(issuer, grant, project, binary, arch, entry, runtime):
    scope = scope_for(project, binary, arch, entry, runtime)
    grant_sha = issuer.consume(grant, scope)
    checked(not project.images() and not list((project.path / "jobs").iterdir()),
            "One-shot capture requires a fresh project")
    deps, libraries = runtime["dependencies"], runtime["libraries"]
    staged = project.path / "inputs" / (scope["image_id"] + ".macho")
    options = ("--project", project.path, "--experimental-trusted-input", *BUDGET)
    worker = engine.run
    starts = []
    baseline_digest = None

    def guarded(workspace, image, mode, args, actual, **kwargs):
        expected_mode = {0: "import", 1: "query"}.get(len(starts))
        if (workspace.path != project.path or workspace.project_id != project.project_id
                or mode != expected_mode or actual != deps
                or engine.worker_limits(args, args.max_functions) != scope["limits"]
                or image["image_id"] != scope["image_id"] or image["arch"] != scope["arch"]
                or image["artifact_sha256"] != scope["artifact_sha256"] or image["sha256"] != scope["slice_sha256"]
                or runtime_files() != libraries
                or engine.tree_digest(Path(actual["java_home"])) != runtime["jdk_tree_sha256"]):
            raise Error("owned_grant_scope", "Worker request differs from the consumed grant", 3)
        raw = metadata.verified_slice(workspace, image)
        selected, _ = focused.extent(raw, image, scope["extent"]["entry_va"])
        if selected != scope["extent"]:
            raise Error("owned_grant_scope", "The immutable staged extent differs from the grant", 3)
        if mode == "import":
            expected = {"import_request": import_state.request_for(workspace, image), "resumed_from": None}
        else:
            expected = {"entry": selected["entry_va"], "from_import": True, "resumed_from": None}
            if engine.tree_digest(engine.imported_program(workspace, image)) != baseline_digest:
                raise Error("owned_grant_scope", "The saved Program differs from the verified import", 3)
        if kwargs != expected:
            raise Error("owned_grant_scope", "Worker options differ from the consumed grant", 3)
        starts.append(mode)
        return worker(workspace, image, mode, args, actual, **kwargs)

    with patch.object(engine, "run", guarded):
        imported = run_scoped(project.path, deps, libraries,
                              ("import", binary, "--arch", arch, *options), staged=staged)
        saved = project.select()
        baseline = engine.imported_program(project, saved)
        baseline_digest = engine.tree_digest(baseline)
        databases = tuple(sorted(path.relative_to(baseline)
                                 for path in (baseline / "image.rep/idata").rglob("*.gbf")))
        checked(databases, "Owned import has no Program database")
        fresh = run_scoped(project.path, deps, libraries,
                           ("decompile", "--from-import", "--address", entry, *options),
                           protected=databases)
    import_id = imported["data"][0]["job_id"]
    query_id = fresh["data"]["origin"]["job_id"]
    query = project.path / "jobs" / query_id
    proof = dict(scope["extent"], program_sha256=baseline_digest)
    manifest = read_json(query / "job.json")
    checked(starts == ["import", "query"] and fresh["data"]["pseudocode"]
            and fresh["data"]["decompile_status"] == "complete"
            and manifest["focused_import"] == proof and "-readOnly" in manifest["argv"]
            and engine.tree_digest(baseline) == baseline_digest, "Focused receipt differs from the owned grant")
    return {"grant_sha256": grant_sha, "scope": scope, "program_sha256": baseline_digest,
            "import_job_id": import_id, "query_job_id": query_id, "response_status": fresh["status"],
            "receipt_sha256": engine.digest(query / "query-result.json")}, fresh


def check_rejections(issuer, scope, capture, project):
    mutations = (
        ("artifact", ("artifact_sha256",), "a" * 64), ("slice", ("slice_sha256",), "b" * 64),
        ("architecture", ("arch",), "arm64e"), ("entry", ("extent", "entry_va"), "0x10"),
        ("extent", ("extent", "extent_sha256"), "c" * 64), ("end", ("extent", "end_va_exclusive"), "0x20"),
        ("workspace", ("project",), scope["project"] + "-other"), ("project_id", ("project_id",), "d" * 32),
        ("ghidra", ("runtime", "dependencies", "ghidra_tree_sha256"), "e" * 64),
        ("jdk", ("runtime", "jdk_tree_sha256"), "f" * 64),
        ("worker_profile", ("runtime", "isolation_runner_sha256"), "1" * 64),
        ("jdk_library", ("runtime", "libraries", next(iter(scope["runtime"]["libraries"])), "sha256"), "2" * 64),
        ("timeout", ("limits", "timeout_seconds"), 91),
    )
    results = {}
    for label, keys, value in mutations:
        changed = deepcopy(scope)
        target = changed
        for key in keys[:-1]:
            target = target[key]
        target[keys[-1]] = value
        status_error("owned_grant_scope", lambda: capture(issuer.issue(changed)))
        results[label] = "scope_mismatch"

    body, signature = issuer.issue(scope)
    for label, grant in (("edited", (body + b" ", signature)),
                         ("other_issuer", TestIssuer().issue(scope)), ("unsigned", (body, b""))):
        status_error("owned_grant_authentication", lambda: capture(grant))
        results[label] = "authentication_failed"
    status_error("owned_grant_expired", lambda: capture(issuer.issue(scope, lifetime_ns=0)))
    results["expired"] = "expired"
    checked(not project.images() and not any((project.path / "jobs").iterdir())
            and not any((project.path / "inputs").iterdir()), "Rejected grant staged data or launched a worker")
    return results


def check_competing_consumers(issuer, scope):
    grant = issuer.issue(scope)
    ready = Barrier(8)

    def consume(_):
        ready.wait(timeout=10)
        try:
            issuer.consume(grant, scope)
        except Error as error:
            checked(error.code == "owned_grant_reused", "Unexpected concurrent claim failure")
            return "reused"
        return "consumed"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(consume, range(8)))
    checked(outcomes.count("consumed") == 1 and outcomes.count("reused") == 7,
            "Concurrent claim allowed multiple consumers")
    return {"consumed": 1, "reused": 7}


def run(build, output):
    deps = engine.dependencies(full=True)
    java = Path(deps["java_home"])
    runtime = {"dependencies": deps, "libraries": runtime_files(), "jdk_tree_sha256": engine.tree_digest(java),
               "isolation_runner_sha256": engine.digest(Path(__file__).with_name("verify_job_isolation.py"))}
    issuer = TestIssuer()
    positive, negative = [], []
    for arch in ("arm64", "x86_64"):
        binary, owned_bytes, _ = fixture_input(build, "DebugAnalysis-" + arch)
        symbols = nm_map(binary)
        entry = symbols["calc_add"]
        workspace = output / arch
        call("project", "create", workspace)
        project = Project(workspace)
        scope = scope_for(project, binary, arch, entry, runtime)
        checked(scope["artifact_sha256"] == hashlib.sha256(owned_bytes).hexdigest(),
                "The requested artifact differs from the owned build manifest")

        def capture(grant):
            return live_capture(issuer, grant, project, binary, arch, entry, runtime)

        grant = issuer.issue(scope)
        status_error("owned_grant_scope", lambda: live_capture(
            issuer, grant, project, binary, arch, symbols["calc_div"], runtime))
        rejected = check_rejections(issuer, scope, capture, project)
        rejected["different_requested_function"] = "scope_mismatch"
        competition = check_competing_consumers(issuer, scope)
        success, fresh = capture(grant)
        before = set((workspace / "jobs").iterdir())
        status_error("owned_grant_reused", lambda: capture(grant))
        with patch.object(engine, "dependencies", side_effect=ValueError("Unexpected engine probe")), \
             patch.object(engine, "run", side_effect=ValueError("Unexpected worker")):
            replay = call("jobs", "resume", success["query_job_id"], "--project", workspace,
                          "--experimental-trusted-input")
        data = dict(replay["data"])
        checked(data.pop("reused_restart") and data.pop("resumed_from") == success["query_job_id"]
                and data == fresh["data"] and set((workspace / "jobs").iterdir()) == before and len(before) == 2,
                "Replay or rejected reuse changed the verified job set")
        positive.append(dict(success, replayed_without_engine=True))
        negative.append({"arch": arch, "rejections": rejected, "concurrent_claims": competition,
                         "reused_grant_rejected_after_capture": True, "new_jobs_for_rejections": 0})
        print(f"{arch}: simulated grant verified for one import, one focused query and offline replay", flush=True)

    checked(engine.dependencies(full=True) == deps and runtime_files() == runtime["libraries"]
            and engine.tree_digest(java) == runtime["jdk_tree_sha256"], "Pinned runtime changed")
    write_new_json(output / "positive.json", {"policy": POLICY, "captures": positive})
    write_new_json(output / "negative.json", {"policy": POLICY, "cases": negative})
    print(output)


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
    run(args.fixture_build_root, output)


if __name__ == "__main__":
    main()
