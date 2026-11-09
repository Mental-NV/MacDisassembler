#!/usr/bin/env python3
"""Test automatic x86_64 dispatch return recovery on frozen owned Ghidra Programs."""
import argparse
from collections import Counter
from itertools import product
import json
from pathlib import Path
import re
import shutil
import subprocess
from types import SimpleNamespace

from audit_core_behavior import complete, core_extents, recovered_name
from compare_aggregates import COMPAT, HARNESS, SOURCE_FILES, compare
from compare_heldout_aggregates import FROZEN, build, capture, evaluate, fixture_contract
from compare_heldout_switch import PROFILES, truth_for
from dispatch_return_evidence import instructions_for, requests
from prototype_experiment import ROOT, fixture_input
from recovered_compare import matrix_exports
from reference_coverage import xcrun
from score_discovery import verified_captures
from validate_decompiler_evidence import read_bytes, read_json, require_complete_function_inventory, sha, write_new_json
from macscope import engine
from macscope.storage import Project


POLICY = "macscope-dispatch-return-recovery/1"
SCRIPT = ROOT / "analysis/scripts/RecoverDispatchReturn.java"
CALCULATOR = "calc_dispatch_table"
HELDOUT = "heldout_dispatch"
FIXTURES = {"abi-fixture": "heldout_dispatch_abi.c", "no-observer-control": "heldout_dispatch.c"}
VARIANT = "x86_64-O2"
STATES = ("sym", "stripped")
MACHINE_FIELDS = ("name", "namespace", "body_ranges", "instructions", "blocks", "calling_convention",
                  "xrefs_from_sample", "xrefs_to_entry", "is_external", "is_thunk")


def indexed(functions):
    records = {row.get("engine_entry") or row["entry_va"]: row for row in functions}
    if len(records) != len(functions):
        raise ValueError("Duplicate function entry")
    return records


def calculator_inputs(build_root, matrix):
    for state in STATES:
        for case, prior, exports in matrix_exports(matrix, symbols=state):
            path, binary, _ = fixture_input(build_root, case, symbols=state)
            digest = sha(binary)
            if digest != prior["input_sha256"]:
                raise ValueError("Matrix input differs from the owned fixture")
            for profile, export in zip(PROFILES, exports):
                aid = prior["baseline_analysis_id" if profile == "baseline" else "inference_analysis_id"]
                yield case, state, profile, path, binary, export, aid, matrix / f"{case}-{state}-tool"


def capture_fixture(output, source, deps, compiler, sdk):
    files = {}
    rev = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "HEAD"], text=True).strip()
    names = (source, *fixture_contract(source), *FROZEN, Path(__file__).name,
             "dispatch_return_evidence.py", "dispatch_linkage.py", "audit_core_behavior.py",
             "scripts/" + SCRIPT.name)
    for name in names:
        data = read_bytes(ROOT / "analysis" / name)
        if data != subprocess.check_output(["git", "-C", ROOT, "show", f"{rev}:analysis/{name}"]):
            raise ValueError("Owned fixture and evaluator must match a committed revision: " + name)
        files[name] = data
    output.mkdir()
    evaluator, inputs = output / "evaluator", output / "inputs"
    evaluator.mkdir()
    inputs.mkdir()
    builds = (("x86_64", "O2"),)
    digests = build(evaluator, inputs, files, source, compiler, sdk, builds=builds)
    write_new_json(output / "frozen-plan.json", {
        "revision": rev, "inputs": digests, "source": source,
        "files_sha256": {name: sha(data) for name, data in files.items()},
    })
    captures = capture(output, evaluator, inputs, deps["ghidra_path"], deps["java_home"], builds=builds)
    write_new_json(output / "frozen-captures.json", captures)
    if {(row["symbols"], row["profile"]) for row in captures} != set(product(STATES, PROFILES)):
        raise ValueError("Incomplete independent fixture capture")
    return files, digests, captures


def fixture_inputs(output, digests, captures):
    for row in captures:
        state, profile = row["symbols"], row["profile"]
        path = output / "inputs" / VARIANT / state
        binary, export = read_bytes(path), output / row["file"]
        raw = read_bytes(export)
        if sha(binary) != digests[VARIANT][state] or sha(raw) != row["sha256"]:
            raise ValueError("Independent capture differs from its frozen identity")
        yield VARIANT, state, profile, path, binary, export, json.loads(raw)["data"]["analysis_id"], (
            output / "projects" / f"{VARIANT}-{state}")


def verify_recovery(snapshot, raw, evidence, plan):
    require_complete_function_inventory(raw)
    if (raw["executable_sha256"] != plan["image_sha256"] or
            raw["analysis_profile"]["name"] != snapshot["engine"]["analysis_profile"]["name"] or
            raw["validation"]["headless_analysis_enabled"] is not False or evidence["policy"] != POLICY):
        raise ValueError("Recovery used a different input, profile or analysis mode")
    before, after = indexed(snapshot["functions"]), indexed(raw["functions"])
    if before.keys() != after.keys():
        raise ValueError("Recovery changed the frozen function entries")
    approved = {row["entry_va"]: row for row in plan["requests"]}
    decisions = indexed(evidence["results"])
    if decisions.keys() != approved.keys():
        raise ValueError("Incomplete recovery decisions")
    applied = set()
    for entry, row in decisions.items():
        if row["call_va"] != approved[entry]["call_va"]:
            raise ValueError("Recovery changed the verified call site")
        if row["status"] == "applied":
            if row["target_vas"] != approved[entry]["target_vas"] or not complete(after[entry]):
                raise ValueError("Recovery differs from the verified table or produced partial pseudocode")
            applied.add(entry)
        elif row["status"] != "skipped":
            raise ValueError("Unknown recovery decision")
    refinements, changed_c = [], []
    expected_c_changes = applied | {approved[entry]["observer"]["entry_va"] for entry in applied}
    for entry in before:
        old, new = before[entry], after[entry]
        for field in MACHINE_FIELDS:
            if comparable(old[field], field) == comparable(new[field], field):
                continue
            if (field != "blocks" or entry not in applied or
                    not preserves_cfg(old, new, approved[entry]["call_va"])):
                raise ValueError(f"Recovery changed {field} at {entry}")
            refinements.append({"entry_va": entry, "split_va": approved[entry]["call_va"]})
        if (old["signature"] != new["signature"]) != (entry in applied):
            raise ValueError("Recovery changed an unexpected signature at " + entry)
        if old["pseudocode"] != new["pseudocode"]:
            if entry not in expected_c_changes:
                raise ValueError("Recovery changed unexpected pseudocode at " + entry)
            changed_c.append(entry)
    return applied, refinements, changed_c


def comparable(value, field):
    if field == "instructions":
        return [{key: item for key, item in row.items() if key != "location"} for row in value]
    if field in ("xrefs_from_sample", "xrefs_to_entry"):
        return sorted(value, key=lambda row: json.dumps(row, sort_keys=True))
    return value


def preserves_cfg(old, new, call):
    """Accept only the override symbol's fall-through split at the computed call."""
    blocks = new["blocks"]
    index = next((i for i, block in enumerate(blocks) if block["min"] == call), 0)
    if not index or len(blocks) != len(old["blocks"]) + 1:
        return False
    left, right = blocks[index - 1:index + 1]
    predecessors = [ins["addr"] for ins in new["instructions"] if ins["fallthrough"] == call]
    if (len(predecessors) != 1 or int(left["max"], 16) + 1 != int(call, 16) or left["edges_truncated"]
            or left["flow"] != "FALL_THROUGH" or left["dsts"] != [
                {"flow": "FALL_THROUGH", "from": predecessors[0], "to": call}]):
        return False
    merged = dict(right, min=left["min"])
    return [*blocks[:index - 1], merged, *blocks[index + 1:]] == old["blocks"]


def query(directory, project, image, saved, snapshot, plan, deps, excluded):
    source = project.path / "jobs" / saved["job_id"] / "program"
    original = engine.tree_digest(source)
    if original != saved["analysis_program_sha256"] or source.is_symlink() or any(
            path.is_symlink() for path in source.rglob("*")):
        raise ValueError("Saved Ghidra Program differs from the frozen capture")
    directory.mkdir(mode=0o700)
    for name in ("home", "tmp", "scripts"):
        (directory / name).mkdir()
    shutil.copytree(source, directory / "program")
    if engine.tree_digest(directory / "program") != original:
        raise ValueError("Copied Ghidra Program differs from the frozen capture")
    for script in (SCRIPT, ROOT / "src/macscope/bridge/MacscopeBridge.java"):
        shutil.copyfile(script, directory / "scripts" / script.name)
    request_path, decision_path, result_path = (
        directory / name for name in ("request.json", "decisions.json", "result.json"))
    write_new_json(request_path, plan)
    sandbox = directory / "sandbox.sb"
    private = "".join("(deny file-read-data (subpath " + json.dumps(str(path)) + "))\n"
                      for path in sorted({*excluded, project.path, ROOT}))
    sandbox.write_text(engine.profile(SimpleNamespace(path=directory), deps) + private)
    argv = ["/usr/bin/sandbox-exec", "-f", str(sandbox),
            str(Path(deps["ghidra_path"]) / "support/analyzeHeadless"), str(directory / "program"), "image",
            "-process", image["image_id"] + ".macho", "-noanalysis", "-readOnly",
            "-scriptPath", str(directory / "scripts"), "-preScript", SCRIPT.name,
            str(request_path), str(decision_path), "-postScript", "MacscopeBridge.java", str(result_path),
            "query", "5000", "30", "-max-cpu", "1", "-analysisTimeoutPerFile", "100",
            "-log", str(directory / "engine.log"), "-scriptlog", str(directory / "script.log")]
    home, temp = directory / "home", directory / "tmp"
    properties = {"user.home": home, "java.io.tmpdir": temp,
                  "application.settingsdir": home / "settings", "application.cachedir": home / "cache"}
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "TMPDIR": str(temp) + "/",
           "JAVA_HOME": deps["java_home"], "GHIDRA_HEADLESS_MAXMEM": "1024M", "LANG": "en_US.UTF-8",
           "JAVA_TOOL_OPTIONS": " ".join(f"-D{key}={json.dumps(str(path))}" for key, path in properties.items())}
    engine.run_process(argv, cwd=directory, env=env, timeout=120, log_path=directory / "launcher.log",
                       manifest_path=directory / "job.json", manifest={"mode": "dispatch_return_recovery"})
    raw, evidence = read_json(result_path), read_json(decision_path)
    applied, refinements, changed_c = verify_recovery(snapshot, raw, evidence, plan)
    if engine.tree_digest(source) != original:
        raise ValueError("Original saved Program changed")
    return {
        "status": "applied" if applied else "skipped",
        "applied_entries": sorted(applied), "decisions": evidence["results"],
        "cfg_refinements": refinements, "changed_pseudocode_entries": changed_c,
        "saved_program_sha256": original, "request_sha256": sha(read_bytes(request_path)),
        "result_sha256": sha(read_bytes(result_path)), "decisions_sha256": sha(read_bytes(decision_path)),
    }


def discover(output, inputs, deps, decoder, excluded):
    results = []
    for case, state, profile, path, binary, export, aid, project_path in inputs:
        project = Project(project_path)
        image = dict(project.select(), active_analysis=aid)
        snapshot, saved = project.snapshot(image)
        raw = read_bytes(export)
        exported = json.loads(raw)["data"]
        if (snapshot["functions"] != exported["functions"] or snapshot["identity"] != exported["identity"]
                or exported["analysis_id"] != aid or snapshot["image"]["sha256"] != sha(binary)
                or snapshot["identity"]["profile"] != profile + "/1"
                or snapshot["identity"]["engine"]["ghidra_tree_sha256"] != deps["ghidra_tree_sha256"]
                or not re.fullmatch(r"[0-9a-f]{32}", saved["job_id"])):
            raise ValueError("Export differs from its captured input, profile or saved Program")
        recovered, skipped = requests(path, binary, decoder, snapshot)
        label = f"{case}-{state}-{profile}"
        row = {"case": case, "symbols": state, "profile": profile, "label": label,
               "status": "no_request", "skipped": skipped, "requests": recovered,
               "analysis_id": aid, "export_sha256": sha(raw), "input_sha256": sha(binary)}
        if recovered:
            plan = {"policy": POLICY, "image_sha256": sha(binary), "requests": recovered}
            row.update(query(output / label, project, image, saved, snapshot, plan, deps, excluded))
        results.append(row)
        print(f"{label} {row['status']}", flush=True)
    return results


def read_recovered(output, row, entry):
    raw = read_bytes(output / row["label"] / "result.json")
    if sha(raw) != row["result_sha256"] or row["applied_entries"] != [entry]:
        raise ValueError("Recovered result differs from the frozen evidence or evaluator entry")
    return indexed(json.loads(raw)["functions"])


def evaluate_calculator(output, rows, build_root, matrix, compiler, sdk, decoder):
    references = {name: read_bytes(ROOT / name) for name in SOURCE_FILES}
    source_digests = {name: sha(contents) for name, contents in references.items()}
    references[COMPAT.name] = read_bytes(COMPAT)
    harness = read_bytes(HARNESS)
    applied = {(row["case"], row["symbols"], row["profile"] + "/1"): row for row in rows
               if row["status"] == "applied"}
    for prov, snapshot, truth, _, manifest in verified_captures(build_root, matrix):
        case, state, profile = (prov[key] for key in ("case", "symbols", "profile"))
        row = applied.pop((case, state, profile), None)
        if row is None:
            continue
        if (prov["export_sha256"] != row["export_sha256"] or
                any(manifest["source"]["source_files_sha256"].get(name) != digest
                    for name, digest in source_digests.items())):
            raise ValueError("Calculator scoring input differs from the frozen fixture")
        extents = core_extents(truth)
        entry = hex(extents[CALCULATOR][0])
        recovered = read_recovered(output, row, entry)
        definitions = {}
        for routine, (va, _) in extents.items():
            record = recovered.get(hex(va))
            if complete(record):
                definitions[hex(va)] = recovered_name(record, routine)
        record = recovered[entry]
        path, binary, _ = fixture_input(build_root, case, symbols=state)
        instructions = instructions_for(path, binary, decoder, record, max_bytes=1024)
        source = {name: recovered[va]["pseudocode"] for va, name in definitions.items()}
        row["behavior"] = compare(output / row["label"] / "behavior", CALCULATOR, 9, 3, 4800,
                                  record["name"], source, compiler, sdk, harness, references,
                                  dispatch=(record, definitions, row["requests"][0]["table"], instructions))
    if applied:
        raise ValueError("Incomplete calculator scoring cohort")


def evaluate_fixture(output, rows, fixture, files, source, compiler, sdk, decoder):
    addresses, digests = truth_for(fixture / "evaluator", fixture / "inputs", VARIANT, (HELDOUT,))
    entry = addresses[HELDOUT]
    for row in rows:
        if row["input_sha256"] != digests[row["symbols"]]:
            raise ValueError("Independent scoring input differs from the frozen fixture")
        if row["status"] != "applied":
            continue
        recovered = read_recovered(output, row, entry)
        record, request = recovered[entry], row["requests"][0]
        definition_entries = (entry, *request["target_vas"])
        definitions = {va: recovered[va]["name"] for va in definition_entries}
        source_text = {name: recovered[va]["pseudocode"] for va, name in definitions.items()}
        path = fixture / "inputs" / VARIANT / row["symbols"]
        binary = read_bytes(path)
        instructions = instructions_for(path, binary, decoder, record, max_bytes=1024)
        row["behavior"] = evaluate(output / row["label"] / "behavior", HELDOUT, record, source_text,
                                   compiler, sdk, files, source, dispatch=(definitions, request["table"], instructions))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("output-dir", "ghidra", "java-home"):
        parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--fixture", choices=("calculator", *FIXTURES), required=True)
    parser.add_argument("--fixture-build-root", type=Path)
    parser.add_argument("--profile-matrix", type=Path)
    parser.add_argument("--experimental-trusted-input", action="store_true")
    args = parser.parse_args()
    output, scratch = args.output_dir.resolve(), Path("/tmp").resolve()
    if (not args.experimental_trusted_input or output == scratch or not output.is_relative_to(scratch)
            or output.is_relative_to(ROOT)):
        parser.error("Choose a new /tmp output directory and opt in to the owned-input experiment")
    calculator = args.fixture == "calculator"
    if (calculator and not (args.fixture_build_root and args.profile_matrix)
            or not calculator and (args.fixture_build_root or args.profile_matrix)):
        parser.error("Calculator validation requires both the owned build and its saved matrix")
    deps = engine.dependencies(args.ghidra, args.java_home, full=True)
    compiler, decoder = xcrun("--find", "clang"), xcrun("--find", "llvm-objdump")
    sdk = xcrun("--sdk", "macosx", "--show-sdk-path")
    output.mkdir(mode=0o700)
    if calculator:
        build_root, matrix = args.fixture_build_root.resolve(), args.profile_matrix.resolve()
        inputs = calculator_inputs(build_root, matrix)
        excluded = (build_root, matrix)
    else:
        source, fixture = FIXTURES[args.fixture], output / "fixture"
        files, digests, captures = capture_fixture(fixture, source, deps, compiler, sdk)
        inputs = fixture_inputs(fixture, digests, captures)
        excluded = (fixture,)
    rows = discover(output, inputs, deps, decoder, excluded)
    write_new_json(output / "frozen-recovery.json", rows)
    if calculator:
        evaluate_calculator(output, rows, build_root, matrix, compiler, sdk, decoder)
    else:
        evaluate_fixture(output, rows, fixture, files, source, compiler, sdk, decoder)
    counts = dict(Counter(row.get("behavior", row)["status"] for row in rows))
    expected = ({"passed": 4, "no_request": 12} if calculator else {"passed": 4}
                if args.fixture == "abi-fixture" else {"no_request": 4})
    status = "passed" if counts == expected else "partial"
    report = {"policy": POLICY, "fixture": args.fixture, "status": status, "counts": counts, "captures": rows,
              "decoder_sha256": engine.digest(Path(decoder)), "engine_sha256": deps["ghidra_tree_sha256"],
              "script_sha256": sha(read_bytes(SCRIPT)),
              "frozen_recovery_sha256": sha(read_bytes(output / "frozen-recovery.json"))}
    write_new_json(output / "report.json", report)
    print(json.dumps({"status": status, "counts": counts}))
    return 0 if status == "passed" else 6


if __name__ == "__main__":
    raise SystemExit(main())
