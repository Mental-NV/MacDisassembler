#!/usr/bin/env python3
"""Opt-in Apple oracle for production-cap Objective-C discovery.

Run on macOS with PYTHONPATH=src. Builds only project-owned arm64/x86_64
dylibs and never executes them. Project preparation stages metadata directly
(no Ghidra import or analysis); all acceptance queries use the public CLI.
Apple tools are invoked explicitly here, never by the product CLI.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from macscope import dyld, import_state, macho, objc, storage
from macscope.schema import validate_envelope

ROOT = Path(__file__).resolve().parents[1]
NAME = "OwnedDiscoveryProbe"
PREFIX_COUNT = 12032
FIXUP = re.compile(r"^\s*(__\S+)\s+(__\S+)\s+(0x[0-9a-fA-F]+)\s+(rebase|bind)\s+(.+)$")
SYMBOL = re.compile(r"^([0-9a-fA-F]+)\s+\([^)]*\)\s+(?:non-external|external)\s+(.+)$")
METHOD = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s+([+-])\[OwnedDiscoveryProbe (\w+)\]$")
# Loaded by ordinary python -m invocation. All external process creation is
# forbidden inside metadata queries, including Ghidra, Java and Apple tools.
GUARD = """import os
import sys
from pathlib import Path
marker = Path(os.environ["MACSCOPE_QUERY_GUARD_MARKER"])
def guard(event, args):
    if event in {"subprocess.Popen", "os.system", "os.posix_spawn", "os.exec", "os.fork", "os.forkpty"}:
        marker.write_text("blocked:" + event)
        raise RuntimeError("Static metadata query attempted external process: " + event)
sys.addaudithook(guard)
marker.write_text("armed")
"""


def apple(root, label, *args):
    result = subprocess.run(["/usr/bin/xcrun", *map(str, args)],
                            capture_output=True, text=True, timeout=90)
    (root / (label + ".txt")).write_text(result.stdout)
    (root / (label + ".stderr")).write_text(result.stderr)
    if result.returncode:
        raise RuntimeError(f"Apple command failed: {args!r}: {result.stderr}")
    return result.stdout


def invoke(root, guard, label, *args, expected=(0,)):
    env = dict(os.environ)
    marker = root / (label + ".guard")
    env["MACSCOPE_QUERY_GUARD_MARKER"] = str(marker)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = os.pathsep.join([str(guard), str(ROOT / "src"), env.get("PYTHONPATH", "")])
    result = subprocess.run([sys.executable, "-m", "macscope", *map(str, args), "--json"],
                            capture_output=True, text=True, timeout=60, env=env)
    (root / (label + ".json")).write_text(result.stdout)
    (root / (label + ".stderr")).write_text(result.stderr)
    assert result.returncode in expected, (label, result.returncode, result.stdout, result.stderr)
    assert marker.read_text() == "armed", "Query guard missing or an external launch was attempted"
    response = json.loads(result.stdout)
    validate_envelope(response)
    return response


def oracle(root, binary):
    text = apple(root, "apple-fixups", "dyld_info", "-fixups", binary)
    rows = [match.groups() for line in text.splitlines() if (match := FIXUP.match(line))]
    sites = {int(row[2], 16): (index, row) for index, row in enumerate(rows)}
    symbols = {match[2]: int(match[1], 16)
               for line in apple(root, "apple-symbols", "nm", "-nm", binary).splitlines()
               if (match := SYMBOL.match(line))}
    class_va = symbols["_OBJC_CLASS_$_" + NAME]
    ro = symbols["__OBJC_CLASS_RO_$_" + NAME]
    prefix = symbols["_owned_unrelated_fixups"]
    for index in range(PREFIX_COUNT):
        _, row = sites[prefix + index * 8]
        assert row[3] == "rebase" and int(row[4], 16) == prefix, row
    slot, = [int(row[2], 16) for row in rows
             if row[1] == "__objc_classlist" and row[3] == "rebase"
             and int(row[4], 16) == class_va]
    # Check both chain traversal order and addresses, independently of macscope.
    for site in (slot, class_va + 32, ro + 24):
        rank, row = sites[site]
        assert rank >= PREFIX_COUNT > 10000 and prefix + PREFIX_COUNT * 8 <= site, (site, rank)
        assert row[3] == "rebase", row
    assert int(sites[class_va + 32][1][4], 16) & ~7 == ro
    methods_text = apple(root, "apple-objc", "dyld_info", "-objc", binary)
    assert "@interface " + NAME in methods_text
    methods = {(match[2], match[3]): int(match[1], 16)
               for line in methods_text.splitlines() if (match := METHOD.match(line))}
    assert set(methods) == {("-", "ownedProbe"), ("+", "ownedClassProbe")}, methods
    for (kind, name), address in methods.items():
        assert symbols[f"{kind}[{NAME} {name}]"] == address
    return {"class_va": class_va, "metadata_va": ro, "slot": slot,
            "class_slot_rank": sites[slot][0], "name_site_rank": sites[ro + 24][0],
            "methods": methods, "fixup_count": len(rows)}


def prepare_project(path, binary, arch):
    # Explicit metadata-only test preparation. Do not misrepresent this as a
    # complete engine import. The queries below need only verified saved bytes.
    project = storage.Project.create(path)
    raw = binary.read_bytes()
    source = macho.inspect_bytes(raw)
    image, = source["slices"]
    assert image["arch"] == arch
    image = dict(image, artifact_sha256=source["artifact_sha256"], input_name=binary.name)
    import_state.stage_inputs(project, image, raw)
    with project.db(False) as db:
        db.execute("INSERT INTO images(id,arch,metadata,imported) VALUES(?,?,?,1)",
                   (image["image_id"], arch, storage.canonical(image).decode()))
    return project


def run_arch(output, guard, arch):
    root = output / arch
    root.mkdir()
    binary = root / "OwnedDiscovery.dylib"
    apple(root, "build", "clang", "-arch", arch, "-dynamiclib", "-O0",
          "-mmacosx-version-min=13.0", "-Wl,-fixup_chains",
          "-Wl,-rename_section,__DATA_CONST,__objc_classlist,__DATA,__objc_classlist",
          "-lobjc", ROOT / "analysis/owned_discovery_fixture.m", "-o", binary)
    expected = oracle(root, binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    project = prepare_project(root / "project", binary, arch)
    common = ("--project", project.path, "--arch", arch)
    # General enumeration still hits the production cap, while scoped discovery
    # succeeds. No monkeypatching of any production limit is permitted.
    capped = invoke(root, guard, "general-fixups", "fixups", "--input", binary,
                    expected=(0, 6))
    assert capped["status"] == "partial", capped
    assert "fixup_limit" in capped["coverage"]["truncation_reason"], capped
    classes = invoke(root, guard, "classes", "objc", "classes", *common,
                     "--name-contains", NAME)
    assert classes["status"] == classes["coverage"]["status"] == "complete", classes
    assert classes["coverage"]["known_total"] == 1, classes
    row, = classes["data"]
    assert row["name"] == NAME and row["arch"] == arch
    for field, value in (("class_va", expected["class_va"]),
                         ("metadata_va", expected["metadata_va"]),
                         ("list_entry_va", expected["slot"])):
        assert int(row[field], 16) == value, (field, row, expected)
    methods = invoke(root, guard, "methods", "objc", "methods", *common,
                     "--class-slot", row["list_entry_va"])
    assert methods["status"] == methods["coverage"]["status"] == "complete", methods
    actual = {("+" if item["method_kind"] == "class" else "-", item["name"]):
              int(item["implementation_va"], 16) for item in methods["data"]}
    assert actual == expected["methods"], (actual, expected)
    assert all(item["class_name"] == NAME and item["class_slot"] == row["list_entry_va"]
               for item in methods["data"])
    absent = invoke(root, guard, "absent", "objc", "classes", *common,
                    "--name-contains", "OwnedDefinitelyAbsent")
    assert absent["status"] == absent["coverage"]["status"] == "complete", absent
    assert absent["data"] == [] and absent["coverage"]["known_total"] == 0, absent
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest
    assert not any((project.path / "engine").iterdir()), "Unexpected engine artifacts"
    return {"arch": arch, "status": "passed", "sha256": digest,
            "unrelated_fixups": PREFIX_COUNT, "apple_fixup_count": expected["fixup_count"],
            "class_slot": row["list_entry_va"], "class_va": row["class_va"],
            "class_slot_rank_zero_based": expected["class_slot_rank"],
            "name_site_rank_zero_based": expected["name_site_rank"],
            "methods_matched": len(actual), "general_fixups_status": capped["status"],
            "filtered_classes_status": classes["status"], "known_total": 1,
            "complete_absence_checked": True, "external_processes_forbidden_in_queries": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("This explicit Apple-tool integration requires macOS")
    output = args.output_dir.resolve()
    scratch = Path("/tmp").resolve()
    if output == scratch or not output.is_relative_to(scratch):
        parser.error("Choose a new output directory under canonical /tmp")
    output.mkdir(mode=0o700)
    guard = output / "query-guard"
    guard.mkdir()
    (guard / "sitecustomize.py").write_text(GUARD)
    assert dyld.MAX_FIXUPS == 10000
    assert objc.MAX_CLASS_POINTERS == 8192 and objc.MAX_CLASS_CHAIN_NODES == 262144
    report = {"status": "failed", "architectures": [], "application_executed": False,
              "project_preparation": "metadata-only staging; no engine import or analysis",
              "source_sha256": hashlib.sha256((ROOT / "analysis/owned_discovery_fixture.m").read_bytes()).hexdigest(),
              "production_limits": {name: getattr(module, name)
                                    for module, names in ((dyld, ("MAX_FIXUPS",)),
                                                          (objc, ("MAX_CLASSES", "MAX_CLASS_POINTERS",
                                                                  "MAX_CLASS_CHAIN_NODES", "MAX_INVENTORY_POINTERS")))
                                    for name in names}}
    try:
        for arch in ("arm64", "x86_64"):
            report["architectures"].append(run_arch(output, guard, arch))
        report["status"] = "passed"
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
