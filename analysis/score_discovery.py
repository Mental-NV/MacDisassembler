#!/usr/bin/env python3
"""Adjudicate saved binary-only tool discovery using evaluator-side DWARF."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from prototype_experiment import fixture_input
from recovered_compare import PROFILES, matrix_exports
from validate_decompiler_evidence import (
    read_bytes, require_complete_function_inventory, sha, write_new_json,
)
from macscope.macho import thin


DIE = re.compile(r"^0x[0-9a-fA-F]+:\s+DW_TAG_([a-z_]+)")
ATTRIBUTE = re.compile(r"^\s+DW_AT_([a-z_]+)\s+\((.*)")
ADDRESS = re.compile(r"^0x[0-9a-fA-F]+")


def attributes(text):
    current = None
    for line in text.splitlines():
        die = DIE.match(line)
        if die:
            if current is not None:
                yield current
            current = {} if die[1] == "subprogram" else None
        elif current is not None:
            attr = ATTRIBUTE.match(line)
            if attr:
                current[attr[1]] = attr[2]
    if current is not None:
        yield current


def dwarf_functions(text, linker_starts, text_range):
    concrete = {}
    exclusions = {
        "abstract_or_declaration": 0, "split_range": 0, "outside_text": 0, "unconfirmed_entry": 0,
    }
    for attr in attributes(text):
        if "ranges" in attr:
            exclusions["split_range"] += 1
            continue
        low = ADDRESS.match(attr.get("low_pc", ""))
        high = ADDRESS.match(attr.get("high_pc", ""))
        if not low or not high:
            exclusions["abstract_or_declaration"] += 1
            continue
        lo, hi = int(low[0], 16), int(high[0], 16)
        if not text_range[0] <= lo < hi <= text_range[1]:
            exclusions["outside_text"] += 1
            continue
        if lo not in linker_starts:
            exclusions["unconfirmed_entry"] += 1
            continue
        name = None
        for key in ("name", "abstract_origin", "specification"):
            name = re.search(r'"([^"]+)"', attr.get(key, ""))
            if name:
                break
        end, names = concrete.setdefault(lo, (hi, set()))
        if end != hi:
            raise ValueError("Conflicting DWARF extents for one entry")
        names.add(name[1] if name else "<unnamed>")
    ordered = sorted(concrete.items())
    if any(end > next_entry for (_, (end, _)), (next_entry, _) in zip(ordered, ordered[1:])):
        raise ValueError("Overlapping evaluator DWARF function ranges")
    if not concrete:
        raise ValueError("No independently confirmed DWARF functions")
    return concrete, exclusions


def merged_ranges(function):
    facet = function["coverage"]["body_ranges"]
    body_ranges = function["body_ranges"]
    if (facet["status"] != "complete" or facet["truncated"] is not False
            or facet["error"] or facet["emitted"] != len(body_ranges) or not body_ranges):
        raise ValueError("Incomplete Ghidra function body")
    ranges = []
    for lo, hi in sorted((int(a, 16), int(b, 16) + 1) for a, b in body_ranges):
        if lo >= hi:
            raise ValueError("Invalid Ghidra function body range")
        if ranges and lo <= ranges[-1][1]:
            ranges[-1] = ranges[-1][0], max(hi, ranges[-1][1])
        else:
            ranges.append((lo, hi))
    return ranges


def score(snapshot, truth, linker_starts):
    require_complete_function_inventory(dict(snapshot["engine"], functions=snapshot["functions"]))
    candidates = {}
    for function in snapshot["functions"]:
        if function["is_external"] or function["is_thunk"]:
            continue
        va = int(function["entry_va"], 16)
        if va in candidates:
            raise ValueError("Duplicate Ghidra function entry")
        candidates[va] = function
    exact = 0
    body_disagreements = []
    missing = []
    for lo, (hi, names) in sorted(truth.items()):
        expected = {"entry_va": hex(lo), "names": sorted(names), "dwarf_end_exclusive": hex(hi)}
        function = candidates.get(lo)
        if function is None:
            missing.append(expected)
            continue
        ranges = merged_ranges(function)
        if ranges == [(lo, hi)]:
            exact += 1
            continue
        intersection = sum(max(0, min(end, hi) - max(start, lo)) for start, end in ranges)
        body_disagreements.append(dict(
            expected, ghidra_ranges=[[hex(a), hex(b)] for a, b in ranges],
            dwarf_only_bytes=hi - lo - intersection,
            ghidra_only_bytes=sum(b - a for a, b in ranges) - intersection,
        ))
    interior = []
    unscored = []
    for va in sorted(candidates.keys() - truth.keys()):
        container = next((lo for lo, (hi, _) in truth.items() if lo < va < hi), None)
        row = {"entry_va": hex(va), "name": candidates[va]["name"], "linker_confirmed": va in linker_starts}
        if container is None:
            unscored.append(row)
        else:
            interior.append(dict(row, containing_dwarf_entry=hex(container)))
    return {
        "dwarf_functions": len(truth), "ghidra_functions": len(candidates),
        "exact_entry_and_body": exact, "entry_matches": exact + len(body_disagreements),
        "body_disagreements": body_disagreements, "missing_entries": missing,
        "interior_candidates": interior, "outside_cohort": unscored,
    }


def tool_output(*args):
    proc = subprocess.run(
        ["/usr/bin/xcrun", "dwarfdump", *map(str, args)], capture_output=True, timeout=60, check=True,
    )
    if len(proc.stdout) > 16 * 1024 * 1024:
        raise ValueError("DWARF tool output exceeds the evidence bound")
    return proc.stdout.decode("utf-8","backslashreplace")


def text_bytes(data, metadata):
    section, = [s for s in metadata["sections"] if (s["segment"], s["name"]) == ("__TEXT", "__text")]
    offset, size = int(section["file_offset"], 16), int(section["size"], 16)
    va = int(section["va"], 16)
    return (va, va + size), data[offset:offset + size]


def verified_captures(build, matrix):
    build, matrix = build.resolve(), matrix.resolve()
    states = ("sym", "stripped")
    paired = {
        state: {case: (prior, paths) for case, prior, paths in matrix_exports(matrix, symbols=state)}
        for state in states
    }
    if paired["sym"].keys() != paired["stripped"].keys():
        raise ValueError("Fixture cohort mismatch")
    for case in paired["sym"]:
        _, symbol_binary, manifest = fixture_input(build, case)
        metadata = thin(symbol_binary)
        text_range, code = text_bytes(symbol_binary, metadata)
        starts = metadata["loader"]["function_starts"]
        if not starts or starts["status"] != "complete":
            raise ValueError("Missing independent linker function starts")
        linker = {int(va, 16) for va in starts["addresses"]}
        config, arch = case.split("-", 1)
        dwarf = build / "evaluator" / case / "CorpusFixture.dSYM/Contents/Resources/DWARF/CorpusFixture"
        if dwarf.is_symlink() or not dwarf.resolve().is_relative_to(build):
            raise ValueError("Evaluator DWARF must remain in the owned build tree")
        uuid = re.search(r"UUID: ([0-9A-Fa-f-]+) \(([^)]+)\)", tool_output("--uuid", dwarf))
        if not uuid or uuid[1].replace("-", "").lower() != metadata["uuid"] or uuid[2] != arch:
            raise ValueError("Evaluator DWARF identity differs from the binary")
        dwarf_text = tool_output("--debug-info", dwarf)
        dwarf_sha = sha(read_bytes(dwarf))
        dwarf_text_sha = sha(dwarf_text.encode())
        truth, exclusions = dwarf_functions(dwarf_text, linker, text_range)
        for state in states:
            prior, exports = paired[state][case]
            binary_path = build / "analyst" / f"{case}-{state}" / "CorpusFixture"
            if binary_path.is_symlink() or not binary_path.resolve().is_relative_to(build):
                raise ValueError("Fixture input must remain inside its build tree")
            binary = read_bytes(binary_path)
            case_records = [
                r for r in manifest["artifacts"]
                if (r["name"], r["config"], r["arch"], r["symbols"], r["container"])
                == ("CorpusFixture", config, arch, state, "thin")
            ]
            observed = thin(binary)
            digest = sha(binary)
            if (len(case_records) != 1 or case_records[0]["sha256"] != digest
                    or prior["input_sha256"] != digest or text_bytes(binary, observed) != (text_range, code)
                    or observed["uuid"] != metadata["uuid"]):
                raise ValueError("Symbol/stripped text or build identity mismatch")
            for profile, path in zip(PROFILES, exports):
                export = read_bytes(path)
                snapshot = json.loads(export)["data"]
                key = "baseline_analysis_id" if profile==PROFILES[0] else "inference_analysis_id"
                if (snapshot["image"]["sha256"] != digest or snapshot["identity"]["profile"] != profile
                        or snapshot["analysis_id"] != prior[key]):
                    raise ValueError("Profile export identity mismatch")
                provenance = {
                    "case": case, "symbols": state, "profile": profile, "input_sha256": digest,
                    "dwarf_sha256": dwarf_sha, "dwarf_text_sha256": dwarf_text_sha,
                    "export_sha256": sha(export), "evaluator_exclusions": exclusions,
                }
                yield provenance, snapshot, truth, linker, manifest


def run(build, matrix):
    report = {
        "schema": "macscope-discovery-dwarf/1", "status": "measured", "cases": [],
        "scope": "Source-aware evaluator comparison of saved binary-only discovery in calculator tools",
        "matrix_report_sha256": sha(read_bytes(matrix / "report.json")),
    }
    for provenance, snapshot, truth, linker, _ in verified_captures(build, matrix):
        report["cases"].append(dict(score(snapshot, truth, linker), **provenance))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-build-root", type=Path, required=True)
    parser.add_argument("--profile-matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.fixture_build_root, args.profile_matrix)
    write_new_json(args.output, report)
    print(json.dumps({"status": report["status"], "cases": len(report["cases"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
