#!/usr/bin/env python3
"""Compare independently decoded PC-relative data references in the owned core."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

from audit_core_behavior import core_extents, inventory, llvm_instructions
from prototype_experiment import fixture_input
from reference_coverage import xcrun
from score_discovery import verified_captures
from validate_decompiler_evidence import read_bytes, sha, write_new_json
from macscope import engine
from macscope.macho import thin


NUM = r"-?(?:0x[0-9a-f]+|[0-9]+)"
RIP = re.compile(rf"({NUM})?\(%rip\)")
LLVM_COMMENT = re.compile(r"##\s+(0x[0-9a-f]+)\b")
PAGE = re.compile(r"(x[0-9]+),\s*(0x[0-9a-f]+)(?:\s+<[^>]*>)?$")
ADD = re.compile(rf"(x[0-9]+),\s*(x[0-9]+),\s*(?:#({NUM})|[wx][0-9]+(?:,\s*[^;]+)?)$")
MEM = re.compile(rf"\[(x[0-9]+)(?:,\s*(?:#({NUM})|([wx][0-9]+)(?:,\s*[^\]]+)?))?\]$")
LITERAL = re.compile(r"[^,]+,\s*(0x[0-9a-f]+)(?:\s+<[^>]*>)?$")
DATA_TYPES = {"DATA", "READ", "WRITE", "READ_WRITE", "INDIRECTION"}


def arm64_page_use(instructions, entry, operands):
    match = PAGE.fullmatch(operands)
    if match is None:
        return None
    register, target = match[1], int(match[2], 16)
    indexed = False
    for address in range(entry + 4, entry + 20, 4):
        if address not in instructions:
            break
        _, mnemonic, operands = instructions[address]
        operands = operands.split(";", 1)[0].strip()
        add = ADD.fullmatch(operands) if mnemonic == "add" else None
        if add and add[2] == register:
            register = add[1]
            if add[3] is None:
                indexed = True
            else:
                target += int(add[3], 0)
            continue
        mem = MEM.search(operands) if mnemonic.startswith(("ld", "st")) else None
        if mem and mem[1] == register:
            target += int(mem[2], 0) if mem[2] else 0
            indexed |= mem[3] is not None
            return address, target, "indexed_base" if indexed else "address"
        break
    return None


def references(instructions, arch):
    expected, unsupported = [], []
    for entry, (raw, mnemonic, operands) in instructions.items():
        reference = None
        if arch == "x86_64" and "%rip" in operands:
            rip, comment = RIP.search(operands), LLVM_COMMENT.search(operands)
            if rip and comment:
                target = entry + len(raw) + int(rip[1] or "0", 0)
                if target != int(comment[1], 16):
                    raise ValueError("LLVM RIP-relative target disagrees with its displacement")
                reference = entry, target, "address"
        elif arch == "arm64" and mnemonic == "adrp":
            reference = arm64_page_use(instructions, entry, operands)
        elif arch == "arm64" and (mnemonic == "adr" or
                                 (mnemonic.startswith("ldr") and "[" not in operands)):
            literal = LITERAL.fullmatch(operands.split(";", 1)[0].strip())
            if literal:
                reference = entry, int(literal[1], 16), "address"
        else:
            continue
        if reference is None:
            unsupported.append({"entry_va": hex(entry), "instruction": mnemonic, "operands": operands})
        else:
            source, destination, interpretation = reference
            expected.append({
                "entry_va": hex(source), "target_va": hex(destination),
                "origin_instruction_va": hex(entry), "interpretation": interpretation,
            })
    return expected, unsupported


def compare(expected, unsupported, record, sections):
    refs = [] if record is None else record["xrefs_from_sample"]
    facet = {} if record is None else record["coverage"]["xrefs_from"]
    complete = (facet.get("status") == "complete" and facet.get("truncated") is False
                and not facet.get("error") and facet.get("emitted") == len(refs))
    typed = {(row["from"], row["to"]) for row in refs if row["type"] in DATA_TYPES}
    emitted = set() if record is None else {row["addr"] for row in record["instructions"]}
    rows = []
    for reference in expected:
        entry, target = reference["entry_va"], reference["target_va"]
        dest = int(target, 16)
        section = next((name for lo, hi, name in sections if lo <= dest < hi), None)
        if section is None:
            status = "target_section_unconfirmed"
        elif entry not in emitted:
            status = "source_instruction_absent"
        elif (entry, target) in typed:
            status = "matched"
        else:
            status = "reference_absent" if complete else "reference_inventory_partial"
        rows.append(dict(reference, section=section, status=status))
    return {"references": rows, "unsupported_patterns": unsupported}


def run(build, matrix, kind, recovery_matrix=None):
    decoder = xcrun("--find", "llvm-objdump")
    caches = {}
    captures = []
    for provenance, snapshot, truth, _, _ in verified_captures(
        build, matrix, kind=kind, recovery_matrix=recovery_matrix,
    ):
        case = provenance["case"]
        arch = case.split("-", 1)[1]
        extents = core_extents(truth)
        if case not in caches:
            decoded = llvm_instructions(build, case, decoder, extents, kind=kind)
            _, binary, _ = fixture_input(build, case, kind=kind)
            sections = [(int(row["va"], 16), int(row["va"], 16) + int(row["size"], 16),
                         row["segment"] + "," + row["name"]) for row in thin(binary)["sections"]]
            oracle = {routine: references(instructions, arch) for routine, instructions in decoded.items()}
            caches[case] = decoded, sections, oracle
        decoded, sections, oracle = caches[case]
        _, records = inventory(snapshot, extents, decoded)
        routines = {routine: compare(*oracle[routine], record, sections) for routine, record in records.items()
                    if any(oracle[routine])}
        captures.append(dict(provenance, analysis_id=snapshot["analysis_id"], routines=routines))
    rows = [row for capture in captures for row in capture["routines"].values()]
    states = Counter(ref["status"] for row in rows for ref in row["references"])
    unsupported = sum(len(row["unsupported_patterns"]) for row in rows)
    interpretation = Counter(ref["interpretation"] for row in rows for ref in row["references"])
    return {
        "schema": "macscope-core-data-references/1",
        "status": "matched" if states and set(states) == {"matched"} and not unsupported else "partial",
        "kind": kind, "counts": dict(states), "interpretations": dict(interpretation),
        "unsupported_patterns": unsupported, "matrix_report_sha256": sha(read_bytes(matrix / "report.json")),
        "decoder_sha256": engine.digest(Path(decoder)), "captures": captures,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-build-root", type=Path, required=True)
    parser.add_argument("--profile-matrix", type=Path, required=True)
    parser.add_argument("--kind", choices=("tool", "app"), required=True)
    parser.add_argument("--recovery-matrix", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.fixture_build_root, args.profile_matrix, args.kind, args.recovery_matrix)
    write_new_json(args.output, result)
    print(json.dumps({key: value for key, value in result.items() if key != "captures"}))
    return 0 if result["status"] == "matched" else 6


if __name__ == "__main__":
    raise SystemExit(main())
