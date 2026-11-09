#!/usr/bin/env python3
"""Check the owned core's instruction boundaries, bytes and direct targets."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess

from audit_core_behavior import core_extents, inventory, llvm_instructions
from prototype_experiment import fixture_input
from reference_coverage import xcrun
from score_discovery import verified_captures
from validate_decompiler_evidence import read_bytes, sha, write_new_json
from macscope import engine


NUMERIC_TARGET = re.compile(r"(?i)(?:^|,)\s*(0x[0-9a-f]+)\s*(?:<[^>]*>)?\s*$")
STUB = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s+[0-9]+\s+(\S+)\s*$")


def target(operands):
    operands = operands.split("##", 1)[0].split(";", 1)[0]
    match = NUMERIC_TARGET.search(operands)
    return int(match[1], 16) if match else None


def expected_branch(arch, mnemonic, operands):
    if arch == "arm64":
        if mnemonic == "bl":
            return "call", target(operands)
        if mnemonic in ("b", "cbz", "cbnz", "tbz", "tbnz") or mnemonic.startswith(("b.", "bc.")):
            return "jump", target(operands)
    elif not operands.startswith("*"):
        if mnemonic.startswith("call"):
            return "call", target(operands)
        if mnemonic.startswith(("j", "loop")):
            return "jump", target(operands)
    return None


def recovered_branch(instruction):
    flow = instruction["flow"]
    if "COMPUTED" in flow:
        return None
    if "CALL" in flow:
        kind = "call"
    elif "JUMP" in flow:
        kind = "jump"
    else:
        return None
    _, _, operands = instruction["text"].partition(" ")
    return kind, target(operands)


def llvm_stubs(build, case, decoder, *, kind="tool"):
    path, _, _ = fixture_input(build, case, kind=kind)
    output = subprocess.check_output([decoder, "--macho", "--indirect-symbols", str(path)], timeout=30)
    if len(output) > 16 << 20:
        raise ValueError("Oversized LLVM indirect symbol evidence")
    in_stubs = False
    stubs = {}
    for line in output.decode(errors="replace").splitlines():
        if line.startswith("Indirect symbols for"):
            in_stubs = line.startswith("Indirect symbols for (__TEXT,__stubs)")
        row = STUB.match(line) if in_stubs else None
        if row is not None:
            entry = int(row[1], 16)
            if entry in stubs:
                raise ValueError("Duplicate LLVM stub entry")
            stubs[entry] = row[2]
    return stubs


def compare(record, independent, arch, end, stubs):
    if record is None:
        return {"status": "missing_recovered_entry"}
    instructions = record["instructions"]
    facet = record["coverage"]["instructions"]
    if (facet["status"] != "complete" or facet["truncated"] is not False
            or facet["error"] or facet["emitted"] != len(instructions)):
        return {"status": "incomplete_instructions"}
    actual = {int(row["addr"], 16): row for row in instructions}
    if len(actual) != len(instructions):
        raise ValueError("Duplicate Ghidra instruction address")
    expected = set(independent)
    missing = sorted(expected - actual.keys())
    extra = sorted(actual.keys() - expected)
    wrong_bytes = []
    target_gaps = []
    tail_calls = []
    branch_matches = 0
    direct_targets = 0
    for address in sorted(expected | actual.keys()):
        oracle = independent.get(address)
        row = actual.get(address)
        reference = expected_branch(arch, oracle[1], oracle[2]) if oracle else None
        observed = recovered_branch(row) if row else None
        if oracle and row:
            encoded = bytes.fromhex(row["bytes"])
            if oracle[0] != encoded or address + len(encoded) > end:
                wrong_bytes.append({"entry": hex(address), "llvm": oracle[0].hex(), "ghidra": encoded.hex()})
        if reference is not None:
            direct_targets += 1
        if reference is None and observed is None:
            continue
        if reference is not None and reference[1] is not None and observed == reference:
            branch_matches += 1
        elif (reference is not None and observed is not None and reference[0] == "jump"
              and observed == ("call", reference[1]) and reference[1] in stubs
              and oracle[1] in ("b", "jmp", "jmpq") and row["flow"] == "CALL_TERMINATOR"
              and row["fallthrough"] is None):
            branch_matches += 1
            tail_calls.append({"entry": hex(address), "target": hex(reference[1]), "stub": stubs[reference[1]]})
        else:
            target_gaps.append({
                "entry": hex(address), "llvm": reference, "ghidra": observed,
                "llvm_operands": oracle[2] if oracle else None, "ghidra_text": row["text"] if row else None,
            })
    return {
        "status": "matched" if not (missing or extra or wrong_bytes or target_gaps) else "disagreement",
        "instruction_starts": len(expected), "instruction_starts_matched": len(expected) - len(missing),
        "instruction_byte_records_matched": len(expected) - len(missing) - len(wrong_bytes),
        "direct_targets": direct_targets, "direct_targets_matched": branch_matches,
        "stub_tail_calls_adjudicated": len(tail_calls), "stub_tail_calls": tail_calls,
        "missing_instructions": [hex(address) for address in missing],
        "extra_instructions": [{"entry": hex(address), "text": actual[address]["text"],
                                "bytes": actual[address]["bytes"]} for address in extra],
        "byte_disagreements": wrong_bytes, "target_disagreements": target_gaps,
    }


def compare_call_references(record, independent, arch, tail_calls):
    expected = {(int(row["entry"], 16), row["target"]) for row in tail_calls}
    indirect_calls = set()
    for address, (_, mnemonic, operands) in independent.items():
        branch = expected_branch(arch, mnemonic, operands)
        if branch and branch[0] == "call":
            if branch[1] is None:
                return {"status": "unverified_call_operand"}
            expected.add((address, hex(branch[1])))
        elif ((arch == "arm64" and mnemonic.startswith("blr"))
              or (arch == "x86_64" and mnemonic.startswith("call") and operands.startswith("*"))):
            indirect_calls.add(address)
    if record is None:
        return {"status": "missing_recovered_entry"}
    refs = record["xrefs_from_sample"]
    facet = record["coverage"]["xrefs_from"]
    if (facet["status"] != "complete" or facet["truncated"] is not False
            or facet["error"] or facet["emitted"] != len(refs)):
        return {"status": "incomplete_outgoing_references"}
    calls = {(int(row["from"], 16), row["to"]) for row in refs
             if row["type"] in ("UNCONDITIONAL_CALL", "CONDITIONAL_CALL")}
    speculative = {(int(row["from"], 16), row["to"]) for row in refs
                   if "CALL" in row["type"] and int(row["from"], 16) in indirect_calls}

    def addresses(rows):
        return [{"entry": hex(address), "target": target} for address, target in sorted(rows)]

    return {
        "status": "matched" if calls == expected and not speculative else "disagreement",
        "expected_direct_call_references": len(expected),
        "matched_direct_call_references": len(expected & calls),
        "encoded_indirect_calls": len(indirect_calls),
        "missing_direct_call_references": addresses(expected - calls),
        "unexpected_direct_call_references": addresses(calls - expected),
        "reported_targets_at_indirect_calls": addresses(speculative),
    }


TOTALS = ("instruction_starts", "instruction_starts_matched", "instruction_byte_records_matched",
          "llvm_instruction_bytes", "direct_targets", "direct_targets_matched", "stub_tail_calls_adjudicated")
CALL_TOTALS = ("expected_direct_call_references", "matched_direct_call_references", "encoded_indirect_calls")


def summary(rows):
    calls = [row["call_references"] for row in rows if "call_references" in row]
    return dict(
        Counter(row["status"] for row in rows),
        **{key: sum(row.get(key, 0) for row in rows) for key in TOTALS},
        call_references={
            "statuses": dict(Counter(row["status"] for row in calls)),
            **{key: sum(row.get(key, 0) for row in calls) for key in CALL_TOTALS},
        },
    )


def run(build, matrix, kind="tool"):
    decoder = xcrun("--find", "llvm-objdump")
    decodes, stubs = {}, {}
    captures = []
    for provenance, snapshot, truth, _, _ in verified_captures(build, matrix, kind=kind):
        case = provenance["case"]
        arch = case.split("-", 1)[1]
        extents = core_extents(truth)
        if case not in decodes:
            decodes[case] = llvm_instructions(build, case, decoder, extents, kind=kind)
            stubs[case] = llvm_stubs(build, case, decoder, kind=kind)
        decoded = decodes[case]
        rows, records = inventory(snapshot, extents, decoded)
        for routine, row in rows.items():
            if routine not in extents:
                continue
            _, end = extents[routine]
            row.update(compare(records[routine], decoded[routine], arch, end, stubs[case]))
            row["call_references"] = compare_call_references(
                records[routine], decoded[routine], arch, row.get("stub_tail_calls", ()),
            )
        captures.append(dict(provenance, analysis_id=snapshot["analysis_id"],
                             native_decompiler_sha256=snapshot["identity"]["engine"]["native_decompiler_sha256"],
                             routines=rows, summary=summary(rows.values())))
    rows = [row for capture in captures for row in capture["routines"].values()]
    return {
        "schema": "macscope-core-instruction-audit/2",
        "status": "matched" if rows and all(
            row["status"] == "matched" and row.get("call_references", {}).get("status") == "matched"
            for row in rows
        ) else "partial",
        "scope": f"LLVM instruction bytes, direct targets and outgoing call references within the owned {kind} core",
        "matrix_report_sha256": sha(read_bytes(matrix / "report.json")),
        "decoder_sha256": engine.digest(Path(decoder)),
        "summary": summary(rows), "captures": captures,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-build-root", type=Path, required=True)
    parser.add_argument("--profile-matrix", type=Path, required=True)
    parser.add_argument("--kind", choices=("tool", "app"), default="tool")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.fixture_build_root, args.profile_matrix, args.kind)
    write_new_json(args.output, report)
    print(json.dumps({"status": report["status"], **report["summary"]}))
    return 0 if report["status"] == "matched" else 6


if __name__ == "__main__":
    raise SystemExit(main())
