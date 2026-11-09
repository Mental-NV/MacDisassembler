#!/usr/bin/env python3
"""Read-only, source-aware evidence checks. No claim of recovered-C equivalence.

The instruction checker consumes a normalized macscope export and LLVM text.
Prototype comparisons consume raw MacscopeBridge results. Neither executes inputs.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

MAX_BYTES = 64 << 20


def read_bytes(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Missing, non-regular or oversized evidence: " + str(path))
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        raise ValueError("Evidence grew beyond the size bound")
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(read_bytes(path))


def write_new_json(path, value):
    # Exclusive creation: completed evidence is never overwritten.
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def index_functions(functions):
    """Names are not keys: imported functions and stubs can share a name."""
    indexed = {}
    for f in functions:
        entry = f.get("engine_entry") or f.get("entry_va")
        if not isinstance(entry, str) or not entry:
            raise ValueError("Missing engine function entry")
        key = (f.get("address_space", "ram"), entry)
        if key in indexed:
            raise ValueError("Duplicate function entry: " + repr(key))
        indexed[key] = f
    if not indexed:
        raise ValueError("Empty function population")
    return indexed


def require_complete_measured_facets(function):
    """Refuse equal-but-incomplete evidence; xref caps are outside this comparison."""
    status = function.get("decompile_status")
    if status not in ("complete", "not_requested"):
        raise ValueError("Decompiler operation did not complete")
    if status == "not_requested" and not (function.get("is_external") or function.get("is_thunk")):
        raise ValueError("Internal function was not decompiled")
    for key in ("pseudocode_truncated", "instructions_truncated", "blocks_truncated", "edges_truncated"):
        if function.get(key) is not False:
            raise ValueError("Missing or incomplete measured facet: " + key)
    for key in ("instructions_error", "cfg_error", "signature_error"):
        if function.get(key):
            raise ValueError("Measured facet failed: " + key)
    if function.get("signature") is None:
        raise ValueError("Function signature is unavailable")
    if status == "complete" and (not function.get("pseudocode") or function.get("decompile_error")):
        raise ValueError("Pseudocode is missing or has a diagnostic requiring review")
    coverage = function.get("coverage", {})
    for key, rows in (("body_ranges", function["body_ranges"]),
                      ("instructions", function["instructions"]), ("cfg", function["blocks"])):
        facet = coverage.get(key, {})
        if (facet.get("status") != "complete" or facet.get("truncated") is not False
                or facet.get("error") or facet.get("emitted") != len(rows)):
            raise ValueError("Incomplete measured coverage: " + key)
    if status == "complete":
        facet = coverage.get("pseudocode", {})
        if (facet.get("status") != "complete" or facet.get("truncated") is not False
                or facet.get("error") or facet.get("emitted") != 1):
            raise ValueError("Incomplete pseudocode coverage")
    if (function.get("instruction_count") != len(function["instructions"])
            or function.get("block_count") != len(function["blocks"])
            or any(block.get("edges_truncated") for block in function["blocks"])):
        raise ValueError("Inconsistent instruction/CFG counts or truncated edges")


def compare_results(baseline, candidate):
    if baseline["executable_sha256"] != candidate["executable_sha256"]:
        raise ValueError("Cannot compare different input identities")
    for function in baseline["functions"] + candidate["functions"]:
        require_complete_measured_facets(function)
    before = index_functions(baseline["functions"])
    after = index_functions(candidate["functions"])
    if before.keys() != after.keys():
        raise ValueError("Function entry set changed")
    fields = ("name", "signature", "calling_convention", "pseudocode",
              "body_ranges", "instructions", "blocks", "decompile_status")
    changes = {
        key: [{"entry_va": entry[1], "name": before[entry]["name"]}
              for entry in before if before[entry].get(key) != after[entry].get(key)]
        for key in fields
    }
    return {
        "function_count": len(before),
        "complete_pseudocode_count": sum(f["decompile_status"] == "complete"
                                        for f in after.values()),
        "changes": changes,
        "unchanged_machine_facets": not any(changes[k] for k in
            ("name", "body_ranges", "instructions", "blocks", "decompile_status")),
        "option_deltas": {
            key: [value, candidate["effective_analysis_options"].get(key)]
            for key, value in baseline["effective_analysis_options"].items()
            if value != candidate["effective_analysis_options"].get(key)
        } | {
            key: [None, value]
            for key, value in candidate["effective_analysis_options"].items()
            if key not in baseline["effective_analysis_options"]
        },
    }


def calculator_call_regression(functions):
    """Exact known-fixture sentinels, NOT a general C parser or call validator."""
    matches = [f for f in functions if f["name"] == "_calc_engine_input_digit"]
    if len(matches) != 1:
        raise ValueError("Expected one named calculator input-digit function")
    code = matches[0].get("pseudocode") or ""
    bad = "_calc_latch_error(iVar1,param_1,3);" in code
    good = "_calc_latch_error((long)param_1,3);" in code
    guard = "(param_2 < 0) || (9 < param_2)" in code
    return {
        "known_extra_argument_observed": bad,
        "expected_inferred_call_and_guard_observed": good and guard and not bad,
        "scope": "Exact source-aware arm64 O0 fixture regression, not semantic equivalence",
    }


def parse_llvm(text, arch):
    if arch not in ("arm64", "x86_64"):
        raise ValueError("Unsupported instruction architecture")
    result = {}
    for line in text.splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F ]+)\t(.*)$", line)
        if not match:
            continue
        address = int(match[1], 16)
        raw = bytes.fromhex(match[2])
        if arch == "arm64":
            if len(raw) != 4:
                raise ValueError("Expected one 32-bit arm64 instruction word")
            raw = raw[::-1]  # LLVM prints the word, not little-endian byte order.
        elif not 1 <= len(raw) <= 15:
            raise ValueError("Invalid x86_64 instruction byte count")
        if address in result:
            raise ValueError("Duplicate LLVM instruction address")
        result[address] = (raw, match[3])
    if not result:
        raise ValueError("LLVM text contains no decoded instructions")
    return result


def adjudicate_snapshot(snapshot, binary, llvm_text):
    if sha(binary) != snapshot["image"]["sha256"]:
        raise ValueError("Binary digest differs from the exported input identity")
    llvm = parse_llvm(llvm_text, snapshot["image"]["arch"])
    index_functions(snapshot["functions"])
    counts = {"function_ranges_checked": 0, "instructions_checked": 0,
              "direct_targets_checked": 0, "direct_targets_unmeasured": 0}
    mismatches = []
    for f in snapshot["functions"]:
        if f["is_external"] or f["is_thunk"]:
            continue
        if f.get("instructions_truncated") or f.get("instructions_error"):
            raise ValueError("Instruction facet is incomplete: " + f["name"])
        ranges = [(int(a, 16), int(b, 16)) for a, b in f["body_ranges"]]
        if not ranges or any(lo > hi for lo, hi in ranges):
            raise ValueError("Invalid or missing body ranges")
        emitted = {}
        for ins in f["instructions"]:
            address = int(ins["addr"], 16)
            if address in emitted:
                raise ValueError("Duplicate emitted instruction address")
            if not any(lo <= address <= hi for lo, hi in ranges):
                raise ValueError("Instruction outside its declared function ranges")
            raw = bytes.fromhex(ins["bytes"])
            if not raw:
                raise ValueError("Empty emitted instruction bytes")
            emitted[address] = raw
            offset = int(ins["location"]["slice_file_offset"], 16)
            if offset < 0 or binary[offset:offset + len(raw)] != raw:
                mismatches.append({"function": f["name"], "address": ins["addr"],
                                   "kind": "original_bytes_at_exported_offset"})
            flow = ins.get("flow", "")
            if ("JUMP" in flow or "CALL" in flow) and "COMPUTED" not in flow:
                independent = llvm.get(address)
                targets = re.findall(r"0x[0-9a-fA-F]+",
                                     independent[1].split("<")[0]) if independent else []
                if not targets:
                    counts["direct_targets_unmeasured"] += 1
                else:
                    counts["direct_targets_checked"] += 1
                    exported = re.findall(r"0x[0-9a-fA-F]+", ins["text"])
                    if not exported or int(targets[-1], 16) != int(exported[-1], 16):
                        mismatches.append({"function": f["name"], "address": ins["addr"],
                                           "kind": "direct_target"})
        selected = {address: value[0] for address, value in llvm.items()
                    if any(lo <= address <= hi for lo, hi in ranges)}
        if emitted != selected:
            mismatches.append({"function": f["name"], "kind": "starts_or_bytes"})
        counts["function_ranges_checked"] += 1
        counts["instructions_checked"] += len(emitted)
    if not counts["instructions_checked"]:
        raise ValueError("No non-external instruction population was checked")
    return {
        "status": "passed" if not mismatches else "failed",
        "binary_sha256": sha(binary), "llvm_text_sha256": sha(llvm_text.encode()),
        **counts, "mismatches": mismatches,
        "scope": "Ghidra-selected ranges and exported file offsets; not independent "
                 "body discovery, indirect-target completeness or pseudocode equivalence",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--llvm-text", type=Path,
                        help="Read previously captured llvm-objdump --disassemble output")
    parser.add_argument("--output", type=Path, help="Create a new report; never overwrite")
    args = parser.parse_args(argv)
    envelope = read_json(args.export)
    snapshot = envelope["data"]
    if args.llvm_text:
        llvm = read_bytes(args.llvm_text).decode()
        invocation = None
    else:
        invocation = ["xcrun", "llvm-objdump", "--disassemble", str(args.binary)]
        proc = subprocess.run(invocation, capture_output=True, timeout=60, check=True)
        if len(proc.stdout) > MAX_BYTES:
            raise ValueError("LLVM output exceeds evidence bound")
        llvm = proc.stdout.decode()
    report = adjudicate_snapshot(snapshot, read_bytes(args.binary), llvm)
    report.update(export_sha256=sha(read_bytes(args.export)), llvm_argv=invocation)
    if args.output:
        write_new_json(args.output, report)
    else:
        print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
