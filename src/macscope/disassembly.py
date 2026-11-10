"""Bounded range queries over saved Ghidra instructions."""
import re

from . import body_ownership
from .errors import Error
from .metadata import VA
from .storage import canonical


MAX_RANGE_BYTES = 4096
ENCODING = re.compile(r"(?:[0-9a-fA-F]{2}){1,15}")


def parse_range(value):
    left, _, right = value.partition(":")
    if not VA.fullmatch(left) or not VA.fullmatch(right):
        raise Error("disasm_range", "Range must be two unslid hexadecimal VAs, START:END", 2)
    start, end = int(left, 16), int(right, 16)
    if not 0 < end - start <= MAX_RANGE_BYTES:
        raise Error("disasm_range", f"Range must cover 1..{MAX_RANGE_BYTES} bytes with an exclusive end", 2)
    return start, end


def candidates(functions, start, end):
    rows = {}
    for function in functions:
        if function["address_space"] != "ram":
            continue
        for row in function["instructions"]:
            address = row["addr"]
            if not VA.fullmatch(address):
                continue
            lo = int(address, 16)
            if lo >= end or lo + 15 <= start:
                continue
            encoding = row["bytes"]
            if not ENCODING.fullmatch(encoding):
                raise Error("disasm_instruction", "Saved instruction has invalid byte evidence")
            hi = lo + len(encoding) // 2
            if hi <= start:
                continue
            key = (lo, hi, canonical(row))
            if key not in rows:
                rows[key] = (row, set())
            rows[key][1].add(function["function_id"])
    return sorted(rows.items())


def query(snapshot, image, start, end):
    saved = candidates(snapshot["functions"], start, end)
    instructions, gaps = [], []
    covered = 0

    def gap(lo, hi, reason):
        gaps.append({"start_va": hex(lo), "end_va": hex(hi), "reason": reason})

    cursor, index = start, 0
    while index < len(saved):
        (lo, hi, _), (row, owners) = saved[index]
        index += 1
        conflict = False
        # Any positive overlap between distinct records makes the entire group ambiguous.
        while index < len(saved) and saved[index][0][0] < hi:
            hi = max(hi, saved[index][0][1])
            index += 1
            conflict = True
        first, last = max(lo, start), min(hi, end)
        if cursor < first:
            gap(cursor, first, "no_saved_instruction")
        if conflict:
            gap(first, last, "conflicting_instructions")
        elif first != lo or last != hi:
            gap(first, last, "instruction_crosses_range_boundary")
        else:
            instructions.append(dict(row, function_ids=sorted(owners)))
            covered += hi - lo
        cursor = last
    if cursor < end:
        gap(cursor, end, "no_saved_instruction")

    result = {"image_id": image["image_id"], "arch": image["arch"], "address_space": "ram",
            "start_va": hex(start), "end_va": hex(end), "requested_bytes": end - start,
            "covered_bytes": covered, "instructions": instructions, "gaps": gaps}
    if ownership := body_ownership.range_view(snapshot["functions"], start, end):
        result["body_ownership"] = ownership
    return result
