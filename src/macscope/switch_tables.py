"""Byte-bound evidence for a guarded x86_64 relative switch table."""
from bisect import bisect_right
import re

from .dispatch_returns import signed
from .dispatch_tables import UnverifiedDispatch
from .errors import Error
from .macho import thin


POLICY = "macscope-guarded-switch-table/1"
SCRIPT = "RecoverSwitchTable.java"
MAX_ENTRIES = 64
MAX_BODY = 8192
TAIL = tuple(re.compile(pattern) for pattern in (
    r"(?:0fbe45|8b45)[89a-f][0-9a-f]",  # load selector into EAX
    r"(?:83c0..|05........)",            # subtract nonzero case base
    r"89c1",                             # mov ECX,EAX
    r"48894d[89a-f][0-9a-f]",            # spill zero-extended index
    r"(?:83e8..|2d........)",            # subtract upper bound for unsigned JA
    r"(?:77..|0f87........)",            # ja default
    r"488b4d[89a-f][0-9a-f]",            # reload the identical spill
    r"488d05........",                   # lea RAX, [RIP + table]
    r"48630c88",                         # movsxd RCX, [RAX + RCX*4]
    r"4801c8",                           # add RAX, RCX
    r"ffe0",                             # jmp RAX
))
HEX = re.compile(r"(?:[0-9a-f]{2}){1,15}")


def require(condition, reason):
    if not condition:
        raise UnverifiedDispatch(reason)


def complete(record, facet, key):
    coverage = record["coverage"].get(facet, {})
    return (coverage.get("status") == "complete" and not coverage.get("truncated")
            and not coverage.get("error") and coverage.get("emitted") == len(record[key]))


def verified_rows(binary, section, root, ranges):
    require(complete(root, "instructions", "instructions"), "incomplete_switch_instructions")
    base, offset = (int(section[key], 16) for key in ("va", "file_offset"))
    instructions = iter(root["instructions"])
    rows = []
    for start, last in ranges:
        address = start
        while address <= last:
            row = next(instructions, None)
            require(row is not None and row["addr"] == hex(address) and HEX.fullmatch(row["bytes"]),
                    "noncontiguous_switch_instructions")
            raw = bytes.fromhex(row["bytes"])
            position = offset + address - base
            require(address + len(raw) <= last + 1 and binary[position:position + len(raw)] == raw,
                    "switch_instruction_bytes_disagree")
            rows.append((address, raw, row["flow"]))
            address += len(raw)
    require(next(instructions, None) is None, "noncontiguous_switch_instructions")
    return rows


def layout(prefix, default):
    require(len(prefix) >= len(TAIL), "unsupported_switch_guard")
    tail = prefix[-len(TAIL):]
    require(all(pattern.fullmatch(raw.hex()) for pattern, (_, raw, _) in zip(TAIL, tail, strict=True)),
            "unsupported_switch_guard")
    _, adjust, _, spill, bound, branch, load, lea, _, _, jump = tail
    bias = signed(adjust[1][2:] if adjust[1][0] == 0x83 else adjust[1][1:])
    count = signed(bound[1][2:] if bound[1][0] == 0x83 else bound[1][1:]) + 1
    guard_va, guard_raw, _ = branch
    branch_target = guard_va + len(guard_raw) + signed(guard_raw[1:] if guard_raw[0] == 0x77 else guard_raw[2:])
    require(bias < 0 and 2 <= count <= MAX_ENTRIES and spill[1][-1] == load[1][-1]
            and signed(spill[1][-1:]) <= -8 and branch_target == default, "unsupported_switch_guard")
    require(all(flow == ("CONDITIONAL_JUMP" if va == guard_va else
                         "COMPUTED_JUMP" if va == jump[0] else "FALL_THROUGH")
                for va, _, flow in prefix), "unsupported_switch_guard_flow")
    return guard_va, jump[0], lea[0] + len(lea[1]) + signed(lea[1][3:]), count


def requests(binary, image, root):
    require(image["arch"] == "x86_64", "unsupported_switch_architecture")
    if not any(b["flow"] == "COMPUTED_JUMP" and not b["dsts"] for b in root["blocks"]):
        raise UnverifiedDispatch("no_unresolved_switch_jump")
    require(complete(root, "cfg", "blocks") and complete(root, "body_ranges", "body_ranges"),
            "incomplete_switch_body")
    ranges = [tuple(map(lambda value: int(value, 16), pair)) for pair in root["body_ranges"]]
    require(len(ranges) == 2, "unsupported_switch_body")
    (entry, jump_end), (default, end) = ranges
    require(hex(entry) == root["entry_va"] and entry <= jump_end < default - 1 <= end
            and end - entry < MAX_BODY, "unsupported_switch_body")
    text = [s for s in image["sections"] if (s["segment"], s["name"]) == ("__TEXT", "__text")]
    require(len(text) == 1 and text[0]["file_offset"] is not None and text[0]["protections"] & 7 == 5,
            "unverified_switch_text")
    section, = text
    base, offset, size = (int(section[key], 16) for key in ("va", "file_offset", "size"))
    require(base <= entry <= end < base + size and offset + size <= len(binary), "unverified_switch_text")
    starts = image["loader"]["function_starts"]
    require(starts and starts["status"] == "complete", "unverified_switch_linker_extent")
    entries = sorted(int(address, 16) for address in starts["addresses"])
    i = bisect_right(entries, entry)
    require(0 < i < len(entries) and entries[i - 1] == entry and end < entries[i],
            "unverified_switch_linker_extent")
    code = verified_rows(binary, section, root, ranges)
    prefix = [row for row in code if row[0] <= jump_end]
    require(code[-1][1:] == (b"\xc3", "TERMINATOR"), "unsupported_switch_body")
    guard, jump, table, count = layout(prefix, default)
    require(jump + 1 == jump_end and table >= end + 1 and table % 4 == 0
            and table + 4 * count <= min(base + size, entries[i]), "unverified_switch_table_extent")
    jumps = [b for b in root["blocks"] if b["flow"] == "COMPUTED_JUMP"]
    require(len(jumps) == 1 and int(jumps[0]["max"], 16) == jump_end and not jumps[0]["dsts"],
            "unsupported_switch_body")
    data = image["loader"]["data_in_code"]
    table_offset = offset + table - base
    require(data["status"] == "complete", "unverified_switch_data_in_code")
    relevant = [r for r in data["records"]
                if (start := int(r["slice_file_offset"], 16)) < table_offset + 4 * count
                and offset + entry - base < start + r["length"]]
    require(relevant == [{"slice_file_offset": hex(table_offset), "kind": "0x4", "length": 4 * count}],
            "unverified_switch_data_in_code")
    raw = binary[table_offset:table_offset + 4 * count]
    targets = [table + signed(raw[j:j + 4]) for j in range(0, len(raw), 4)]
    recovered = sorted(set(targets) - {default})
    require(len(recovered) >= 2 and recovered[0] == jump_end + 1 and recovered[-1] < default,
            "unverified_switch_destinations")
    gap_bytes = binary[offset + jump_end + 1 - base:offset + default - base]
    return [{"guard_va": hex(guard), "jump_va": hex(jump), "jump_end_va": hex(jump_end),
             "default_va": hex(default), "end_va": hex(end), "table_va": hex(table),
             "gap_bytes": gap_bytes.hex(), "table_bytes": raw.hex(), "targets": [hex(target) for target in targets],
             "known": [{"va": hex(va), "bytes": raw.hex()} for va, raw, _ in code]}]


def request(binary, image, root, _functions):
    plan = {"policy": POLICY, "image_sha256": image["sha256"], "entry_va": root["entry_va"], "requests": []}
    try:
        plan["requests"] = requests(binary, thin(binary), root)
    except UnverifiedDispatch as error:
        plan["skipped_reason"] = str(error)
    return plan


def decision(plan, report):
    result = {"entry_va": plan["entry_va"], "status": "skipped"}
    if not plan["requests"] and report is None:
        return dict(result, reason=plan["skipped_reason"])
    error = Error("switch_table_result", "Worker did not verify the guarded switch table", 10)
    if (len(plan["requests"]) != 1 or not isinstance(report, dict) or report.get("policy") != POLICY
            or report.get("entry_va") != plan["entry_va"]):
        raise error
    proof, = plan["requests"]
    evidence = {key: proof[key] for key in ("jump_va", "jump_end_va", "table_va", "targets")}
    if (any(report.get(key) != value for key, value in evidence.items())
            or report.get("labels") != list(range(len(proof["targets"])))
            or report.get("status") != "applied"):
        raise error
    return dict(result, status="applied", labels=report["labels"], **evidence)


def reviewed_blocks(blocks, recovery):
    """Apply only the verified edge set to fresh coverage, leaving saved CFG evidence intact."""
    if recovery is None or recovery["status"] != "applied":
        return blocks
    return [dict(block, dsts=[{"flow": "COMPUTED_JUMP", "from": recovery["jump_va"], "to": target}
                              for target in dict.fromkeys(recovery["targets"])])
            if block["flow"] == "COMPUTED_JUMP" and block["max"] == recovery["jump_end_va"] else block
            for block in blocks]
