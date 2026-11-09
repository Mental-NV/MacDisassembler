"""Derive a bounded x86_64 aggregate-return request from frozen binary evidence."""
import re

from aggregate_compat import Unsupported
from audit_core_behavior import complete, decode_instructions
from audit_core_data_references import NUM
from dispatch_linkage import table_targets
from macscope.macho import thin


REGISTERS = {
    "rax": "rax", "eax": "rax", "rbx": "rbx", "ebx": "rbx", "rcx": "rcx", "ecx": "rcx",
    "rdx": "rdx", "edx": "rdx", "rdi": "rdi", "edi": "rdi", "rsi": "rsi", "esi": "rsi",
    **{name: f"r{i}" for i in range(8, 16) for name in (f"r{i}", f"r{i}d")},
}
ARGUMENT_REGISTERS = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"}
MOV = re.compile(rf"%([a-z0-9]+), (?:%([a-z0-9]+)|({NUM}\(%rip\)))")
LEA = re.compile(rf"{NUM}\(%rip\), %([a-z0-9]+)")
SUFFIX = (
    ("popq", r"%rbp"),
    ("retq", ""),
    ("movl", rf"\${NUM}, %edx"),
    ("xorl", r"%eax, %eax"),
    ("retq", ""),
)


def direct_call(address, raw):
    if len(raw) == 5 and raw[0] == 0xe8:
        return address + len(raw) + int.from_bytes(raw[1:], "little", signed=True)
    return None


def operands_text(operands):
    return operands.split("##", 1)[0].strip()


def caller_observation(instructions, address, entry):
    """Recognize both return registers reaching stores or live ABI argument slots."""
    rows = list(instructions.items())
    index = next((i for i, (va, _) in enumerate(rows) if va == address), None)
    if index is None:
        return None
    raw, mnemonic, _ = rows[index][1]
    if mnemonic != "callq" or direct_call(address, raw) != entry:
        return None
    sequence = [{"va": hex(address), "bytes": raw.hex()}]
    live = {"rax": "word", "rdx": "status"}
    forwarded = {}
    observed = {}
    next_va = address + len(raw)
    for va, (raw, mnemonic, operands) in rows[index + 1:index + 9]:
        if va != next_va:
            break
        next_va += len(raw)
        operands = operands_text(operands)
        sequence.append({"va": hex(va), "bytes": raw.hex()})
        if mnemonic == "callq" and direct_call(va, raw) is not None:
            inputs = {value for register, value in forwarded.items() if register in ARGUMENT_REGISTERS}
            if len(observed) == 2 and inputs == {"word", "status"}:
                return {"kind": "call_arguments", "call_va": hex(address),
                        "reads": observed, "sequence": sequence}
            break
        move = MOV.fullmatch(operands) if mnemonic in ("movl", "movq") else None
        lea = LEA.fullmatch(operands) if mnemonic == "leaq" else None
        if move and move[1] in REGISTERS:
            source = REGISTERS[move[1]]
            wanted = (move[1], mnemonic) in (("rax", "movq"), ("edx", "movl"))
            value = live.get(source) if wanted else None
            if value and value not in observed:
                observed[value] = {"va": hex(va), "destination": move[2] or move[3]}
            if move[3]:
                if not value:
                    break
                if len(observed) == 2 and all("%rip" in row["destination"] for row in observed.values()):
                    return {"kind": "stores", "call_va": hex(address), "reads": observed, "sequence": sequence}
                continue
            destination = REGISTERS.get(move[2])
        elif lea:
            value, destination = None, REGISTERS.get(lea[1])
        elif mnemonic == "xorl" and operands == "%eax, %eax":
            value, destination = None, "rax"
        else:
            break
        if destination is None:
            break
        live.pop(destination, None)
        forwarded.pop(destination, None)
        if value:
            live[destination] = value
            forwarded[destination] = value
    return None


def dispatch_exit(instructions, layout):
    call = int(layout["call_va"], 16)
    after_call = [(va, row) for va, row in instructions.items() if va > call]
    if len(after_call) != len(SUFFIX) or any(
        mnemonic != expected or not re.fullmatch(pattern, operands_text(operands))
        for (_, (_, mnemonic, operands)), (expected, pattern) in zip(after_call, SUFFIX)
    ):
        raise Unsupported("unverified_dispatch_return_paths")
    branches = [operands for _, mnemonic, operands in instructions.values() if mnemonic == "jne"]
    if len(branches) != 1 or branches[0].split()[0] != hex(after_call[2][0]):
        raise Unsupported("unverified_dispatch_return_paths")
    return [{"va": hex(va), "bytes": row[0].hex()} for va, row in instructions.items()]


def instructions_for(path, binary, decoder, record, *, max_bytes):
    ranges = record["body_ranges"]
    rows = record["instructions"]
    facet = record["coverage"]["instructions"]
    if (len(ranges) != 1 or ranges[0][0] != record["entry_va"] or facet["status"] != "complete"
            or facet["truncated"] or facet["error"] or facet["emitted"] != len(rows)):
        raise Unsupported("incomplete_dispatch_instruction_capture")
    start, last = (int(address, 16) for address in ranges[0])
    if not 0 < last + 1 - start <= max_bytes:
        raise Unsupported("unsupported_dispatch_instruction_extent")
    decoded = decode_instructions(path, binary, decoder, {"function": (start, last + 1)})["function"]
    observed = [(int(row["addr"], 16), row["bytes"]) for row in rows]
    if observed != [(va, raw.hex()) for va, (raw, _, _) in decoded.items()]:
        raise Unsupported("dispatch_instruction_bytes_disagree")
    return decoded


def requests(path, binary, decoder, snapshot):
    """Use only binary bytes and Ghidra's own saved entries and references."""
    image = thin(binary)
    if image["arch"] != "x86_64":
        return [], []
    starts = image["loader"]["function_starts"]
    if not starts or starts["status"] != "complete":
        raise Unsupported("incomplete_dispatch_function_starts")
    entries = set(starts["addresses"])
    functions = [record for record in snapshot["functions"] if not record["is_external"] and not record["is_thunk"]]
    records = {record["entry_va"]: record for record in functions}
    if len(records) != len(functions):
        raise ValueError("Duplicate binary-derived function entry")
    candidates = [record for record in functions if record["entry_va"] in entries and complete(record)
                  and any(row["flow"] == "COMPUTED_CALL" for row in record["instructions"])]
    if len(candidates) > 32:
        raise Unsupported("dispatch_request_candidate_limit")
    requested, skipped = [], []
    callers = {}

    def recover(record):
        entry = record["entry_va"]
        decoded = instructions_for(path, binary, decoder, record, max_bytes=1024)
        layout = table_targets(binary, decoded)
        if layout["kind"] != "masked":
            raise Unsupported("unverified_dispatch_return_paths")
        machine = dispatch_exit(decoded, layout)
        call = layout["call_va"]
        computed = [row["addr"] for row in record["instructions"] if row["flow"] == "COMPUTED_CALL"]
        if (computed != [call] or any(row["from"] == call and "CALL" in row["type"]
                                      for row in record["xrefs_from_sample"])):
            raise Unsupported("unverified_dispatch_call_site")
        targets = sorted({slot["target_va"] for slot in layout["slots"]}, key=lambda address: int(address, 16))
        if entry in targets or any(target not in records or not complete(records[target]) for target in targets):
            raise Unsupported("missing_dispatch_target_capture")
        incoming = {int(row["from"], 16) for row in record["xrefs_to_entry"]
                    if row["to"] == entry and row["type"] == "UNCONDITIONAL_CALL" and not row["from_external"]}
        witness = None
        for caller in functions:
            if caller["entry_va"] == entry:
                continue
            hits = [int(row["addr"], 16) for row in caller["instructions"]
                    if row["flow"] == "UNCONDITIONAL_CALL" and int(row["addr"], 16) in incoming]
            if not hits:
                continue
            caller_va = caller["entry_va"]
            if caller_va not in callers:
                callers[caller_va] = instructions_for(path, binary, decoder, caller, max_bytes=16384)
            for address in hits:
                witness = caller_observation(callers[caller_va], address, int(entry, 16))
                if witness:
                    witness["entry_va"] = caller_va
                    break
            if witness:
                break
        if witness is None:
            raise Unsupported("missing_dispatch_return_observer")
        return {"entry_va": entry, "call_va": call, "target_vas": targets,
                "machine": machine, "observer": witness, "table": layout}

    for record in candidates:
        try:
            requested.append(recover(record))
        except Unsupported as error:
            skipped.append({"entry_va": record["entry_va"], "reason": str(error)})
    return requested, skipped
