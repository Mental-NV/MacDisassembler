"""Bounded binary evidence for opt-in x86_64 dispatch return recovery."""
import hashlib
import re

from .dispatch_tables import UnverifiedDispatch, table_entries
from .errors import Error
from .macho import thin
from .storage import canonical


POLICY = "macscope-dispatch-return-recovery/1"
# The supported masked dispatcher preserves RAX and RDX on the call path
# and defines both on the default path. Immediate and displacement bytes
# are decoded below rather than taken from the disassembler's text.
MASKED_DISPATCH = tuple((label, re.compile(pattern)) for label, pattern in (
    ("selector", "89f9"),              # mov ecx, edi
    ("bias", "80c1.."),                # add cl, imm8
    ("bound", "80f9.."),               # cmp cl, imm8
    ("in_range", "0f92c0"),            # setb al
    ("mask", "40b7.."),                # mov dil, imm8
    ("shift", "40d2ef"),               # shr dil, cl
    ("guard", "4020c7"),               # and dil, al
    ("check", "4080ff01"),             # cmp dil, 1
    ("failure_branch", "75.."),        # jne rel8
    ("save_frame", "55"),
    ("frame", "4889e5"),
    ("index", "0fb6c1"),               # movzx eax, cl
    ("table", "488d0d........"),       # lea rcx, [rip + disp32]
    ("row", "488b04c1"),               # mov rax, [rcx + rax*8]
    ("left", "4889f7"),                # mov rdi, rsi
    ("right", "4889d6"),               # mov rsi, rdx
    ("call", "ff5008"),                # call [rax + 8]
    ("restore_frame", "5d"),
    ("success_return", "c3"),
    ("failure_status", "ba........"),  # mov edx, imm32
    ("failure_value", "31c0"),         # xor eax, eax
    ("failure_return", "c3"),
))
RAX, RDX = 0, 2
ARGUMENT_REGISTERS = {7, 6, 2, 1, 8, 9}
HEX_BYTES = re.compile(r"(?:[0-9a-f]{2}){1,15}")


def instruction_bytes(binary, image, record, limit):
    ranges, instructions = record["body_ranges"], record["instructions"]
    coverage = record["coverage"]["instructions"]
    if (len(ranges) != 1 or ranges[0][0] != record["entry_va"] or coverage["status"] != "complete"
            or coverage["truncated"] or coverage["error"] or coverage["emitted"] != len(instructions)):
        raise UnverifiedDispatch("incomplete_dispatch_instruction_capture")
    start, last = (int(address, 16) for address in ranges[0])
    if not 0 < last + 1 - start <= limit:
        raise UnverifiedDispatch("unsupported_dispatch_instruction_extent")
    sections = [section for section in image["sections"]
                if (section["segment"], section["name"]) == ("__TEXT", "__text")]
    if len(sections) != 1 or sections[0]["file_offset"] is None:
        raise UnverifiedDispatch("dispatch_text_unavailable")
    text = sections[0]
    base, offset, size = (int(text[key], 16) for key in ("va", "file_offset", "size"))
    if not base <= start <= last < base + size or offset + size > len(binary):
        raise UnverifiedDispatch("dispatch_code_outside_text")
    file_start, file_end = offset + start - base, offset + last + 1 - base
    data = image["loader"]["data_in_code"]
    if data["status"] != "complete" or any(
        (data_start := int(row["slice_file_offset"], 16)) < file_end and
        file_start < data_start + row["length"] for row in data["records"]
    ):
        raise UnverifiedDispatch("dispatch_code_overlaps_data_in_code")
    code = {}
    cursor = start
    for row in instructions:
        if row["addr"] != hex(cursor) or not HEX_BYTES.fullmatch(row["bytes"]):
            raise UnverifiedDispatch("noncontiguous_dispatch_instructions")
        raw = bytes.fromhex(row["bytes"])
        position = offset + cursor - base
        if cursor + len(raw) > last + 1 or raw != binary[position:position + len(raw)]:
            raise UnverifiedDispatch("dispatch_instruction_bytes_disagree")
        code[cursor] = raw
        cursor += len(raw)
    if cursor != last + 1:
        raise UnverifiedDispatch("noncontiguous_dispatch_instructions")
    return code


def signed(raw):
    return int.from_bytes(raw, "little", signed=True)


def direct_target(address, raw):
    if len(raw) == 5 and raw[0] == 0xe8:
        return address + 5 + signed(raw[1:])
    return None


def masked_layout(code):
    if len(code) != len(MASKED_DISPATCH):
        raise UnverifiedDispatch("unsupported_dispatch_instruction_shape")
    fields = {}
    for (label, pattern), (address, raw) in zip(MASKED_DISPATCH, code.items()):
        if not pattern.fullmatch(raw.hex()):
            raise UnverifiedDispatch("unsupported_dispatch_instruction_shape")
        fields[label] = address, raw
    branch, branch_bytes = fields["failure_branch"]
    if branch + len(branch_bytes) + signed(branch_bytes[1:]) != fields["failure_status"][0]:
        raise UnverifiedDispatch("unverified_dispatch_return_paths")
    table, lea = fields["table"]
    base = table + len(lea) + signed(lea[3:])
    bias = (-fields["bias"][1][-1]) & 0xff
    count, mask = fields["bound"][1][-1], fields["mask"][1][-1]
    if base < 0 or base % 8 or not 1 <= count <= 8 or not 0 < mask < (1 << count):
        raise UnverifiedDispatch("unverified_dispatch_index_domain")
    return {"kind": "masked", "base_va": base, "call_va": fields["call"][0],
            "field": 8, "stride": 8, "count": count, "bias": bias, "mask": mask}


def transfer(raw):
    """Decode only the moves, RIP LEAs and zeroing accepted in an observer."""
    if raw == b"\x31\xc0":
        return None, RAX, 4
    rex = raw[0] if 0x40 <= raw[0] <= 0x4f else 0
    body = raw[bool(rex):]
    if len(body) < 2:
        return None
    opcode, modrm = body[:2]
    reg = (modrm >> 3 & 7) + (8 if rex & 4 else 0)
    width = 8 if rex & 8 else 4
    if opcode == 0x89 and len(body) == 2 and modrm >> 6 == 3:
        return reg, (modrm & 7) + (8 if rex & 1 else 0), width
    if len(body) == 6 and modrm & 0xc7 == 5:
        if opcode == 0x89:
            return reg, None, width
        if opcode == 0x8d:
            return None, reg, width
    return None


def observer(code, address, entry):
    if address not in code or direct_target(address, code[address]) != entry:
        return None
    cursor = address + len(code[address])
    sequence = [address]
    available, forwarded, stores = {"word", "status"}, {}, set()
    for _ in range(8):
        raw = code.get(cursor)
        if raw is None:
            break
        sequence.append(cursor)
        if direct_target(cursor, raw) is not None:
            arguments = {value for register, value in forwarded.items() if register in ARGUMENT_REGISTERS}
            if arguments == {"word", "status"}:
                return observation("call_arguments", address, sequence, code)
            break
        move = transfer(raw)
        if move is None:
            break
        source, destination, width = move
        value = {(RAX, 8): "word", (RDX, 4): "status"}.get((source, width))
        if value not in available:
            value = None
        if destination is None:
            if not value:
                break
            stores.add(value)
            if stores == {"word", "status"}:
                return observation("stores", address, sequence, code)
        else:
            # Partial writes are excluded. The accepted instructions write
            # a full register, either directly or by zero extension.
            if destination == RAX and (value, width) != ("word", 8):
                available.discard("word")
            if destination == RDX and value != "status":
                available.discard("status")
            forwarded.pop(destination, None)
            if value:
                forwarded[destination] = value
        cursor += len(raw)
    return None


def observation(kind, address, sequence, code):
    return {"kind": kind, "call_va": hex(address),
            "sequence": [{"va": hex(va), "bytes": code[va].hex()} for va in sequence]}


def find_observer(binary, image, records, root):
    entry = root["entry_va"]
    incoming = sorted({int(ref["from"], 16) for ref in root["xrefs_to_entry"]
                       if ref["type"] == "UNCONDITIONAL_CALL" and not ref["from_external"] and
                       ref["to"] == entry and (ref["from"] or "").startswith("0x")})
    for caller in records.values():
        ranges = caller["body_ranges"]
        if caller["entry_va"] == entry or len(ranges) != 1:
            continue
        lo, hi = (int(value, 16) for value in ranges[0])
        hits = [va for va in incoming if lo <= va <= hi]
        if not hits:
            continue
        try:
            code = instruction_bytes(binary, image, caller, 16384)
        except UnverifiedDispatch:
            continue
        for address in hits:
            witness = observer(code, address, int(entry, 16))
            if witness:
                return dict(witness, entry_va=caller["entry_va"])
    raise UnverifiedDispatch("missing_dispatch_return_observer")


def evidence(binary, image, root, functions):
    if image["arch"] != "x86_64":
        raise UnverifiedDispatch("unsupported_dispatch_architecture")
    if root["decompile_status"] != "complete" or root["pseudocode_truncated"]:
        raise UnverifiedDispatch("incomplete_dispatch_pseudocode_capture")
    starts = image["loader"]["function_starts"]
    entry = root["entry_va"]
    if not starts or starts["status"] != "complete" or entry not in starts["addresses"]:
        raise UnverifiedDispatch("unverified_dispatch_function_start")
    code = instruction_bytes(binary, image, root, 1024)
    layout = masked_layout(code)
    call = hex(layout["call_va"])
    computed = [row["addr"] for row in root["instructions"] if row["flow"] == "COMPUTED_CALL"]
    if (computed != [call] or any(ref["from"] == call and "CALL" in ref["type"]
                                  for ref in root["xrefs_from_sample"])):
        raise UnverifiedDispatch("unverified_dispatch_call_site")
    slots = table_entries(binary, image, layout)
    targets = sorted({slot["target_va"] for slot in slots}, key=lambda va: int(va, 16))
    records = {row["entry_va"]: row for row in functions if row["entry_va"] is not None
               and not row["is_external"] and not row["is_thunk"]}
    if entry in targets or any(va not in records or records[va]["decompile_status"] != "complete" for va in targets):
        raise UnverifiedDispatch("missing_dispatch_target_capture")
    witness = find_observer(binary, image, records, root)
    return {"entry_va": entry, "call_va": call, "target_vas": targets, "observer": witness,
            "machine": [{"va": hex(va), "bytes": raw.hex()} for va, raw in code.items()],
            "table": dict(layout, base_va=hex(layout["base_va"]), call_va=call, slots=slots)}


def request(binary, image, root, functions):
    plan = {"policy": POLICY, "image_sha256": image["sha256"], "entry_va": root["entry_va"], "requests": []}
    try:
        plan["requests"].append(evidence(binary, thin(binary), root, functions))
    except UnverifiedDispatch as error:
        plan["skipped_reason"] = str(error)
    return plan


def request_identity(plan):
    return {"policy": POLICY, "request_sha256": hashlib.sha256(canonical(plan) + b"\n").hexdigest()}


def decision(plan, report):
    if not plan["requests"] and report is None:
        return {"entry_va": plan["entry_va"], "status": "skipped", "reason": plan["skipped_reason"]}
    if (not plan["requests"] or not isinstance(report, dict) or report.get("policy") != POLICY
            or not isinstance(report.get("results"), list) or len(report["results"]) != 1):
        raise Error("dispatch_return_result", "Worker did not verify the requested dispatch return", 10)
    requested = plan["requests"][0]
    row = report["results"][0]
    if (not isinstance(row, dict) or row.get("entry_va") != requested["entry_va"]
            or row.get("call_va") != requested["call_va"]):
        raise Error("dispatch_return_result", "Worker reported a different dispatch return site", 10)
    if row.get("status") == "applied" and (row.get("target_vas") == requested["target_vas"]
            and row.get("prior_return_storage") == "RAX:8" and row.get("return_storage") == "RDX:8,RAX:8"
            and isinstance(row.get("convention"), str) and row["convention"]):
        # The table is evidence for the return type, not a set of exported call edges.
        return {key: row[key] for key in ("entry_va", "call_va", "status", "prior_return_storage",
                                          "return_storage", "convention")}
    if row.get("status") == "skipped" and row.get("reason") in (
            "unsupported_or_already_typed_root", "callee_abi_disagreement"):
        return {key: row[key] for key in ("entry_va", "call_va", "status", "reason")}
    raise Error("dispatch_return_result", "Worker reported invalid dispatch return evidence", 10)
