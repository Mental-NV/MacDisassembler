"""Bounded ARM64 tail exits for a disposable, exact no-analysis query.

Only byte-decoded B instructions leaving the selected linker extent qualify.
The destination must independently be a complete linker start or an ordinary,
strongly bound Mach-O import stub. No symbols inferred by Ghidra are used.
"""
from hashlib import sha256

from . import dyld, macho_load, metadata
from .errors import Error
from .storage import canonical

POLICY = "macscope-focused-tail-calls/1"
MAX_CANDIDATES = 64
MAX_STUBS = 16
MAX_REQUEST_BYTES = 128 * 1024


def branch_target(address, raw):
    if len(raw) != 4 or address % 4:
        return None
    word = int.from_bytes(raw, "little")
    if word & 0xfc000000 != 0x14000000:  # B, not BL or a conditional branch.
        return None
    displacement = word & 0x03ffffff
    if displacement & 0x02000000:
        displacement -= 1 << 26
    target = address + displacement * 4
    return target if 0 <= target < 1 << 64 else None


def safe_code(data, parsed, address, size):
    offset = metadata.mapped_location(parsed, address, size, from_file=False)
    sections = [row for row in parsed["sections"] if row["file_offset"] is not None
                and int(row["va"], 16) <= address
                and address + size <= int(row["va"], 16) + int(row["size"], 16)]
    if (address % 4 or offset is None or offset + size > len(data) or len(sections) != 1
            or not sections[0]["protections"] & 4 or not int(sections[0]["flags"], 16) & 0x80000400):
        return None
    loader = parsed["loader"]
    table = loader.get("data_in_code")
    if table and (table["status"] != "complete" or any(
            int(row["slice_file_offset"], 16) < offset + size
            and offset < int(row["slice_file_offset"], 16) + row["length"] for row in table["records"])):
        return None
    encryption = loader.get("encryption")
    if encryption and encryption["cryptid"]:
        start = int(encryption["slice_file_offset"], 16)
        if start < offset + size and offset < start + int(encryption["size"], 16):
            return None
    return offset


def plan(data, image, parsed, proof, payload):
    # Import lazily: import_links also consumes focused receipts.
    from . import import_links

    result = {"policy": POLICY, "arch": parsed["arch"], "candidates": [], "reason": None}
    if parsed["arch"] != "arm64":
        return dict(result, reason="architecture_unsupported")
    start, end = int(proof["entry_va"], 16), int(proof["end_va_exclusive"], 16)
    branches = []
    for offset in range(0, len(payload), 4):
        raw = payload[offset:offset + 4]
        target = branch_target(start + offset, raw)
        if target is not None and not start <= target < end:
            branches.append({"source_va": hex(start + offset), "source_bytes": raw.hex(), "target_va": hex(target)})
            if len(branches) > MAX_CANDIDATES:
                return dict(result, reason="candidate_limit")  # No partial prefix repair.
    if not branches:
        return result
    extents = [(int(row["slice_file_offset"], 16), int(row["size"], 16))
               for row in parsed["loader"]["linkedit"] if row["kind"] == "function_starts"]
    text = [row for row in parsed["segments"] if row["name"] == "__TEXT" and row["file_offset"] == "0x0"]
    starts = macho_load.function_starts(data, extents, text[0] if len(text) == 1 else None,
                                       members={int(row["target_va"], 16) for row in branches})
    if not starts or starts["status"] != "complete":
        return dict(result, reason="linker_starts_incomplete")
    known = set(starts["addresses"])
    bindings = {}
    for row in branches:
        target = int(row["target_va"], 16)
        offset = safe_code(data, parsed, target, 4)
        if offset is None:
            continue
        if row["target_va"] in known:
            result["candidates"].append(dict(row, target_kind="linker_function_start",
                                               target_bytes=data[offset:offset + 4].hex()))
            continue
        section = import_links.section_at(parsed, target, "__TEXT", "__stubs")
        if section is None or safe_code(data, parsed, target, 12) is None:
            continue
        stub = import_links.stub_slot(data, parsed, target, section)
        if stub is None:
            continue
        slot, instructions = stub
        if slot not in bindings:
            if len(bindings) == MAX_STUBS:
                return dict(result, candidates=[], reason="stub_limit")
            try:
                _, rows, gaps = dyld.fixups(data, image, parsed=parsed, address=int(slot, 16))
            except Error:
                rows, gaps = [], ["binding_unavailable"]
            candidates = [item for item in rows if item["kind"] == "bind"]
            slot_offset = metadata.mapped_location(parsed, int(slot, 16), 8, from_file=False)
            bindings[slot] = (candidates[0] if not gaps and len(candidates) == 1 and slot_offset is not None
                              and import_links.strong_bind(parsed, candidates[0], slot_offset) else None)
        binding = bindings[slot]
        if binding is not None:
            result["candidates"].append(dict(row, target_kind="declared_import_stub",
                target_bytes=data[offset:offset + 12].hex(), stub_instructions=instructions,
                bind_va=slot, binding=binding))
    if len(canonical(result)) + 1 > MAX_REQUEST_BYTES:
        return dict(result, candidates=[], reason="request_byte_limit")
    return result


def request_digest(plan):
    return sha256(canonical(plan) + b"\n").hexdigest()


def verify(plan, report, function, *, annotate=False):
    """Bind every override to its requested bytes and preserve pre-override flow."""
    expected = {"policy": POLICY, "request_sha256": request_digest(plan)}
    if (not isinstance(report, dict) or set(report) != {*expected, "decisions"}
            or any(report[key] != value for key, value in expected.items())
            or not isinstance(report["decisions"], list)
            or len(report["decisions"]) != len(plan["candidates"])):
        raise Error("focused_tail_calls", "Worker returned invalid tail-call provenance", 10)
    instructions = {row["addr"]: row for row in function["instructions"]}
    applied = set()
    for candidate, decision in zip(plan["candidates"], report["decisions"]):
        source = candidate["source_va"]
        if (not isinstance(decision, dict) or set(decision) != {"source_va", "outcome"}
                or decision["source_va"] != source
                or decision["outcome"] not in ("applied", "instruction_unavailable")):
            raise Error("focused_tail_calls", "Worker returned an invalid tail-call decision", 10)
        instruction = instructions.get(source)
        if decision["outcome"] == "instruction_unavailable":
            if instruction is not None:
                raise Error("focused_tail_calls", "Worker skipped an available proven tail exit", 10)
            continue
        if (plan["arch"] != "arm64" or instruction is None or instruction["bytes"] != candidate["source_bytes"]
                or instruction["flow"] != "CALL_TERMINATOR"
                or branch_target(int(source, 16), bytes.fromhex(instruction["bytes"])) != int(candidate["target_va"], 16)):
            raise Error("focused_tail_calls", "Worker tail call differs from the proved branch", 10)
        original = {"original_flow": "UNCONDITIONAL_JUMP", "flow_override": "CALL_RETURN"}
        if annotate:
            instruction.update(original)
        elif any(instruction.get(key) != value for key, value in original.items()):
            raise Error("focused_tail_calls", "Tail call is missing its original instruction flow", 10)
        applied.add(source)
    if any((row.get("flow_override") or row["flow"] == "CALL_TERMINATOR") and row["addr"] not in applied
           for row in function["instructions"]):
        raise Error("focused_tail_calls", "Worker reported an unrequested tail call", 10)
    if annotate:
        function["tail_call_recovery"] = report


def verified_target(function, instruction):
    """Recognize only an applied receipt-bound B, never an arbitrary call override."""
    plan = function.get("origin", {}).get("extent", {}).get("tail_calls")
    report = function.get("tail_call_recovery")
    if not plan or not report or instruction.get("flow_override") != "CALL_RETURN":
        return None
    if (plan.get("arch") != "arm64" or report.get("policy") != POLICY
            or report.get("request_sha256") != request_digest(plan)
            or instruction.get("original_flow") != "UNCONDITIONAL_JUMP"):
        return None
    for candidate, decision in zip(plan["candidates"], report.get("decisions", ())):
        if (candidate["source_va"] == instruction["addr"] == decision.get("source_va")
                and decision.get("outcome") == "applied" and candidate["source_bytes"] == instruction["bytes"]):
            target = branch_target(int(instruction["addr"], 16), bytes.fromhex(instruction["bytes"]))
            if target is not None and hex(target) == candidate["target_va"]:
                return target
    return None
