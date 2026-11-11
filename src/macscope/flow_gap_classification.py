"""Bounded source proofs for residual gaps, never runtime callee resolution.

Plans are captured before execution and must be recomputed from the saved slice
on full replay. At most 64 byte-pattern candidates, 16 binding queries and 128
KiB of serialized evidence are retained. Exhaustion discards the entire prefix.
Candidate scanning is not disassembly: promotion requires exact captured source
instruction boundaries, and ARM64 wrappers require a single complete CFG block.
"""
import re

from . import dyld, metadata
from .errors import Error
from .storage import canonical

POLICY = "macscope-flow-gap-classification/1"
MAX_CANDIDATES = 64
MAX_BIND_SLOTS = 16
MAX_REQUEST_BYTES = 128 * 1024
MAX_SCAN_BYTES = 8192
KINDS = {"unclassified", "verified_linkage_boundary", "unresolved_internal_transfer"}


def _signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def direct(arch, address, raw):
    """Return (width, target, expected flow), excluding calls and overflow."""
    width = None
    flow = "CONDITIONAL_JUMP"
    if arch == "arm64" and address % 4 == 0 and len(raw) >= 4:
        word = int.from_bytes(raw[:4], "little")
        width = 4
        if word & 0xfc000000 == 0x14000000:
            displacement, flow = _signed(word & 0x3ffffff, 26) * 4, "UNCONDITIONAL_JUMP"
        elif word & 0xff000010 == 0x54000000 or word & 0x7e000000 == 0x34000000:
            displacement = _signed((word >> 5) & 0x7ffff, 19) * 4
        elif word & 0x7e000000 == 0x36000000:
            displacement = _signed((word >> 5) & 0x3fff, 14) * 4
        else:
            return None
        target = address + displacement
    elif arch == "x86_64" and raw:
        if raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f:
            width = 2
            flow = "UNCONDITIONAL_JUMP" if raw[0] == 0xeb else flow
        elif raw[0] == 0xe9:
            width, flow = 5, "UNCONDITIONAL_JUMP"
        elif len(raw) >= 2 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
            width = 6
        if width is None or len(raw) < width:
            return None
        displacement = int.from_bytes(raw[width - (1 if width == 2 else 4):width], "little", signed=True)
        target = address + width + displacement
    else:
        return None
    return (width, target, flow) if 0 <= target < 1 << 64 else None


def wrapper(arch, address, raw):
    if arch == "arm64" and address % 4 == 0 and len(raw) >= 12:
        adrp, ldr, br = (int.from_bytes(raw[i:i + 4], "little") for i in (0, 4, 8))
        if adrp & 0x9f00001f != 0x90000010 or ldr & 0xffc003ff != 0xf9400210 or br != 0xd61f0200:
            return None
        page = _signed((adrp >> 29 & 3) | (adrp >> 5 & 0x7ffff) << 2, 21)
        slot = (address & ~0xfff) + page * 4096 + (ldr >> 10 & 0xfff) * 8
        widths = [4, 4, 4]
    elif arch == "x86_64" and len(raw) >= 6 and raw[:2] == b"\xff\x25":
        slot = address + 6 + int.from_bytes(raw[2:6], "little", signed=True)
        widths = [6]
    else:
        return None
    return (slot, widths) if 0 <= slot <= (1 << 64) - 8 else None


def safe_code(binary, parsed, address, size):
    if address < 0 or address + size > 1 << 64 or size < 1:
        return None
    if parsed["arch"] == "arm64" and address % 4:
        return None
    offset = metadata.mapped_location(parsed, address, size, from_file=False)
    sections = [s for s in parsed["sections"] if s["file_offset"] is not None
                and int(s["va"], 16) <= address and address + size <= int(s["va"], 16) + int(s["size"], 16)]
    if (offset is None or offset + size > len(binary) or len(sections) != 1
            or not sections[0]["protections"] & 4 or not int(sections[0]["flags"], 16) & 0x80000400):
        return None
    table = parsed["loader"].get("data_in_code")
    if table and (table["status"] != "complete" or any(
            int(r["slice_file_offset"], 16) < offset + size and offset < int(r["slice_file_offset"], 16) + r["length"]
            for r in table["records"])):
        return None
    crypt = parsed["loader"].get("encryption")
    if crypt and crypt["cryptid"] and int(crypt["slice_file_offset"], 16) < offset + size and offset < int(crypt["slice_file_offset"], 16) + int(crypt["size"], 16):
        return None
    return offset


def plan(binary, image, parsed, extent, payload):
    from . import import_links
    arch = parsed["arch"]
    result = {"policy": POLICY, "arch": arch, "candidates": [], "reason": None}
    if arch not in ("arm64", "x86_64"):
        raise ValueError("Unsupported classification architecture")
    start, end = int(extent["entry_va"], 16), int(extent["end_va_exclusive"], 16)
    if end - start != len(payload) or not 0 <= start < end <= 1 << 64:
        raise ValueError("Invalid classification extent")
    if len(payload) > MAX_SCAN_BYTES:
        return dict(result, reason="scan_byte_limit")
    bindings = {}
    for index in range(0, len(payload), 4 if arch == "arm64" else 1):
        address, raw = start + index, payload[index:index + 12]
        link, branch = wrapper(arch, address, raw), direct(arch, address, raw)
        if not link and not branch:
            continue
        if len(result["candidates"]) == MAX_CANDIDATES:
            return dict(result, candidates=[], reason="candidate_limit")
        widths = link[1] if link else [branch[0]]
        size = sum(widths)
        instructions, cursor = [], 0
        for width in widths:
            instructions.append({"va": hex(address + cursor), "bytes": raw[cursor:cursor + width].hex()})
            cursor += width
        source = instructions[-1]
        row = {"source_va": source["va"], "source_bytes": source["bytes"], "instructions": instructions,
               "kind": "unclassified", "reason": "source_code_unverified"}
        result["candidates"].append(row)
        offset = safe_code(binary, parsed, address, size)
        if offset is None or binary[offset:offset + size] != raw[:size]:
            continue
        if branch:
            width = 4 if arch == "arm64" else 1
            offset = safe_code(binary, parsed, branch[1], width)
            row["reason"] = "target_code_unverified"
            if offset is not None:
                row.update(kind="unresolved_internal_transfer", reason="same_image_direct_branch",
                           target_va=hex(branch[1]), target_bytes=binary[offset:offset + width].hex())
            continue
        slot = link[0]
        if slot not in bindings:
            if len(bindings) == MAX_BIND_SLOTS:
                return dict(result, candidates=[], reason="binding_slot_limit")
            try:
                _, rows, gaps = dyld.fixups(binary, image, parsed=parsed, address=slot)
            except Error:
                rows, gaps = [], ["unavailable"]
            offset = metadata.mapped_location(parsed, slot, 8, from_file=False)
            matching = [r for r in rows if r.get("kind") == "bind"]
            binding = matching[0] if not gaps and len(rows) == len(matching) == 1 else None
            if offset is None or offset + 8 > len(binary) or binding is None or not import_links.strong_bind(parsed, binding, offset):
                binding = None
            bindings[slot] = binding
        row["reason"] = "binding_unverified"
        if bindings[slot] is not None:
            row.update(kind="verified_linkage_boundary", reason="ordinary_import_pointer_sequence",
                       bind_va=hex(slot), binding=bindings[slot])
    if len(canonical(result)) + 1 > MAX_REQUEST_BYTES:
        return dict(result, candidates=[], reason="request_byte_limit")
    validate_plan(result)
    return result


def _address(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-f]+", value) or not 0 <= int(value, 16) < 1 << 64:
        raise ValueError("Invalid proof address")
    return int(value, 16)


def _bytes(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", value):
        raise ValueError("Invalid proof bytes")
    return bytes.fromhex(value)


def validate_plan(value):
    """Validate bounded JSON and byte-derived fields; replay also recomputes plan."""
    try:
        return _validate_plan(value)
    except (KeyError, TypeError, AttributeError, OverflowError, RecursionError) as error:
        raise ValueError("Malformed flow classification plan") from error


def _validate_plan(value):
    if (not isinstance(value, dict) or set(value) != {"policy", "arch", "candidates", "reason"}
            or value["policy"] != POLICY or value["arch"] not in ("arm64", "x86_64")
            or value["reason"] not in (None, "scan_byte_limit", "candidate_limit", "binding_slot_limit", "request_byte_limit")
            or not isinstance(value["candidates"], list) or len(value["candidates"]) > MAX_CANDIDATES
            or value["reason"] is not None and value["candidates"] or len(canonical(value)) + 1 > MAX_REQUEST_BYTES):
        raise ValueError("Invalid flow classification plan")
    seen = set()
    for row in value["candidates"]:
        base = {"source_va", "source_bytes", "instructions", "kind", "reason"}
        kind = row.get("kind") if isinstance(row, dict) else None
        extra = {"bind_va", "binding"} if kind == "verified_linkage_boundary" else {"target_va", "target_bytes"} if kind == "unresolved_internal_transfer" else set()
        if kind not in KINDS or set(row) != base | extra or not isinstance(row["instructions"], list) or not 1 <= len(row["instructions"]) <= 3:
            raise ValueError("Invalid classification candidate")
        site = _address(row["source_va"])
        if site in seen:
            raise ValueError("Duplicate classification site")
        seen.add(site)
        raw, first, end = b"", None, None
        for instruction in row["instructions"]:
            if not isinstance(instruction, dict) or set(instruction) != {"va", "bytes"}:
                raise ValueError("Invalid proof instruction")
            va, code = _address(instruction["va"]), _bytes(instruction["bytes"])
            if end is not None and va != end:
                raise ValueError("Noncontiguous proof sequence")
            first = va if first is None else first
            end, raw = va + len(code), raw + code
        if row["instructions"][-1] != {"va": row["source_va"], "bytes": row["source_bytes"]}:
            raise ValueError("Proof terminal mismatch")
        link, branch = wrapper(value["arch"], first, raw), direct(value["arch"], first, raw)
        if not link and not branch or len(raw) != (sum(link[1]) if link else branch[0]):
            raise ValueError("Unsupported proof sequence")
        if kind == "verified_linkage_boundary":
            if not link or _address(row["bind_va"]) != link[0] or not isinstance(row["binding"], dict) or row["reason"] != "ordinary_import_pointer_sequence":
                raise ValueError("Invalid linkage proof")
            binding = row["binding"]
            # Dyld evidence is flat metadata; do not admit arbitrary nested JSON,
            # unresolved/weak/authenticated or display-name-only binding claims.
            if (len(binding) > 32 or any(not isinstance(k, str) or len(k) > 128
                    or type(v) not in (str, int, bool, type(None))
                    or isinstance(v, str) and len(v) > 4096 for k, v in binding.items())
                    or binding.get("kind") != "bind" or binding.get("resolution") != "declared_symbol"
                    or binding.get("weak_import") is not False or binding.get("authenticated", False) is not False
                    or binding.get("stream") == "weak_bind" or binding.get("import_addend") != 0
                    or binding.get("inline_addend", 0) != 0
                    or type(binding.get("library_ordinal")) is not int or binding["library_ordinal"] < 1
                    or not isinstance(binding.get("library"), str) or not binding["library"]
                    or not isinstance(binding.get("symbol"), str) or not binding["symbol"]
                    or not binding["symbol"].isascii() or not binding["symbol"].isprintable()
                    or "\\" in binding["symbol"]):
                raise ValueError("Invalid declared binding proof")
            _address(binding.get("slice_file_offset"))
        elif kind == "unresolved_internal_transfer":
            if not branch or len(row["instructions"]) != 1 or _address(row["target_va"]) != branch[1] or len(_bytes(row["target_bytes"])) != (4 if value["arch"] == "arm64" else 1) or row["reason"] != "same_image_direct_branch":
                raise ValueError("Invalid internal proof")
        elif row["reason"] not in ("source_code_unverified", "target_code_unverified", "binding_unverified"):
            raise ValueError("Invalid unavailable proof reason")


def classification(function, gap, location, plan):
    from . import flow_gap_evidence
    validate_plan(plan)
    unknown = lambda reason: {"kind": "unclassified", "reason": reason}
    if plan["arch"] != function.get("arch"):
        raise ValueError("Classification architecture mismatch")
    if location.get("kind") != "instruction":
        return unknown("exact_source_unavailable")
    flow_gap_evidence.validate_sources(function)
    indexed, reason = flow_gap_evidence.instruction_index(function)
    if reason:
        return unknown(reason)
    site = _address(location["instruction_va"])
    instruction = indexed.get(site)
    if instruction is None or location != flow_gap_evidence.exact(instruction, function):
        raise ValueError("Classification location differs from captured instruction")
    for row in plan["candidates"]:
        if row["source_va"] != location["instruction_va"]:
            continue
        if any(indexed.get(_address(r["va"]), {}).get("bytes") != r["bytes"] for r in row["instructions"]):
            return unknown("source_sequence_not_captured")
        if row["kind"] == "unclassified":
            return unknown(row["reason"])
        if row["kind"] == "unresolved_internal_transfer":
            decoded = direct(plan["arch"], site, bytes.fromhex(row["source_bytes"]))
            if (gap.get("from") != row["source_va"] or gap.get("to") != row["target_va"]
                    or gap.get("flow") != decoded[2] or instruction["flow"] != decoded[2]):
                return unknown("gap_transfer_not_proven")
        else:
            outside_edge = gap.get("reason") == "focused_flow_outside_body"
            missing_destination = gap.get("reason") == "computed_jump_destination_unavailable"
            if (instruction["flow"] != "COMPUTED_JUMP" or not (outside_edge or missing_destination)
                    or outside_edge and (gap.get("from") != row["source_va"]
                                         or gap.get("flow") != "COMPUTED_JUMP" or gap.get("to") is None)):
                return unknown("gap_transfer_not_proven")
            blocks = function["blocks"]
            for facet, count in (("instructions", len(function["instructions"])), ("cfg", len(blocks)),
                                 ("body_ranges", len(function["body_ranges"]))):
                coverage = function.get("coverage", {}).get(facet, {})
                if (not isinstance(coverage, dict) or coverage.get("status") != "complete"
                        or coverage.get("emitted") != count or coverage.get("truncated") is not False
                        or coverage.get("error") is not None):
                    return unknown("wrapper_capture_incomplete")
            if any(function.get(key) for key in ("instructions_truncated", "instructions_error", "blocks_truncated",
                                                 "edges_truncated", "cfg_error")):
                return unknown("wrapper_capture_incomplete")
            first = _address(row["instructions"][0]["va"])
            terminal_blocks = [b for b in blocks if _address(b["min"]) <= first
                               and _address(b["max"]) == site + len(bytes.fromhex(row["source_bytes"])) - 1
                               and b["flow"] == "COMPUTED_JUMP"]
            if outside_edge:
                # The observed destination may be Ghidra's synthetic external
                # target. Correlate the raw gap with its captured edge only;
                # never interpret it as the pointer slot or a runtime callee.
                edge = {key: gap[key] for key in ("from", "to", "flow")}
                supporting = [b for b in terminal_blocks
                              if sum(all(e.get(key) == value for key, value in edge.items())
                                     for e in b["dsts"]) == 1]
                if len(terminal_blocks) != 1:
                    return unknown("wrapper_block_unverified")
            else:
                supporting = [b for b in terminal_blocks
                              if (b["min"], b["max"]) == (gap.get("block_min"), gap.get("block_max"))]
            if len(supporting) != 1 or supporting[0]["edges_truncated"] or any(b["edges_truncated"] for b in blocks):
                return unknown("wrapper_block_unverified")
            if any(indexed[_address(r["va"])]["flow"] != "FALL_THROUGH"
                   or indexed[_address(r["va"])].get("fallthrough") != hex(_address(r["va"]) + 4)
                   for r in row["instructions"][:-1]):
                return unknown("wrapper_fallthrough_unverified")
            if len(row["instructions"]) > 1:
                for other in indexed.values():
                    if ("JUMP" in other["flow"] and other["addr"] != row["source_va"]
                            and not any(e["from"] == other["addr"] and e["to"] is not None
                                        and "JUMP" in e["flow"] for b in blocks for e in b["dsts"])):
                        return unknown("wrapper_edge_destination_unverified")
            for block in blocks:
                if (len(row["instructions"]) > 1 and block is not supporting[0]
                        and "JUMP" in block["flow"]
                        and not any(e["to"] is not None and "JUMP" in e["flow"] for e in block["dsts"])):
                    return unknown("wrapper_edge_destination_unverified")
                for edge in block["dsts"]:
                    if edge["to"] is None:
                        if (len(row["instructions"]) > 1 and "JUMP" in edge["flow"]
                                and edge["from"] != row["source_va"]):
                            return unknown("wrapper_edge_destination_unverified")
                        continue
                    try:
                        destination = _address(edge["to"])
                    except ValueError:
                        # Captured CFG addresses may name EXTERNAL/non-RAM
                        # spaces. They are not proof of an absent interior edge.
                        return unknown("wrapper_edge_destination_unverified")
                    if first < destination <= site:
                        return unknown("wrapper_interior_entry")
        result = {"kind": row["kind"], "reason": row["reason"], "proof": row}
        if row["kind"] == "verified_linkage_boundary":
            result["runtime_target"] = "unresolved"
        return result
    return unknown(plan["reason"] or "source_proof_unavailable")
