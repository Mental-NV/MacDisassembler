"""Byte proofs for an exact decompilation from a saved no-analysis import."""

from hashlib import sha256

from . import flow_gap_classification, flow_gap_evidence, focused_boundaries, focused_tailcalls, macho_load, metadata
from .direct_signatures import arm64_direct_target
from .dispatch_returns import direct_target
from .errors import Error
from .macho import thin
from .pseudocode import VA, address_spans
from .schema import validate_envelope, validate_function


POLICY = "macscope-focused-import/3"
RESUMABLE_POLICIES = frozenset(("macscope-focused-import/2", POLICY))
MAX_BYTES = 8192
PROJECT_BACKUPS = frozenset(("image.rep/idata/~index.bak", "image.rep/idata/~journal.bak"))
RECEIPT_FACETS = {"pseudocode", "instructions", "body_ranges", "xrefs_from", "xrefs_to_entry"}


def select(project, image, entry, *, policy=POLICY):
    return extent(metadata.verified_slice(project, image), image, entry, policy=policy)


def extent(data, image, entry, *, policy=POLICY):
    if policy not in ("macscope-focused-import/1", *RESUMABLE_POLICIES):
        raise Error("focused_policy", "Unsupported recorded focused-query policy", 3)
    address = metadata.hex_address(entry, "Unslid function entry")
    parsed = thin(data, include_section_linkage=True)
    loader = parsed["loader"]
    extents = [(int(row["slice_file_offset"], 16), int(row["size"], 16))
               for row in loader["linkedit"] if row["kind"] == "function_starts"]
    text = [row for row in parsed["segments"] if row["name"] == "__TEXT" and row["file_offset"] == "0x0"]
    starts = macho_load.function_starts(data, extents, text[0] if len(text) == 1 else None, selected=address)
    if starts is None or starts["status"] != "complete":
        raise Error("focused_function_starts", "Exact selection requires a complete linker function-start stream", 3,
                    partial={"status": starts["status"] if starts else "absent",
                             "reason": starts.get("reason") if starts else None})
    if not starts["addresses"]:
        raise Error("focused_entry_missing", "The requested address is not a linker function start", 3)
    if len(starts["addresses"]) != 2:
        raise Error("focused_boundary_missing", "The selected entry has no next linker function start", 3)
    _, end = (int(value, 16) for value in starts["addresses"])
    size = end - address
    if size > MAX_BYTES:
        raise Error("focused_extent_limit", f"Selected linker extent exceeds {MAX_BYTES} bytes", 3)
    offset = metadata.mapped_location(parsed, address, size, from_file=False)
    sections = [row for row in parsed["sections"] if row["file_offset"] is not None
                and int(row["va"], 16) <= address and end <= int(row["va"], 16) + int(row["size"], 16)]
    if (offset is None or len(sections) != 1 or not sections[0]["protections"] & 4
            or not int(sections[0]["flags"], 16) & 0x80000400
            or parsed["arch"] == "arm64" and (address % 4 or size % 4)):
        raise Error("focused_extent_unmapped", "Selected linker extent must fit one executable instruction section", 3)
    table = loader.get("data_in_code")
    if table and (table["status"] != "complete" or any(
            overlaps(offset, size, row, row["length"]) for row in table["records"])):
        raise Error("focused_data_in_code", "Selected extent lacks complete evidence that it excludes embedded data", 3)
    encryption = loader.get("encryption")
    if encryption and encryption["cryptid"] and overlaps(offset, size, encryption, int(encryption["size"], 16)):
        raise Error("focused_encryption", "Selected extent overlaps encrypted bytes", 3)
    payload = data[offset:offset + size]
    proof = {"policy": policy, "entry_va": hex(address), "end_va_exclusive": hex(end),
             "slice_file_offset": hex(offset), "container_file_offset": hex(offset + int(image["offset"], 16)),
             "extent_sha256": sha256(payload).hexdigest(), "length": size}
    if policy in RESUMABLE_POLICIES:
        proof["tail_calls"] = focused_tailcalls.plan(data, image, parsed, proof, payload)
    if policy == POLICY:
        proof["flow_gap_classification"] = flow_gap_classification.plan(data, image, parsed, proof, payload)
    return proof, payload


def direct_calls(arch, function):
    """Decode call targets from a focused receipt whose instruction bytes were verified."""
    decode = arm64_direct_target if arch == "arm64" else direct_target
    for row in function["instructions"]:
        if row["flow"] == "CALL_TERMINATOR" and arch == "arm64":
            target = focused_tailcalls.verified_target(function, row)
            yield row, hex(target) if target is not None else None
            continue
        if row["flow"] != "UNCONDITIONAL_CALL":
            continue
        target = decode(int(row["addr"], 16), bytes.fromhex(row["bytes"]))
        yield row, hex(target) if target is not None and 0 <= target < 1 << 64 else None


def overlaps(offset, size, row, length):
    start = int(row["slice_file_offset"], 16)
    return offset < start + length and start < offset + size


def validate_result(result, proof):
    """Validate the focused receipt fields consumed by replay and call tracing."""
    try:
        validate_envelope(result)
        function = result["data"]
        validate_function(function)
        entry = proof["entry_va"]
        if (result["command"] != "decompile" or result["status"] not in ("complete", "partial")
                or result["analysis_id"] is not None or function.get("address_space") != "ram"
                or function["entry_va"] != entry or function.get("engine_entry") != entry
                or function.get("is_external") is not False or function.get("is_thunk") is not False
                or function.get("decompile_status") not in ("complete", "partial", "failed", "timeout", "cancelled")):
            raise ValueError("Invalid focused function identity or outcome")
        coverage = function.get("coverage")
        if (not isinstance(coverage, dict) or not RECEIPT_FACETS <= coverage.keys()
                or any(not isinstance(facet, dict) or not isinstance(facet.get("status"), str)
                       for facet in coverage.values())):
            raise ValueError("Invalid focused facet coverage")
        start, limit = int(entry, 16), int(proof["end_va_exclusive"], 16)
        ranges = function["body_ranges"]
        if not ranges or ranges[0][0] != entry:
            raise ValueError("Focused body does not start at the recorded entry")
        previous = start - 1
        for lo, hi in ranges:
            if (not VA.fullmatch(lo) or not VA.fullmatch(hi)
                    or not previous < int(lo, 16) <= int(hi, 16) < limit):
                raise ValueError("Invalid focused body range")
            previous = int(hi, 16)
        instructions = function.get("instructions")
        if (not isinstance(instructions, list) or not 1 <= len(instructions) <= MAX_BYTES
                or any(not isinstance(row, dict) or not isinstance(row.get("addr"), str)
                       or not VA.fullmatch(row["addr"]) or not isinstance(row.get("flow"), str)
                       or not isinstance(row.get("bytes"), str) for row in instructions)):
            raise ValueError("Invalid focused instruction records")
        for key in ("xrefs_to_entry", "xrefs_from_sample"):
            rows = function.get(key)
            if not isinstance(rows, list):
                raise ValueError("Invalid focused reference collection")
            for row in rows:
                if (not isinstance(row, dict) or not isinstance(row.get("from"), str)
                        or not isinstance(row.get("type"), str) or "to" not in row
                        or (row["to"] is not None and not isinstance(row["to"], str))
                        or (row.get("operand_index") is not None and type(row["operand_index"]) is not int)
                        or (row.get("source") is not None and not isinstance(row["source"], str))):
                    raise ValueError("Invalid focused reference record")
                if key == "xrefs_from_sample" and (not VA.fullmatch(row["from"])
                        or not start <= int(row["from"], 16) < limit):
                    raise ValueError("Focused outgoing reference starts outside the extent")
        address_spans(function, function["pseudocode"])
        if "tail_calls" in proof:
            verify_native_scope(function)
            focused_tailcalls.verify(proof["tail_calls"], function.get("tail_call_recovery"), function)
            if focused_boundaries.gaps(function, proof) and (result["status"] == "complete"
                    or function["decompile_status"] == "complete"):
                raise ValueError("Focused control flow is not confined to its body; capture a new query")
        flow_gap_evidence.validate(function, proof)
        if any(isinstance(gap, dict) and "evidence" in gap for gap in function.get("control_flow_gaps", ())):
            if result["status"] != "partial":
                raise ValueError("Control-flow gap evidence requires a partial result")
    except (KeyError, TypeError, ValueError) as error:
        raise Error("query_receipt", str(error), 3) from error


def verify(proof, payload, report, function):
    base = {key: proof[key] for key in ("entry_va", "end_va_exclusive", "extent_sha256")}
    if "tail_calls" in proof:
        base["tail_calls"] = report.get("tail_calls")
    if report != base:
        raise Error("focused_worker_proof", "Worker did not confirm the exact selected range digest", 10)
    verify_instructions(proof, payload, function)
    if "tail_calls" in proof:
        verify_native_scope(function)
        focused_tailcalls.verify(proof["tail_calls"], report.get("tail_calls"), function, annotate=True)


def verify_instructions(proof, payload, function):
    instructions = function.get("instructions")
    if not isinstance(instructions, list) or not instructions or function.get("entry_va") != proof["entry_va"]:
        raise Error("focused_instructions", "Worker did not publish instructions for the selected entry", 10)
    start = int(proof["entry_va"], 16)
    last_end = 0
    for index, row in enumerate(instructions):
        try:
            offset = int(row["addr"], 16) - start
            raw = bytes.fromhex(row["bytes"])
        except (KeyError, TypeError, ValueError) as error:
            raise Error("focused_instructions", "Worker published malformed instruction bytes", 10) from error
        end = offset + len(raw)
        if (not raw or raw.hex() != row["bytes"] or offset < last_end or index == 0 and offset != 0
                or end > len(payload) or payload[offset:end] != raw):
            raise Error("focused_instructions", "Worker instructions disagree with the selected file bytes", 10)
        last_end = end


def verify_native_scope(function):
    scope = function.get("native_scope")
    fields = {"policy", "status", "operations_scanned", "operations_truncated", "outside_body_operations",
              "outside_body_addresses", "error"}
    if (not isinstance(scope, dict) or set(scope) != fields
            or scope["policy"] != "macscope-focused-native-scope/1"
            or type(scope["operations_scanned"]) is not int or not 0 <= scope["operations_scanned"] <= 100000
            or type(scope["operations_truncated"]) is not bool
            or type(scope["outside_body_operations"]) is not int
            or not 0 <= scope["outside_body_operations"] <= scope["operations_scanned"]
            or not isinstance(scope["outside_body_addresses"], list)
            or len(scope["outside_body_addresses"]) > min(64, scope["outside_body_operations"])
            or (scope["error"] is not None and not isinstance(scope["error"], str))):
        raise Error("focused_native_scope", "Worker returned an invalid native operation scope", 10)
    status = ("unavailable" if scope["error"] is not None else
              "partial" if scope["operations_truncated"] or scope["outside_body_operations"] else "complete")
    seen = set()
    for value in scope["outside_body_addresses"]:
        if (not isinstance(value, str) or not VA.fullmatch(value) or value in seen
                or any(int(lo, 16) <= int(value, 16) <= int(hi, 16) for lo, hi in function["body_ranges"])):
            raise Error("focused_native_scope", "Native outside-body evidence disagrees with selected body", 10)
        seen.add(value)
    if scope["status"] != status or bool(seen) != bool(scope["outside_body_operations"]):
        raise Error("focused_native_scope", "Native operation scope has an inconsistent outcome", 10)
