"""Byte proofs for an exact decompilation from a saved no-analysis import."""

from hashlib import sha256

from . import macho_load, metadata
from .errors import Error
from .macho import thin


POLICY = "macscope-focused-import/1"
MAX_BYTES = 8192
PROJECT_BACKUPS = frozenset(("image.rep/idata/~index.bak", "image.rep/idata/~journal.bak"))


def select(project, image, entry):
    return extent(metadata.verified_slice(project, image), image, entry)


def extent(data, image, entry):
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
    proof = {"policy": POLICY, "entry_va": hex(address), "end_va_exclusive": hex(end),
             "slice_file_offset": hex(offset), "container_file_offset": hex(offset + int(image["offset"], 16)),
             "extent_sha256": sha256(payload).hexdigest(), "length": size}
    return proof, payload


def overlaps(offset, size, row, length):
    start = int(row["slice_file_offset"], 16)
    return offset < start + length and start < offset + size


def verify(proof, payload, report, function):
    if report != {key: proof[key] for key in ("entry_va", "end_va_exclusive", "extent_sha256")}:
        raise Error("focused_worker_proof", "Worker did not confirm the exact selected range digest", 10)
    verify_instructions(proof, payload, function)


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
