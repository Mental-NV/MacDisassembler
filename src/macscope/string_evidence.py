"""File bytes and exact incoming references for saved string records."""
from collections import defaultdict
from hashlib import sha256

from . import address_xrefs, metadata

MAX_BYTES = 16 * 1024
MAX_XREFS = 32


def omit_redacted_bytes(row, redact):
    value = row.get("value")
    if value is None or redact(value) == value:
        return row
    safe = dict(row, bytes_redacted=True)
    safe.pop("bytes_sha256", None)
    return safe


def file_offset(image, start, length):
    # Header strings can be file-backed without belonging to a section.
    if any(int(section["va"], 16) < start + length
           and int(section["va"], 16) + int(section["size"], 16) > start
           for section in image["sections"] if int(section["size"], 16)):
        return metadata.mapped_location(image, start, length, from_file=False)
    segments = [dict(s, size=s["file_size"]) for s in image.get("segments", ())]
    return metadata.mapped_location({"sections": segments}, start, length, from_file=False)


def add_bytes(row, image, base, data):
    start = int(row["va"], 16) if row["va"] is not None else None
    length = row["length_bytes"]
    row.update(encoding=row.get("encoding"), bytes=None, rva=None,
               slice_file_offset=None, container_file_offset=None)
    if start is None or base is None:
        row["bytes_status"] = "location_unavailable"
        return
    if start >= base:
        row["rva"] = hex(start - base)
    offset = file_offset(image, start, length) if length > 0 else None
    if offset is None:
        row["bytes_status"] = "file_range_unavailable"
        return
    row["slice_file_offset"] = hex(offset)
    row["container_file_offset"] = hex(int(image["offset"], 16) + offset)
    if row.get("bytes_redacted"):
        row["bytes_status"] = "redacted"
    elif data is None or not row.get("bytes_sha256") or length > MAX_BYTES:
        row["bytes_status"] = "string_byte_evidence_unavailable"
    else:
        original = data[offset:offset + length]
        if len(original) != length or sha256(original).hexdigest() != row["bytes_sha256"]:
            row["bytes_status"] = "file_bytes_differ_from_program"
        else:
            row.update(bytes=original.hex(), bytes_status="verified_slice")


def enrich_page(project, image, snapshot, rows):
    if not rows:
        return
    data = (metadata.verified_slice(project, image)
            if any(row.get("bytes_sha256") for row in rows) else None)
    preferred = image.get("loader", {}).get("preferred_image_base")
    engine = snapshot["engine"]
    base = int(preferred, 16) if preferred is not None else None
    engine_base = engine.get("image_base")
    if engine_base is None or int(engine_base, 16) != base:
        base = None
    targets = {row["engine_address"] for row in rows if row["va"] is not None}
    references = defaultdict(list)
    for ref in engine.get(address_xrefs.REFERENCES, ()):
        if ref["to"] in targets:
            references[ref["to"]].append(ref)
    complete = (address_xrefs.complete(engine, address_xrefs.REFERENCES)
                and not engine.get("analysis_timed_out"))
    for row in rows:
        add_bytes(row, image, base, data)
        incoming = references[row["engine_address"]]
        row["xrefs_to_start"] = incoming[:MAX_XREFS]
        row["xrefs_status"] = ("unavailable" if row["va"] is None or address_xrefs.REFERENCES not in engine
                               else "complete" if complete and len(incoming) <= MAX_XREFS else "partial")
