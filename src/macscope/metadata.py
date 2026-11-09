"""Read-only queries over imported Mach-O metadata and saved engine facets."""
import hashlib
import re

from .errors import Error
from .macho import read_regular, thin


PREFLIGHT_LISTS = ("segments", "sections")
ENGINE_LISTS = ("imports", "exports", "symbols", "strings")
HEADER_FIELDS = (
    "image_id", "arch", "cpu_type", "cpu_subtype", "file_type", "flags", "uuid",
    "offset", "size", "sha256", "artifact_sha256", "input_name", "load_commands",
    "warnings", "loader_evidence", "bundle_image",
)
VA = re.compile(r"0x[0-9a-fA-F]{1,16}")


def verified_slice(project, image):
    data = read_regular(project.path / "inputs" / (image["image_id"] + ".macho"))
    if hashlib.sha256(data).hexdigest() != image["sha256"]:
        raise Error("input_integrity", "Immutable slice digest differs from the imported image")
    return data


def headers(project, image):
    if "flags" not in image:
        image = dict(image, **thin(verified_slice(project,image)))
    return {key: image[key] for key in HEADER_FIELDS if key in image}


def address_fields(row, image, origin):
    address = row.get("va", row.get("address"))
    va = address if address and VA.fullmatch(address) else None
    space = "ram" if va else address.partition(":")[0] if address and ":" in address else None
    return dict(row, image_id=image["image_id"], arch=image["arch"], origin=origin,
                engine_address=address, va=va, address_space=space)


def records(args, project, image, snapshot):
    command = args.command
    filters = {"collection": command}
    if command in PREFLIGHT_LISTS:
        raw = image[command] if command in image else thin(verified_slice(project,image))[command]
        gap = None
        origin = "macho_preflight"
    else:
        engine = snapshot["engine"]
        raw = engine.get(command, [])
        facet = engine.get("coverage", {}).get(command, {})
        complete = (facet.get("status") == "complete" and not facet.get("truncated")
                    and not facet.get("error") and facet.get("emitted") == len(raw))
        gap = None if complete else "engine_collection_incomplete"
        origin = "ghidra"
    if command == "strings":
        filters.update(contains=args.contains,min_length=args.min_length)
        if any(row.get("value_truncated") or row.get("value") is None for row in raw):
            gap = gap or "string_values_incomplete"
        rows = [row for row in raw if row["length_bytes"] >= args.min_length and
                (args.contains is None or args.contains in (row.get("value") or ""))]
    else:
        filters["name_contains"] = args.name_contains
        rows = [row for row in raw if args.name_contains is None
                or args.name_contains in (row.get("name") or "")]
    rows = [address_fields(row,image,origin) for row in rows]
    rows.sort(key=lambda row: (
        row["va"] is None, int(row["va"],16) if row["va"] else 0, row["engine_address"] or "",
        row.get("name") or "", row.get("namespace") or "", row.get("value") or "",
    ))
    return rows, filters, gap


def read_bytes_at(project, image, address, length):
    if not VA.fullmatch(address):
        raise Error("address", "Address must be an unslid hexadecimal VA", 2)
    start = int(address,16)
    ranges = [
        (int(section["va"],16), int(section["file_offset"],16))
        for section in image["sections"]
        if section["file_offset"] is not None and
        int(section["va"],16) <= start and start+length <= int(section["va"],16)+int(section["size"],16)
    ]
    if len(ranges) != 1:
        raise Error("bytes_unmapped", "Byte range must fit one file-backed Mach-O section", 2)
    va, file_offset = ranges[0]
    offset = file_offset + start - va
    data = verified_slice(project,image)
    if offset + length > len(data):
        raise Error("input_integrity", "Mapped range exceeds the imported slice")
    return {"image_id": image["image_id"], "arch": image["arch"], "address_space": "ram",
            "va": hex(start), "slice_file_offset": hex(offset),
            "container_file_offset": hex(int(image["offset"],16)+offset),
            "length": length, "bytes": data[offset:offset+length].hex()}
