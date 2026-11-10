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
    "warnings", "loader_evidence", "bundle_image", "loader",
)
VA = re.compile(r"0x[0-9a-fA-F]{1,16}")


def verified_slice(project, image):
    data = read_regular(project.path / "inputs" / (image["image_id"] + ".macho"))
    if hashlib.sha256(data).hexdigest() != image["sha256"]:
        raise Error("input_integrity", "Immutable slice digest differs from the imported image")
    return data


def headers(project, image):
    if "loader" not in image or "flags" not in image:
        image = dict(image, **thin(verified_slice(project,image)))
    return {key: image[key] for key in HEADER_FIELDS if key in image}


def loader_gaps(images):
    gaps = []
    for image in images:
        loader = image.get("loader", {})
        for name in ("function_starts","data_in_code"):
            record = loader.get(name)
            if record and record["status"] != "complete":
                gaps.append(f"{image['arch']} {name}: {record['status']}")
    return gaps


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
        if args.encoding != "auto":
            filters["encoding"] = args.encoding
            if any(row.get("encoding") is None for row in rows):
                gap = gap or "string_encodings_incomplete"
            rows = [row for row in rows if row.get("encoding") == args.encoding]
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


def hex_address(value, label):
    if not VA.fullmatch(value):
        raise Error("address", f"{label} must be a hexadecimal 64-bit value", 2)
    return int(value, 16)


def preferred_base(project, image, data=None):
    loader = image.get("loader", {})
    if "preferred_image_base" not in loader:
        loader = thin(verified_slice(project, image) if data is None else data)["loader"]
    value = loader["preferred_image_base"]
    return int(value, 16) if value is not None else None


def rva_to_va(rva, base):
    if base is None:
        raise Error("rva_base_unavailable", "The selected Mach-O has no unique preferred image base", 3)
    if base + rva >= 2**64:
        raise Error("address", "RVA exceeds the unslid 64-bit address space", 2)
    return base + rva


def map_section(sections, start, length, source, target):
    match = None
    end = start + length
    for section in sections:
        origin = section[source]
        if origin is None:
            continue
        lo, size = int(origin, 16), int(section["size"], 16)
        if not size or lo >= end or lo + size <= start:
            continue
        destination = section[target]
        if match is not None or destination is None or start < lo or end > lo + size:
            return None
        match = int(destination, 16) + start - lo
    return match


def mapped_location(image, start, length, *, from_file):
    source, target = ("file_offset", "va") if from_file else ("va", "file_offset")
    sections = image["sections"]
    mapped = map_section(sections, start, length, source, target)
    if mapped is not None and map_section(sections, mapped, length, target, source) == start:
        return mapped
    return None


def read_bytes_at(project, image, address, length, *, rva=None, file_offset=None):
    value, label = (file_offset, "Slice file offset") if file_offset is not None else (
        (rva, "RVA") if rva is not None else (address, "Unslid virtual address"))
    position = hex_address(value, label)
    data = verified_slice(project, image)
    base = preferred_base(project, image, data)
    if file_offset is not None:
        offset = position
        if offset + length > len(data):
            raise Error("bytes_unmapped", "File range exceeds the selected Mach-O slice", 2)
        start = mapped_location(image, offset, length, from_file=True)
    else:
        start = position if rva is None else rva_to_va(position, base)
        offset = mapped_location(image, start, length, from_file=False)
        if offset is None:
            raise Error("bytes_unmapped", "Byte range must fit one unambiguous file-backed Mach-O section", 2)
        if offset + length > len(data):
            raise Error("input_integrity", "Mapped range exceeds the imported slice")
    return {"image_id": image["image_id"], "arch": image["arch"],
            "address_space": "ram" if start is not None else None,
            "va": hex(start) if start is not None else None,
            "rva": hex(start - base) if start is not None and base is not None and start >= base else None,
            "slice_file_offset": hex(offset), "container_file_offset": hex(int(image["offset"], 16) + offset),
            "length": length, "bytes": data[offset:offset + length].hex()}
