"""Decode supported dyld fixups from immutable Mach-O bytes."""
import struct

from .chained_layout import (
    IMPORT_WIDTHS, MAX_PAGE_RECORDS, header, require_engine_layout, segment_pages, starts_region, symbol_bounds,
)
from .errors import Error
from .dyld_legacy import decode_legacy, library_for_ordinal
from .macho_load import bounded


MAX_FIXUPS = 10000
MAX_ENGINE_CHAINED_FIXUPS = 262144
MAX_LEGACY_LOOKUP_OPERATIONS = 262144
POINTER_FORMATS = {
    1: "DYLD_CHAINED_PTR_ARM64E",
    2: "DYLD_CHAINED_PTR_64",
    6: "DYLD_CHAINED_PTR_64_OFFSET",
    9: "DYLD_CHAINED_PTR_ARM64E_USERLAND",
    12: "DYLD_CHAINED_PTR_ARM64E_USERLAND24",
}
ARM64E_FORMATS = {1, 9, 12}
AUTH_KEYS = ("IA", "IB", "DA", "DB")


def import_symbol(data, payload, end, table, symbols, count, format_id, index, libraries):
    if index >= count:
        raise Error("fixup_ordinal", "Chained bind ordinal exceeds its import table")
    at = payload+table+index*IMPORT_WIDTHS[format_id]
    addend = 0
    if format_id == 3:
        value, addend = struct.unpack_from("<Qq",data,at)
        ordinal, width = value & 0xFFFF, 16
        if value >> 17 & 0x7FFF:
            raise Error("fixup_import", "Reserved chained import bits are set")
        name_offset = value >> 32
    else:
        value = struct.unpack_from("<I",data,at)[0]
        ordinal, width = value & 0xFF, 8
        name_offset = value >> 9
        if format_id == 2:
            addend = struct.unpack_from("<i",data,at+4)[0]
    if ordinal >= (1 << width)-15:
        ordinal -= 1 << width
    name_start, name_end = symbol_bounds(data, payload + symbols, end, name_offset)
    return {"symbol": data[name_start:name_end].decode("utf-8","backslashreplace"),
            "library_ordinal": ordinal,
            "library": library_for_ordinal(ordinal,libraries),
            "weak_import": bool(value >> width & 1), "import_addend": addend}


def rebase_target(target, high, base):
    decoded = base + target
    if decoded >= 1 << 56:
        raise Error("fixup_pointer", "Chained target exceeds its address field")
    return {"kind": "rebase", "target_va": hex(decoded | high << 56), "high8": hex(high)}


def arm64e_pointer(value, kind, base):
    authenticated = bool(value >> 63)
    bind = bool(value >> 62 & 1)
    if bind:
        ordinal_bits = 24 if kind == 12 else 16
        ordinal = value & ((1 << ordinal_bits) - 1)
        if (value & 0xFFFFFFFF) >> ordinal_bits:
            raise Error("fixup_pointer", "Reserved arm64e chained bind bits are set")
        addend = 0 if authenticated else value >> 32 & 0x7FFFF
        if addend >= 1 << 18:
            addend -= 1 << 19
        fields = {"kind": "bind", "ordinal": ordinal, "inline_addend": addend, "target_va": None}
    elif authenticated:
        fields = rebase_target(value & 0xFFFFFFFF, 0, base)
    else:
        fields = rebase_target(value & ((1 << 43) - 1), value >> 43 & 0xFF, 0 if kind == 1 else base)
    fields["authenticated"] = authenticated
    fields["authentication"] = ({
        "key": AUTH_KEYS[value >> 49 & 3], "address_diversity": bool(value >> 48 & 1),
        "diversity": value >> 32 & 0xFFFF,
    } if authenticated else None)
    return fields, (value >> 51 & 0x7FF) * 8


def ordinary_pointer(value, kind, base):
    if value >> 63:
        if value >> 32 & 0x7FFFF:
            raise Error("fixup_pointer", "Reserved chained bind bits are set")
        fields = {"kind": "bind", "ordinal": value & 0xFFFFFF,
                  "inline_addend": value >> 24 & 0xFF, "target_va": None}
    else:
        if value >> 44 & 0x7F:
            raise Error("fixup_pointer", "Reserved chained rebase bits are set")
        fields = rebase_target(value & ((1 << 36) - 1), value >> 36 & 0xFF, base if kind == 6 else 0)
    return fields, (value >> 51 & 0xFFF) * 4


def decode_chained(data, image, parsed, extent, *, address=None, selected=None, for_engine=False, whole_page=False):
    payload,size = int(extent["slice_file_offset"],16),int(extent["size"],16)
    end = payload+size
    version,starts,table,symbols,count,format_id,symbol_format = header(data, payload, size)
    result = {"format": "chained", "version": version, "import_count": count,
              "imports_format": format_id, "symbols_format": symbol_format, "pointer_formats": []}
    if whole_page:
        # Internal metadata lookup only. Engine admission and exact-slot queries
        # retain their existing scope and budgets.
        if address is None or selected is None or for_engine:
            raise ValueError("A chained page lookup requires one selected address")
        segment = parsed["segments"][selected]
        start = int(segment["va"],16)
        result["page_range"] = [hex(start),hex(start+int(segment["size"],16))]
    records = []
    unsupported = []
    for invalid, reason in ((version!=0,"fixup_version"),(format_id not in IMPORT_WIDTHS,"imports_format"),
                            (symbol_format!=0,"symbols_format")):
        if invalid:
            unsupported.append(reason)
    base = parsed["loader"]["preferred_image_base"]
    if base is None:
        unsupported.append("image_base")
    if unsupported:
        return result, records, unsupported
    base = int(base,16)
    starts_end = starts_region(size, starts, table, symbols, count, format_id)
    libraries = [d["path"] for d in parsed["loader"]["dylibs"] if d["kind"]!="id"]
    imports = {}
    formats = set()
    pages_seen = 0
    seen_addresses = set()
    limit = MAX_ENGINE_CHAINED_FIXUPS if for_engine else MAX_FIXUPS
    for segment,kind,segment_offset,page_size,pages,page_table in segment_pages(
            data,payload,starts,starts_end,parsed["segments"],selected=selected):
        formats.add(kind)
        if kind not in POINTER_FORMATS:
            unsupported.append(f"pointer_format_{kind}")
            continue
        arm64e = kind in ARM64E_FORMATS
        if arm64e and parsed["arch"] not in ("arm64", "arm64e"):
            raise Error("fixup_pointer", "An arm64e pointer format requires an ARM64 image")
        stride = 8 if arm64e else 4
        decode = arm64e_pointer if arm64e else ordinary_pointer
        segment_va = int(segment["va"],16)
        file_offset = segment["file_offset"]
        if segment_va-base!=segment_offset or file_offset is None:
            raise Error("fixup_segments", "Chained starts disagree with the file-backed segment mapping")
        file_offset, file_size = int(file_offset,16), int(segment["file_size"],16)
        selected_page = (address-segment_va)//page_size if address is not None else None
        if whole_page:
            start = segment_va+selected_page*page_size
            result["page_range"] = [hex(start),hex(min(start+page_size,segment_va+int(segment["size"],16)))]
        page_indices = range(pages) if selected_page is None else range(selected_page,min(selected_page+1,pages))
        for page in page_indices:
            pages_seen += 1
            if pages_seen > MAX_PAGE_RECORDS:
                result["pointer_formats"] = sorted(formats)
                return result, records, [*unsupported,"page_limit"]
            first = struct.unpack_from("<H",data,page_table+page*2)[0]
            if first==0xFFFF:
                continue
            if first>=page_size or first%stride:
                raise Error("fixup_pages", "Unsupported multi-start or invalid chained page offset")
            offset = page*page_size+first
            page_end = min((page+1)*page_size,file_size)
            while True:
                bounded(offset,8,page_end,"Chained pointer in file-backed page")
                if address is None and len(seen_addresses)==limit:
                    result["pointer_formats"] = sorted(formats)
                    return result, records, [*unsupported,"fixup_limit"]
                va = segment_va+offset
                if va in seen_addresses:
                    raise Error("fixup_duplicate", "Multiple fixup chains describe the same address")
                seen_addresses.add(va)
                at = file_offset+offset
                value = struct.unpack_from("<Q",data,at)[0]
                fields, step = decode(value,kind,base)
                if fields["kind"] == "bind":
                    ordinal = fields.pop("ordinal")
                    if ordinal not in imports:
                        imports[ordinal] = import_symbol(data,payload,end,table,symbols,count,format_id,ordinal,libraries)
                    symbol = imports[ordinal]
                    if for_engine and symbol["library"] is None:
                        raise Error("fixup_ordinal", "Unsupported special chained bind library ordinal")
                    fields.update(symbol, resolution=(
                        "declared_symbol" if symbol["library"] else "unresolved_library_ordinal"
                    ))
                if not for_engine and (address is None or va == address or whole_page):
                    records.append({"address_space": "ram", "va": hex(va), "slice_file_offset": hex(at),
                                    "container_file_offset": hex(int(image["offset"],16)+at),
                                    "pointer_format": POINTER_FORMATS[kind], "raw": hex(value), **fields})
                if not step:
                    break
                if for_engine and step < 8:
                    raise Error("fixup_pointer", "Chained pointer slots overlap")
                offset += step
    result["pointer_formats"] = sorted(formats)
    return result, records, sorted(set(unsupported))


def require_engine_chains(data, parsed):
    extent = require_engine_layout(data, parsed["loader"], parsed["segments"])
    if extent is None:
        return
    _, _, gaps = decode_chained(data, parsed, parsed, extent, for_engine=True)
    if "fixup_limit" in gaps or "page_limit" in gaps:
        raise Error("fixup_chain_limit", "Chained pointer traversal exceeds the engine admission limit", 7)
    if gaps:
        raise Error("fixup_pointer_unsupported", "Unsupported chained pointer layout: " + ", ".join(gaps), 3)


def slot_segment(parsed, address):
    end = address + 8
    overlaps = []
    for index, segment in enumerate(parsed["segments"]):
        start = int(segment["va"],16)
        limit = start + int(segment["size"],16)
        if start < end and address < limit and start < limit:
            overlaps.append((index,start,limit))
    if (len(overlaps) != 1 or not overlaps[0][1] <= address < end <= overlaps[0][2]
            or end > 1 << 64):
        raise Error("fixup_address_unmapped", "An exact fixup slot must fit one unambiguous Mach-O segment", 3)
    return overlaps[0][0]



def chained_page(data, image, parsed, address):
    """Validate and return a whole selected page, never an image-wide inventory.

    The returned half-open page_range is safe to cache only when gaps is empty
    and decoding completed without an exception. An absent segment-start record
    covers that segment; no chained relocations are declared there.
    """
    selected = slot_segment(parsed,address)
    extents = [row for row in parsed["loader"]["linkedit"] if row["kind"]=="chained_fixups"]
    if len(extents) != 1:
        raise Error("fixup_layout", "A page lookup requires one chained fixup payload")
    return decode_chained(data,image,parsed,extents[0],address=address,selected=selected,whole_page=True)


def fixups(data, image, *, parsed=None, weak_definitions=False, address=None):
    if parsed is None:
        from .macho import thin

        parsed = thin(data)
    if address is not None and weak_definitions:
        raise Error("fixup_address_scope", "Weak definitions are keyed by opcode offset rather than slot address", 2)
    selected = slot_segment(parsed,address) if address is not None else None
    loader = parsed["loader"]
    if not weak_definitions:
        extents = [row for row in loader["linkedit"] if row["kind"]=="chained_fixups"]
        if len(extents)>1:
            raise Error("fixup_layout", "Ambiguous chained fixup payload")
        if extents:
            return decode_chained(data,image,parsed,extents[0],address=address,selected=selected)
    streams = [row for row in loader["dyld_streams"] if row["kind"]!="export_trie" and row["size"]!="0x0"]
    if weak_definitions:
        streams = [row for row in streams if row["kind"] == "weak_bind"]
    if streams:
        limit = MAX_FIXUPS if address is None else MAX_LEGACY_LOOKUP_OPERATIONS
        return decode_legacy(data,image,parsed,streams,limit,weak_definitions=weak_definitions,address=address)
    return {"format":"none"}, [], []
