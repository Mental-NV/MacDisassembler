"""Decode supported dyld fixups from immutable Mach-O bytes."""
import struct

from .errors import Error
from .dyld_legacy import decode_legacy, library_for_ordinal
from .macho import thin
from .macho_load import bounded


MAX_FIXUPS = 10000
MAX_PAGE_RECORDS = 262144
POINTER_FORMATS = {2: "DYLD_CHAINED_PTR_64", 6: "DYLD_CHAINED_PTR_64_OFFSET"}
IMPORT_WIDTHS = {1: 4, 2: 8, 3: 16}


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
    name_start = payload+symbols+name_offset
    name_end = data.find(b"\0",name_start,min(end,name_start+4097))
    if name_end <= name_start:
        raise Error("fixup_symbol", "Chained import symbol is missing or oversized")
    return {"symbol": data[name_start:name_end].decode("utf-8","backslashreplace"),
            "library_ordinal": ordinal,
            "library": library_for_ordinal(ordinal,libraries),
            "weak_import": bool(value >> width & 1), "import_addend": addend}


def segment_pages(data, payload, starts, starts_end, segments):
    bounded(starts,4,starts_end,"Chained segment count")
    count = struct.unpack_from("<I",data,payload+starts)[0]
    if count > len(segments):
        raise Error("fixup_segments", "Chained starts exceed the Mach-O segment table")
    table_end = starts+4+count*4
    bounded(starts+4,count*4,starts_end,"Chained segment offsets")
    for index in range(count):
        relative = struct.unpack_from("<I",data,payload+starts+4+index*4)[0]
        if not relative:
            continue
        at = starts+relative
        if at < table_end:
            raise Error("fixup_segments", "Chained segment data overlaps its offset table")
        bounded(at,22,starts_end,"Chained segment header")
        size,page_size,pointer_format,segment_offset,_,pages = struct.unpack_from("<IHHQIH",data,payload+at)
        bounded(at,size,starts_end,"Chained segment data")
        if size < 22+pages*2 or page_size not in (4096,16384):
            raise Error("fixup_pages", "Invalid chained page table")
        yield segments[index], pointer_format, segment_offset, page_size, pages, payload+at+22


def decode_chained(data, image, parsed, extent):
    payload,size = int(extent["slice_file_offset"],16),int(extent["size"],16)
    end = payload+size
    bounded(0,28,size,"Chained fixup header")
    version,starts,table,symbols,count,format_id,symbol_format = struct.unpack_from("<7I",data,payload)
    result = {"format": "chained", "version": version, "import_count": count,
              "imports_format": format_id, "symbols_format": symbol_format, "pointer_formats": []}
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
    starts_end = table
    if count==0 and table==symbols==0:
        starts_end = size
    elif not 28 <= starts < table <= symbols <= size:
        raise Error("fixup_layout", "Chained starts, imports or symbols overlap")
    else:
        bounded(table,count*IMPORT_WIDTHS[format_id],symbols,"Chained imports")
    if starts<28:
        raise Error("fixup_layout", "Chained starts overlap the header")
    libraries = [d["path"] for d in parsed["loader"]["dylibs"] if d["kind"]!="id"]
    imports = {}
    formats = set()
    pages_seen = 0
    seen_addresses = set()
    for segment,kind,segment_offset,page_size,pages,page_table in segment_pages(
            data,payload,starts,starts_end,parsed["segments"]):
        formats.add(kind)
        if kind not in POINTER_FORMATS:
            unsupported.append(f"pointer_format_{kind}")
            continue
        segment_va = int(segment["va"],16)
        file_offset = segment["file_offset"]
        if segment_va-base!=segment_offset or file_offset is None:
            raise Error("fixup_segments", "Chained starts disagree with the file-backed segment mapping")
        file_offset, file_size = int(file_offset,16), int(segment["file_size"],16)
        for page in range(pages):
            pages_seen += 1
            if pages_seen > MAX_PAGE_RECORDS:
                result["pointer_formats"] = sorted(formats)
                return result, records, [*unsupported,"page_limit"]
            first = struct.unpack_from("<H",data,page_table+page*2)[0]
            if first==0xFFFF:
                continue
            if first>=page_size or first%4:
                raise Error("fixup_pages", "Unsupported multi-start or invalid chained page offset")
            offset = page*page_size+first
            page_end = min((page+1)*page_size,file_size)
            while True:
                bounded(offset,8,page_end,"Chained pointer in file-backed page")
                if len(records)==MAX_FIXUPS:
                    result["pointer_formats"] = sorted(formats)
                    return result, records, [*unsupported,"fixup_limit"]
                va = segment_va+offset
                if va in seen_addresses:
                    raise Error("fixup_duplicate", "Multiple fixup chains describe the same address")
                seen_addresses.add(va)
                at = file_offset+offset
                value = struct.unpack_from("<Q",data,at)[0]
                row = {"address_space": "ram", "va": hex(va), "slice_file_offset": hex(at),
                       "container_file_offset": hex(int(image["offset"],16)+at),
                       "pointer_format": POINTER_FORMATS[kind], "raw": hex(value)}
                if value >> 63:
                    if value >> 32 & 0x7FFFF:
                        raise Error("fixup_pointer", "Reserved chained bind bits are set")
                    ordinal = value & 0xFFFFFF
                    if ordinal not in imports:
                        imports[ordinal] = import_symbol(data,payload,end,table,symbols,count,format_id,ordinal,libraries)
                    symbol = imports[ordinal]
                    row.update(kind="bind",inline_addend=(value>>24)&0xFF,target_va=None,
                               resolution="declared_symbol" if symbol["library"] else "unresolved_library_ordinal",
                               **symbol)
                else:
                    if value >> 44 & 0x7F:
                        raise Error("fixup_pointer", "Reserved chained rebase bits are set")
                    target = value & ((1<<36)-1)
                    high = value>>36&0xFF
                    decoded = base+target if kind==6 else target
                    if decoded >= 1<<56:
                        raise Error("fixup_pointer", "Chained target exceeds its address field")
                    row.update(kind="rebase",target_va=hex(decoded | high<<56),high8=hex(high))
                records.append(row)
                step = value>>51&0xFFF
                if not step:
                    break
                offset += step*4
    result["pointer_formats"] = sorted(formats)
    return result, records, sorted(set(unsupported))


def fixups(data, image):
    parsed = thin(data)
    loader = parsed["loader"]
    extents = [row for row in loader["linkedit"] if row["kind"]=="chained_fixups"]
    if len(extents)>1:
        raise Error("fixup_layout", "Ambiguous chained fixup payload")
    if extents:
        return decode_chained(data,image,parsed,extents[0])
    streams = [row for row in loader["dyld_streams"] if row["kind"]!="export_trie" and row["size"]!="0x0"]
    if streams:
        return decode_legacy(data,image,parsed,streams,MAX_FIXUPS)
    return {"format":"none"}, [], []
