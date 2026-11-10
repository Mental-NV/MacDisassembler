"""Bounds shared by chained-fixup queries and headless input admission."""
import struct

from .errors import Error
from .macho_load import bounded


HEADER = struct.Struct("<7I")
IMPORT_WIDTHS = {1: 4, 2: 8, 3: 16}
MAX_PAGE_RECORDS = 262144
MAX_CHAINED_IMPORTS = 262144
MAX_ENGINE_SEGMENT_PAGES = 0x7FFF  # Ghidra 12.2 reads page_count as a signed short.


def header(data, payload, size):
    bounded(payload, size, len(data), "Chained fixup payload")
    bounded(0, HEADER.size, size, "Chained fixup header")
    return HEADER.unpack_from(data, payload)


def starts_region(size, starts, table, symbols, count, format_id):
    if starts < HEADER.size:
        raise Error("fixup_layout", "Chained starts overlap the header")
    if count == 0 and table == symbols == 0:
        return size
    if not starts < table <= symbols <= size:
        raise Error("fixup_layout", "Chained starts, imports or symbols overlap")
    bounded(table, count * IMPORT_WIDTHS[format_id], symbols, "Chained imports")
    return table


def symbol_bounds(data, symbols, end, name_offset):
    start = symbols + name_offset
    stop = data.find(b"\0", start, min(end, start + 4097))
    if stop <= start:
        raise Error("fixup_symbol", "Chained import symbol is missing or oversized")
    return start, stop


def segment_pages(data, payload, starts, starts_end, segments, *, selected=None):
    bounded(starts,4,starts_end,"Chained segment count")
    count = struct.unpack_from("<I",data,payload+starts)[0]
    if count > len(segments):
        raise Error("fixup_segments", "Chained starts exceed the Mach-O segment table")
    table_end = starts+4+count*4
    bounded(starts+4,count*4,starts_end,"Chained segment offsets")
    indices = range(count) if selected is None else range(selected, min(selected + 1, count))
    spans = []
    for index in indices:
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
        spans.append((at, at + size))
        yield segments[index], pointer_format, segment_offset, page_size, pages, payload+at+22
    ordered = sorted(spans)
    if any(end > start for (_, end), (start, _) in zip(ordered, ordered[1:])):
        raise Error("fixup_segments", "Chained segment records overlap")


def require_engine_layout(data, loader, segments):
    extents = [row for row in loader["linkedit"] if row["kind"] == "chained_fixups"]
    if not extents:
        return
    if len(extents) != 1:
        raise Error("fixup_layout", "Ambiguous chained fixup payload")
    extent, = extents
    payload, size = int(extent["slice_file_offset"], 16), int(extent["size"], 16)
    version, starts, table, symbols, count, format_id, symbol_format = header(data, payload, size)
    if version != 0 or format_id not in IMPORT_WIDTHS or symbol_format != 0:
        raise Error("fixup_header_unsupported",
                    "Engine admission requires version 0 chained fixups with supported imports and uncompressed symbols", 3)
    starts_end = starts_region(size, starts, table, symbols, count, format_id)
    if count > MAX_CHAINED_IMPORTS:
        raise Error("fixup_import_limit", "Chained import count exceeds the engine admission limit", 7)

    pages_seen = 0
    for _, _, _, _, pages, _ in segment_pages(data, payload, starts, starts_end, segments):
        pages_seen += pages
        if pages > MAX_ENGINE_SEGMENT_PAGES or pages_seen > MAX_PAGE_RECORDS:
            raise Error("fixup_page_limit", "Chained page count exceeds the engine admission limit", 7)

    width = IMPORT_WIDTHS[format_id]
    for at in range(payload + table, payload + table + count * width, width):
        name_offset = (struct.unpack_from("<I", data, at + 4)[0] if format_id == 3
                       else struct.unpack_from("<I", data, at)[0] >> 9)
        symbol_bounds(data, payload + symbols, payload + size, name_offset)
