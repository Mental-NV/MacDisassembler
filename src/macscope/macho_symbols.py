"""Read symbol declarations and their indirect table slots from a Mach-O slice."""
import struct

from .errors import Error
from .macho import thin
from .macho_load import MAX_TABLE_ROWS


NLIST = struct.Struct("<IBBHQ")
MAX_NAME = 4096
MAX_NAME_BYTES = 2 * 1024 * 1024
SYMBOL_KINDS = {0: "undefined", 2: "absolute", 0xa: "alias", 0xc: "prebound_undefined", 0xe: "section"}
SLOTS = {6: "non_lazy_pointer", 7: "lazy_pointer", 8: "stub", 0x10: "lazy_dylib_pointer", 0x14: "thread_local_pointer"}
MARKERS = {0x80000000: "local", 0x40000000: "absolute", 0xc0000000: "local_absolute"}


class SymbolLimit(ValueError):
    pass


class SymbolTable:
    def __init__(self, data, table, sections):
        self.data = data
        self.offset = int(table["slice_file_offset"], 16)
        self.count = table["count"]
        self.strings = int(table["strings_offset"], 16)
        self.end = self.strings + int(table["strings_size"], 16)
        self.sections = sections
        self.name_bytes = 0

    def name(self, index):
        if index == 0:
            return b""
        start = self.strings + index
        if start >= self.end:
            raise Error("symbol_table_malformed", "Symbol name index exceeds the declared string table")
        stop = self.data.find(b"\0", start, min(self.end, start + MAX_NAME + 1))
        if stop < 0:
            if self.end - start > MAX_NAME:
                raise SymbolLimit("symbol_name_limit")
            raise Error("symbol_table_malformed", "Symbol name is unterminated within the string table")
        self.name_bytes += stop - start
        if self.name_bytes > MAX_NAME_BYTES:
            raise SymbolLimit("symbol_name_budget")
        return self.data[start:stop]

    def read(self, index):
        offset = self.offset + index * NLIST.size
        string, kind_bits, section_index, description, value = NLIST.unpack_from(self.data, offset)
        name = self.name(string)
        external = bool(kind_bits & 1)
        kind = "debug" if kind_bits & 0xe0 else SYMBOL_KINDS.get(kind_bits & 0xe, "unknown")
        if kind == "undefined" and external and value:
            kind = "common"
        row = {"symbol_index": index, "name": name.decode("utf-8", "backslashreplace"), "name_hex": name.hex(),
               "kind": kind, "n_type": hex(kind_bits), "n_desc": hex(description),
               "raw_value": hex(value), "section_index": section_index, "is_external": external,
               "is_private_external": bool(kind_bits & 0x10), "entry_slice_file_offset": hex(offset)}
        if kind == "alias":
            target = self.name(value)
            row.update(alias_name=target.decode("utf-8", "backslashreplace"), alias_name_hex=target.hex())
        if kind == "section" and not 1 <= section_index <= len(self.sections):
            raise Error("symbol_table_malformed", "Defined symbol refers to an invalid section ordinal")
        return row


def location(va, section, base, container):
    offset = None
    if va is not None and section and section["file_offset"] is not None:
        delta = va - int(section["va"], 16)
        if 0 <= delta < int(section["size"], 16):
            offset = int(section["file_offset"], 16) + delta
    return {
        "va": hex(va) if va is not None else None, "address_space": "ram" if va is not None else None,
        "rva": hex(va - base) if va is not None and base is not None and va >= base else None,
        "segment": section["segment"] if section else None, "section": section["name"] if section else None,
        "slice_file_offset": hex(offset) if offset is not None else None,
        "container_file_offset": hex(container + offset) if offset is not None else None,
    }


def declared(table, base, container):
    if table is None:
        return [], ["symbol_table_unavailable"]
    rows, gaps = [], []
    try:
        for index in range(min(table.count, MAX_TABLE_ROWS)):
            row = table.read(index)
            defined = row["kind"] == "section"
            va = int(row["raw_value"], 16) if defined else None
            section = table.sections[row["section_index"] - 1] if defined else None
            rows.append(dict(row, **location(va, section, base, container)))
    except SymbolLimit as error:
        gaps.append(str(error))
    if table.count > MAX_TABLE_ROWS:
        gaps.append("symbol_row_limit")
    return rows, gaps


def slot_ranges(sections, table_count):
    ranges = []
    for section_index, section in enumerate(sections, 1):
        section_type = int(section["flags"], 16) & 0xff
        size = int(section["size"], 16)
        if section_type not in SLOTS or not size:
            continue
        stride = section["reserved2"] if section_type == 8 else 8
        start = section["reserved1"]
        if not stride or size % stride:
            raise Error("indirect_symbol_malformed", "Invalid stride or size in an indirect symbol section")
        end = start + size // stride
        if end > table_count:
            raise Error("indirect_symbol_malformed", "Indirect section exceeds its declared table")
        ranges.append((start, end, stride, section_index, section_type, section))
    ranges.sort(key=lambda item: item[0])
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        raise Error("indirect_symbol_malformed", "Indirect symbol sections claim overlapping table entries")
    return ranges


def indirect_entry(table, raw):
    if raw in MARKERS:
        return {"kind": MARKERS[raw], "symbol_index": None, "name": None}
    if table is None:
        return {"kind": "symbol_unavailable", "symbol_index": raw, "name": None}
    if raw >= table.count:
        raise Error("indirect_symbol_malformed", "Indirect entry references an out-of-range symbol index")
    symbol = table.read(raw)
    return {"kind": "symbol", "symbol_index": raw, "name": symbol["name"],
            "name_hex": symbol["name_hex"], "symbol_kind": symbol["kind"]}


def indirect(data, table, extent, sections, base, container):
    if extent is None:
        return [], ["indirect_symbol_table_unavailable"]
    ranges = slot_ranges(sections, extent["count"])
    offset = int(extent["slice_file_offset"], 16)
    rows, gaps = [], []
    mapped = sum(end - start for start, end, *_ in ranges)
    if mapped != extent["count"]:
        gaps.append("indirect_symbol_slots_unmapped")
    if mapped > MAX_TABLE_ROWS:
        gaps.append("indirect_symbol_row_limit")
    try:
        for start, end, stride, section_index, section_type, section in ranges:
            for index in range(start, min(end, start + MAX_TABLE_ROWS - len(rows))):
                at = offset + index * 4
                raw = struct.unpack_from("<I", data, at)[0]
                entry = indirect_entry(table, raw)
                if entry["kind"] == "symbol_unavailable" and "symbol_table_unavailable" not in gaps:
                    gaps.append("symbol_table_unavailable")
                va = int(section["va"], 16) + (index - start) * stride
                rows.append(dict(entry, **location(va, section, base, container),
                                 indirect_index=index, entry_slice_file_offset=hex(at),
                                 raw_entry=hex(raw), section_index=section_index,
                                 slot_kind=SLOTS[section_type], slot_size=stride))
    except SymbolLimit as error:
        gaps.append(str(error))
    return rows, gaps


def inventory(data, source, container):
    parsed = thin(data, include_section_linkage=source == "indirect")
    sections, loader = parsed["sections"], parsed["loader"]
    base = loader["preferred_image_base"]
    base = int(base, 16) if base is not None else None
    extent = loader.get("symbol_table")
    table = SymbolTable(data, extent, sections) if extent is not None else None
    if source == "indirect":
        return indirect(data, table, loader.get("indirect_symbol_table"), sections, base, container)
    return declared(table, base, container)
