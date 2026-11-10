"""Decode linked Mach-O compact unwind lookup records."""
import struct

from . import eh_frame as dwarf_frame
from .errors import Error
from .macho import thin
from .macho_load import MAX_TABLE_ROWS
from .macho_view import MappedImage


PAGE_SIZE = 4096
MAX_PAGES = 4096
MAX_SECTION_BYTES = 16 * 1024 * 1024
MODES = {
    "arm64": {2: "frameless", 3: "dwarf", 4: "frame", 5: "frame_pauth_lr"},
    "x86_64": {1: "rbp_frame", 2: "stack_immediate", 3: "stack_indirect", 4: "dwarf"},
}


def span(start, count, stride, lo, hi):
    end = start + count * stride
    if start < lo or end > hi or (count and start % 4):
        raise ValueError("Unwind array exceeds its bounds or is misaligned")
    return start, end


def disjoint(*spans):
    nonempty = sorted((start, end) for start, end in spans if start < end)
    if any(a[1] > b[0] for a, b in zip(nonempty, nonempty[1:])):
        raise ValueError("Overlapping unwind arrays")


def words(data, offset, count):
    return struct.unpack_from(f"<{count}I", data, offset)


def page_entries(data, start, end, first, common):
    span(start, 1, 4, 0, end)
    kind, = words(data, start, 1)
    if kind not in (2, 3):
        return None, []
    span(start, 1, 8, 0, end)
    kind, offset, count = struct.unpack_from("<IHH", data, start)
    if kind == 2:
        begin, stop = span(start + offset, count, 8, start + 8, end)
        return "regular", [(va, code, begin + index * 8) for index, (va, code) in
                           enumerate(struct.iter_unpack("<II", data[begin:stop]))]
    span(start, 1, 12, 0, end)
    local_offset, local_count = struct.unpack_from("<HH", data, start + 8)
    entries = span(start + offset, count, 4, start + 12, end)
    locals_ = span(start + local_offset, local_count, 4, start + 12 if local_count else start, end)
    disjoint(entries, locals_)
    if len(common) + local_count > 256:
        raise ValueError("Compressed unwind encoding table exceeds its index width")
    encodings = common + words(data, locals_[0], local_count)
    result = []
    for at in range(*entries, 4):
        word, = struct.unpack_from("<I", data, at)
        index = word >> 24
        if index >= len(encodings):
            raise ValueError("Compressed unwind entry has an invalid encoding index")
        result.append((first + (word & 0xffffff), encodings[index], at))
    return "compressed", result


def image_va(base, rva):
    if base is None:
        return None
    value = base + rva
    if value >= 2**64:
        raise ValueError("Unwind address exceeds the 64-bit image")
    return value


def optional_hex(value):
    return hex(value) if value is not None else None


def location(base, first, end, mapped, container):
    start_va, end_va = image_va(base, first), image_va(base, end)
    offset = None
    if start_va is not None:
        try:
            candidate, _, protections = mapped.mapping(start_va, 1)
            if protections & 4:
                offset = candidate
        except ValueError:
            pass
    return {"rva": hex(first), "end_rva": hex(end), "va": optional_hex(start_va),
            "end_va": optional_hex(end_va), "address_space": "ram" if start_va is not None else None,
            "slice_file_offset": optional_hex(offset),
            "container_file_offset": optional_hex(container + offset if offset is not None else None)}


def lsda_entries(data, lo, hi, first, end):
    result = {}
    previous = first - 1
    for func, lsda in struct.iter_unpack("<II", data[lo:hi]):
        if not previous < func < end or not lsda:
            raise ValueError("Invalid LSDA index entry")
        result[func] = lsda
        previous = func
    return result


def decode(binary, parsed, source, eh_frame, container):
    section_offset = int(source["slice_file_offset"], 16)
    length = int(source["size"], 16)
    data = memoryview(binary)[section_offset:section_offset + length]
    bounds = len(data)
    span(0, 1, 4, 0, bounds)
    version, = words(data, 0, 1)
    source["version"] = version
    if version != 1:
        return [], {"compact_unwind_version_unsupported"}
    span(0, 1, 28, 0, bounds)
    common_off, common_count, person_off, person_count, index_off, count = words(data, 4, 6)
    source.update(common_encoding_count=common_count, personality_count=person_count, index_count=count)
    if not count:
        raise ValueError("Missing compact unwind index sentinel")
    common_extent = span(common_off, common_count, 4, 28 if common_count else 0, bounds)
    person_extent = span(person_off, person_count, 4, 28 if person_count else 0, bounds)
    index_extent = span(index_off, count, 12, 28, bounds)
    if count > MAX_PAGES + 1 or common_count > 256 or person_count > 256:
        return [], {"compact_unwind_index_limit"}
    index = list(struct.iter_unpack("<III", data[slice(*index_extent)]))
    if index[-1][1] != 0 or any(a[0] >= b[0] or a[2] > b[2] for a, b in zip(index, index[1:])):
        raise ValueError("Invalid compact unwind top-level index or sentinel")
    pages = sorted(row[1] for row in index[:-1])
    if len(set(pages)) != len(pages):
        raise ValueError("Duplicate compact unwind page offset")
    page_bounds = dict(zip(pages, pages[1:] + [bounds]))
    prefix_end = pages[0] if pages else bounds
    lsda_lo, lsda_hi = index[0][2], index[-1][2]
    if any((row[2] - lsda_lo) % 8 for row in index):
        raise ValueError("Invalid compact unwind LSDA alignment")
    lsda_extent = span(lsda_lo, (lsda_hi - lsda_lo) // 8, 8, 28 if lsda_hi > lsda_lo else 0, prefix_end)
    prefix = ((0, 28), common_extent, person_extent, index_extent, lsda_extent)
    disjoint(*prefix)
    if any(start < end and end > prefix_end for start, end in prefix):
        raise ValueError("Compact unwind page overlaps the index or encoding arrays")
    if (lsda_hi - lsda_lo) // 8 > MAX_TABLE_ROWS:
        return [], {"compact_unwind_lsda_limit"}
    common = words(data, common_off, common_count)
    personalities = words(data, person_off, person_count)
    base = parsed["loader"]["preferred_image_base"]
    base = int(base, 16) if base is not None else None
    mapped = MappedImage(binary, parsed["segments"])
    rows, gaps = [], set()
    modes = MODES[parsed["arch"]]
    for (first, page, lsda), (end, _, next_lsda) in zip(index, index[1:]):
        page_kind, entries = page_entries(data, page, min(page + PAGE_SIZE, page_bounds[page]), first, common)
        if page_kind is None:
            gaps.add("compact_unwind_page_unsupported")
            continue
        starts = [entry[0] for entry in entries]
        if (not starts or starts[0] != first or starts[-1] >= end
                or any(a >= b for a, b in zip(starts, starts[1:]))):
            raise ValueError("Invalid compact unwind entry order or range")
        lsdas = lsda_entries(data, lsda, next_lsda, first, end)
        if set(lsdas) != {rva for rva, word, _ in entries if word & 0x40000000}:
            raise ValueError("Compact unwind LSDA flags disagree with the index")
        for (rva, word, at), limit in zip(entries, starts[1:] + [end]):
            if len(rows) == MAX_TABLE_ROWS:
                return rows, gaps | {"compact_unwind_row_limit"}
            personality = (word >> 28) & 3
            if personality > len(personalities):
                raise ValueError("Invalid compact unwind personality index")
            mode = modes.get((word >> 24) & 0xf, "unknown") if word else "no_recipe"
            fields = location(base, rva, limit, mapped, container)
            if fields["slice_file_offset"] is None:
                gaps.add("compact_unwind_address_unmapped")
            if mode == "unknown":
                gaps.add("compact_unwind_encoding_unknown")
            entry_offset = section_offset + at
            row = dict(fields, origin="macho_compact_unwind", page_kind=page_kind,
                       encoding=hex(word), mode=mode, not_function_start_flag=bool(word & 0x80000000),
                       personality_index=personality or None,
                       personality_slot_rva=hex(personalities[personality - 1]) if personality else None,
                       lsda_rva=optional_hex(lsdas.get(rva)), entry_slice_file_offset=hex(entry_offset),
                       entry_container_file_offset=hex(container + entry_offset))
            if mode == "dwarf":
                delta = word & 0xffffff
                row["dwarf_fde_offset"] = hex(delta)
                if eh_frame and delta + 4 <= int(eh_frame["size"], 16):
                    row["dwarf_fde_slice_file_offset"] = hex(int(eh_frame["slice_file_offset"], 16) + delta)
                else:
                    gaps.add("compact_unwind_dwarf_reference_unavailable")
            rows.append(row)
    return rows, gaps


def extent(parsed, name, container):
    sections = [s for s in parsed["sections"] if s["segment"] == "__TEXT" and s["name"] == name]
    if not sections:
        return None
    if len(sections) != 1 or sections[0]["file_offset"] is None:
        raise ValueError("Ambiguous or non-file-backed unwind section")
    section = sections[0]
    offset = int(section["file_offset"], 16)
    return {"va": section["va"], "slice_file_offset": hex(offset),
            "container_file_offset": hex(container + offset), "size": section["size"]}


def inventory(data, container, *, source="compact"):
    parsed = thin(data)
    try:
        compact = extent(parsed, "__unwind_info", container)
        eh_frame = extent(parsed, "__eh_frame", container)
        info = {"compact_unwind": compact, "eh_frame": eh_frame}
        if source == "dwarf":
            if eh_frame is None:
                return info, [], ["eh_frame_unavailable"]
            if int(eh_frame["size"], 16) > MAX_SECTION_BYTES:
                return info, [], ["eh_frame_byte_limit"]
            rows, issues = dwarf_frame.decode(data, parsed, eh_frame, container)
            return info, rows, sorted(issues)
        gaps = {"eh_frame_not_decoded"} if eh_frame else set()
        if compact is None:
            return info, [], sorted(gaps | {"compact_unwind_unavailable"})
        if int(compact["size"], 16) > MAX_SECTION_BYTES:
            return info, [], sorted(gaps | {"compact_unwind_byte_limit"})
        rows, issues = decode(data, parsed, compact, eh_frame, container)
        return info, rows, sorted(gaps | issues)
    except (ValueError, struct.error) as error:
        code = "eh_frame_malformed" if source == "dwarf" else "compact_unwind_malformed"
        raise Error(code, str(error)) from error
