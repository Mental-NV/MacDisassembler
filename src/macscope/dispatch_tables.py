"""Verify file-backed selector rows and indirect pointers from Mach-O fixups."""
from bisect import bisect_left

from .dyld import fixups


SG_READ_ONLY = 0x10  # mach-o/loader.h: segment becomes read-only after fixups.


class UnverifiedDispatch(ValueError):
    """The input does not prove a supported immutable table."""


def table_entries(binary, image, layout):
    """Read entries only after instruction evidence has bounded the table."""
    segments = {row["name"]: row for row in image["segments"]}
    format_info, rows, gaps = fixups(binary, {"offset": "0x0"}, parsed=image)
    if format_info["format"] != "chained" or gaps:
        raise UnverifiedDispatch("incomplete_dispatch_fixups")
    rebases = {int(row["va"], 16): row for row in rows}
    fixup_vas = sorted(rebases)
    starts = image["loader"]["function_starts"]
    if not starts or starts["status"] != "complete":
        raise UnverifiedDispatch("incomplete_dispatch_function_starts")
    entries = {int(va, 16) for va in starts["addresses"]}

    def file_offset(address, width):
        matches = [row for row in image["sections"] if row["file_offset"] is not None
                   and int(row["va"], 16) <= address
                   and address + width <= int(row["va"], 16) + int(row["size"], 16)]
        if len(matches) != 1:
            raise UnverifiedDispatch("dispatch_slot_outside_section")
        section = matches[0]
        segment = segments[section["segment"]]
        if not int(segment["flags"], 16) & SG_READ_ONLY or segment["protections"] & 4:
            raise UnverifiedDispatch("mutable_dispatch_table")
        offset = int(section["file_offset"], 16) + address - int(section["va"], 16)
        segment_offset = int(segment["file_offset"], 16)
        if (offset != segment_offset + address - int(segment["va"], 16)
                or not segment_offset <= offset <= min(len(binary), segment_offset +
                                                       int(segment["file_size"], 16)) - width):
            raise UnverifiedDispatch("dispatch_slot_outside_file")
        return offset

    def check_fixup_overlap(address, width, expected=None):
        index = bisect_left(fixup_vas, address - 7)
        while index < len(fixup_vas) and fixup_vas[index] < address + width:
            if fixup_vas[index] != expected:
                raise UnverifiedDispatch("overlapping_dispatch_fixup")
            index += 1

    def pointer(address):
        offset = file_offset(address, 8)
        check_fixup_overlap(address, 8, expected=address)
        row = rebases.get(address, {})
        if (address % 8 or row.get("kind") != "rebase"
                or row.get("pointer_format") not in ("DYLD_CHAINED_PTR_64", "DYLD_CHAINED_PTR_64_OFFSET")
                or row.get("high8") != "0x0" or int(row["slice_file_offset"], 16) != offset):
            raise UnverifiedDispatch("unverified_dispatch_rebase")
        return int(row["target_va"], 16)

    base, stride, count, field = (layout[key] for key in ("base_va", "stride", "count", "field"))
    file_offset(base, stride * count)
    slots = []
    for index in range(count):
        slot = base + index * stride
        if layout["kind"] == "masked":
            if not layout["mask"] & (1 << index):
                continue
            row = pointer(slot)
        else:
            row = slot
        check_fixup_overlap(row, 1)
        tag = binary[file_offset(row, field + 8)]
        if layout["kind"] == "masked" and tag != ((layout["bias"] + index) & 0xff):
            raise UnverifiedDispatch("dispatch_selector_disagrees_with_row")
        target = pointer(row + field)
        if target not in entries:
            raise UnverifiedDispatch("dispatch_target_not_linker_function")
        slots.append({"index": index, "tag": tag, "slot_va": hex(slot), "row_va": hex(row),
                      "pointer_va": hex(row + field), "target_va": hex(target)})
    return slots
