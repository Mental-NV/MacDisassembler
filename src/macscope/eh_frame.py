"""Bounded inventory of linked DWARF call frame records and instructions."""
from typing import NamedTuple

from .macho_load import MAX_TABLE_ROWS, uleb
from .macho_view import MappedImage


MAX_PROGRAM_OPS = 1024
MAX_TOTAL_OPS = 20000
MAX_EXPRESSION = 4096
OMIT = 0xff
FORMATS = {2: (2, False), 3: (4, False), 4: (8, False),
           10: (2, True), 11: (4, True), 12: (8, True)}
OPCODES = {
    0x00: ("nop", ""), 0x01: ("set_loc", "p"),
    0x02: ("advance_loc1", "b"), 0x03: ("advance_loc2", "h"), 0x04: ("advance_loc4", "i"),
    0x05: ("offset_extended", "uu"), 0x06: ("restore_extended", "u"),
    0x07: ("undefined", "u"), 0x08: ("same_value", "u"), 0x09: ("register", "uu"),
    0x0a: ("remember_state", ""), 0x0b: ("restore_state", ""),
    0x0c: ("def_cfa", "uu"), 0x0d: ("def_cfa_register", "u"), 0x0e: ("def_cfa_offset", "u"),
    0x0f: ("def_cfa_expression", "e"), 0x10: ("expression", "ue"),
    0x11: ("offset_extended_sf", "us"), 0x12: ("def_cfa_sf", "us"),
    0x13: ("def_cfa_offset_sf", "s"), 0x14: ("val_offset", "uu"),
    0x15: ("val_offset_sf", "us"), 0x16: ("val_expression", "ue"),
    0x2e: ("GNU_args_size", "u"),
}
PRIMARY = {0x40: ("advance_loc", ""), 0x80: ("offset", "u"), 0xc0: ("restore", "")}
FIXED_OPERANDS = {"b": 1, "h": 2, "i": 4}


class Unsupported(ValueError):
    pass


class Cie(NamedTuple):
    address_size: int
    augmented: bool
    fde_encoding: int
    lsda_encoding: int


class Reader:
    def __init__(self, data, start, end, section_va):
        self.data, self.pos, self.end, self.section_va = data, start, end, section_va

    def take(self, size):
        at = self.pos
        if size > self.end - at:
            raise ValueError("Truncated .eh_frame field")
        self.pos += size
        return self.data[at:self.pos]

    def number(self, size, signed=False):
        return int.from_bytes(self.take(size), "little", signed=signed)

    def unsigned(self):
        value, self.pos = uleb(self.data, self.pos, self.end)
        return value

    def signed(self):
        value = 0
        for shift in range(0, 70, 7):
            byte = self.number(1)
            value |= (byte & 0x7f) << shift
            if byte < 0x80:
                if byte & 0x40:
                    value -= 1 << (shift + 7)
                if -(1 << 63) <= value < 1 << 63:
                    return value
                break
        raise ValueError("SLEB128 exceeds 64 bits")

    def augmentation_name(self):
        at = self.pos
        while self.pos - at < 64:
            if self.number(1) == 0:
                return bytes(self.data[at:self.pos - 1]).decode("ascii", "backslashreplace")
        raise Unsupported("eh_frame_augmentation_name_limit")

    def block(self):
        size = self.unsigned()
        start = self.pos
        self.take(size)
        return Reader(self.data, start, self.pos, self.section_va)

    def encoded_number(self, fmt, address_size):
        if fmt in (0, 8):
            return self.number(address_size, signed=fmt == 8)
        if fmt == 1:
            return self.unsigned()
        if fmt == 9:
            return self.signed()
        if fmt not in FORMATS:
            raise Unsupported("eh_frame_pointer_format_unsupported")
        return self.number(*FORMATS[fmt])

    def pointer(self, encoding, address_size, gaps):
        if encoding == OMIT:
            return None
        start = self.pos
        base = encoding & 0x70
        if base == 0x50:
            raise Unsupported("eh_frame_pointer_base_unsupported")
        fmt = encoding & 0xf
        # Apple's linked EH records use native-width two's complement PC offsets.
        raw = (self.number(address_size, signed=True) if base == 0x10 and fmt == 0
               else self.encoded_number(fmt, address_size))
        address = None
        if base in (0, 0x10):
            address = raw if base == 0 else self.section_va + start + raw
            if not 0 <= address < 2**64:
                raise ValueError(".eh_frame pointer exceeds the address space")
        else:
            gaps.add("eh_frame_pointer_base_unsupported")
        indirect = bool(encoding & 0x80)
        return {"encoding": hex(encoding), "raw": hex(raw), "indirect": indirect,
                "va": hex(address) if address is not None and not indirect else None,
                "slot_va": hex(address) if address is not None and indirect else None}


def read_cie(reader, row, gaps):
    version = reader.number(1)
    row["version"] = version
    if version not in (1, 3, 4):
        raise Unsupported("eh_frame_cie_version_unsupported")
    name = reader.augmentation_name()
    row["augmentation"] = name
    address_size = reader.number(1) if version == 4 else 8
    segment_size = reader.number(1) if version == 4 else 0
    if address_size not in (4, 8) or segment_size:
        raise Unsupported("eh_frame_cie_address_format_unsupported")
    code, data = reader.unsigned(), reader.signed()
    if code == 0:
        raise ValueError("Zero .eh_frame code alignment")
    register = reader.number(1) if version == 1 else reader.unsigned()
    row.update(address_size=address_size, code_alignment=hex(code), data_alignment=hex(data),
               return_address_register=hex(register))
    fde_encoding, lsda_encoding = 0, OMIT
    if name.startswith("z"):
        aug = reader.block()
        letters = name[1:]
        if len(set(letters)) != len(letters) or any(c not in "PLRS" for c in letters):
            raise Unsupported("eh_frame_cie_augmentation_unsupported")
        for char in letters:
            if char == "P":
                row["personality"] = aug.pointer(aug.number(1), address_size, gaps)
            elif char == "L":
                lsda_encoding = aug.number(1)
            elif char == "R":
                fde_encoding = aug.number(1)
            else:
                row["signal_frame"] = True
        if aug.pos != aug.end:
            raise ValueError(".eh_frame CIE augmentation length mismatch")
    elif name:
        raise Unsupported("eh_frame_cie_augmentation_unsupported")
    row.update(fde_pointer_encoding=hex(fde_encoding), lsda_pointer_encoding=hex(lsda_encoding))
    return Cie(address_size, name.startswith("z"), fde_encoding, lsda_encoding)


def read_fde(reader, row, cie, mapped, base, container, gaps):
    pointer = reader.pointer(cie.fde_encoding, cie.address_size, gaps)
    if pointer is None:
        raise Unsupported("eh_frame_fde_address_omitted")
    length = reader.encoded_number(cie.fde_encoding & 0xf, cie.address_size)
    if length < 0:
        raise ValueError("Negative .eh_frame code range")
    row.update(initial_location=pointer, range_size=hex(length), va=pointer["va"],
               end_va=None, rva=None, end_rva=None, address_space=None,
               slice_file_offset=None, container_file_offset=None)
    if pointer["va"] is None:
        gaps.add("eh_frame_fde_address_unresolved")
    else:
        start = int(pointer["va"], 16)
        end = start + length
        if end >= 2**64:
            raise ValueError(".eh_frame range exceeds the address space")
        row.update(end_va=hex(end), address_space="ram")
        if base is not None and start >= base:
            row.update(rva=hex(start - base), end_rva=hex(end - base))
        try:
            offset, _, protections = mapped.mapping(start, max(1, length))
            if protections & 4:
                row.update(slice_file_offset=hex(offset), container_file_offset=hex(container + offset))
        except ValueError:
            pass
        if row["slice_file_offset"] is None:
            gaps.add("eh_frame_fde_range_unmapped")
    if cie.augmented:
        aug = reader.block()
        if aug.pos < aug.end and cie.lsda_encoding != OMIT:
            row["lsda"] = aug.pointer(cie.lsda_encoding, cie.address_size, gaps)
        if aug.pos != aug.end:
            raise ValueError(".eh_frame FDE augmentation length mismatch")


def instructions(reader, cie, limit, gaps):
    result = []
    while reader.pos < reader.end and len(result) < limit:
        at = reader.pos
        opcode = reader.number(1)
        primary = opcode & 0xc0
        spec = PRIMARY[primary] if primary else OPCODES.get(opcode)
        if spec is None:
            gaps.add("eh_frame_cfi_opcode_unsupported")
            return result, at
        name, arguments = spec
        operands = [hex(opcode & 0x3f)] if primary else []
        row = {"section_offset": hex(at), "opcode": "DW_CFA_" + name, "operands": operands}
        try:
            for form in arguments:
                if form == "u":
                    operands.append(hex(reader.unsigned()))
                elif form == "s":
                    operands.append(hex(reader.signed()))
                elif form == "p":
                    row["location"] = reader.pointer(cie.fde_encoding, cie.address_size, gaps)
                elif form == "e":
                    size = reader.unsigned()
                    data = reader.take(size)
                    if size > MAX_EXPRESSION:
                        raise Unsupported("eh_frame_expression_limit")
                    row["expression_hex"] = data.hex()
                else:
                    operands.append(hex(reader.number(FIXED_OPERANDS[form])))
        except Unsupported as error:
            gaps.add(str(error))
            return result, at
        row["size_bytes"] = reader.pos - at
        result.append(row)
    if reader.pos < reader.end:
        gaps.add("eh_frame_cfi_instruction_limit")
        return result, reader.pos
    return result, None


def decode(binary, parsed, extent, container):
    section_offset, size, section_va = (int(extent[k], 16) for k in ("slice_file_offset", "size", "va"))
    data = memoryview(binary)[section_offset:section_offset + size]
    source = Reader(data, 0, size, section_va)
    base = parsed["loader"]["preferred_image_base"]
    base = int(base, 16) if base is not None else None
    mapped = MappedImage(binary, parsed["segments"])
    rows, cies, gaps = [], {}, set()
    budget = MAX_TOTAL_OPS
    while source.pos < source.end:
        if len(rows) == MAX_TABLE_ROWS:
            gaps.add("eh_frame_record_limit")
            break
        start = source.pos
        length = source.number(4)
        dwarf64 = length == 0xffffffff
        if dwarf64:
            length = source.number(8)
        elif length >= 0xfffffff0:
            raise ValueError("Reserved .eh_frame record length")
        if length == 0:
            if any(data[source.pos:]):
                raise ValueError("Nonzero bytes after .eh_frame terminator")
            break
        body = source.pos
        source.take(length)
        reader = Reader(data, body, source.pos, section_va)
        reference = reader.number(4)  # The linked .eh_frame CIE pointer is always four bytes.
        offset = section_offset + start
        row = {"kind": "fde" if reference else "cie", "origin": "macho_eh_frame",
               "format": "dwarf64" if dwarf64 else "dwarf32", "section_offset": hex(start),
               "entry_size": source.pos - start, "entry_slice_file_offset": hex(offset),
               "entry_container_file_offset": hex(container + offset), "instructions": []}
        issues = set()
        try:
            if reference:
                target = body - reference
                if target not in cies:
                    raise ValueError(".eh_frame FDE refers to an invalid CIE offset")
                row["cie_offset"] = hex(target)
                cie = cies[target]
                if cie is None:
                    raise Unsupported("eh_frame_fde_cie_unsupported")
                read_fde(reader, row, cie, mapped, base, container, issues)
            else:
                cies[start] = None
                cie = cies[start] = read_cie(reader, row, issues)
            program, unparsed = instructions(reader, cie, min(MAX_PROGRAM_OPS, budget), issues)
            budget -= len(program)
            row["instructions"] = program
            if unparsed is not None:
                row["unparsed_instruction_offset"] = hex(unparsed)
        except Unsupported as error:
            issues.add(str(error))
        row.update(status="partial" if issues else "complete", gaps=sorted(issues))
        gaps.update(issues)
        rows.append(row)
    return rows, gaps
