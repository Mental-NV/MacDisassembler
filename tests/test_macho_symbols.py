"""Bounded tests for declared Mach-O symbols and indirect slots."""
import struct
import unittest
from unittest import mock

from macscope import macho_symbols
from macscope.errors import Error
from test_macho import command, image


BASE = 0x100000000
PAYLOAD = 32 + 72 + 2 * 80 + 24 + 80


def linked_image(*, stride=6, pointer_start=2, entries=(1, 0x80000000, 0x40000000, 0xc0000000),
                 undefined_name=8):
    strings = b"\0_owned\0_puts\0_limit\0_alias\0"
    records = b"".join(struct.pack("<IBBHQ", *row) for row in (
        (1, 0x0f, 1, 0, BASE + PAYLOAD),
        (undefined_name, 1, 0, 0x100, 0),
        (14, 3, 0, 0, 42),
        (21, 0x0b, 0, 0, 1),
    ))
    section_bytes = bytes(28)
    table = struct.pack("<4I", *entries)
    symbol_offset = PAYLOAD + len(section_bytes)
    string_offset = symbol_offset + len(records)
    table_offset = string_offset + len(strings)
    segment = struct.pack("<16s4Q4I", b"__TEXT", BASE, 4096, 0, table_offset+len(table), 7, 5, 2, 0)
    for name, delta, size, flags, reserved1, reserved2 in (
        (b"__stubs", 0, 12, 0x80000408, 0, stride),
        (b"__got", 12, 16, 6, pointer_start, 0),
    ):
        offset = PAYLOAD + delta
        segment += struct.pack("<16s16s2Q8I", name, b"__TEXT", BASE+offset, size,
                               offset, 0, 0, 0, flags, reserved1, reserved2, 0)
    symtab = command(2, struct.pack("<4I", symbol_offset, 4, string_offset, len(strings)))
    fields = [0] * 18
    fields[12:14] = [table_offset, len(entries)]
    dysymtab = command(0xb, struct.pack("<18I", *fields))
    return image(commands=[command(0x19, segment), symtab, dysymtab],
                 payload=section_bytes + records + strings + table)


class MachOSymbolTests(unittest.TestCase):
    def test_declared_kinds_keep_raw_values_and_alias_names(self):
        rows, gaps = macho_symbols.inventory(linked_image(), "macho", 0x4000)
        self.assertEqual(gaps, [])
        self.assertEqual([(r["name"], r["kind"]) for r in rows], [
            ("_owned", "section"), ("_puts", "undefined"), ("_limit", "absolute"), ("_alias", "alias"),
        ])
        self.assertEqual(rows[0]["va"], hex(BASE + PAYLOAD))
        self.assertEqual(rows[0]["container_file_offset"], hex(0x4000 + PAYLOAD))
        self.assertEqual(rows[2]["raw_value"], "0x2a")
        self.assertIsNone(rows[2]["va"])
        self.assertEqual(rows[3]["alias_name"], "_owned")
        self.assertIsNone(rows[3]["va"])

    def test_indirect_uses_stride_and_preserves_all_marker_values(self):
        rows, gaps = macho_symbols.inventory(linked_image(), "indirect", 0x4000)
        self.assertEqual(gaps, [])
        self.assertEqual([r["kind"] for r in rows], ["symbol", "local", "absolute", "local_absolute"])
        self.assertEqual([r["indirect_index"] for r in rows], [0, 1, 2, 3])
        self.assertEqual([r["slot_size"] for r in rows], [6, 6, 8, 8])
        self.assertEqual([r["rva"] for r in rows], [hex(PAYLOAD+i) for i in (0, 6, 12, 20)])
        self.assertEqual(rows[0]["name"], "_puts")
        self.assertEqual(rows[0]["symbol_kind"], "undefined")
        self.assertTrue(all(r["name"] is None and r["symbol_index"] is None for r in rows[1:]))

    def test_invalid_strides_overlapping_ranges_and_bad_indices_fail(self):
        cases = [
            (linked_image(stride=0), "indirect", "indirect_symbol_malformed"),
            (linked_image(pointer_start=1), "indirect", "indirect_symbol_malformed"),
            (linked_image(pointer_start=3), "indirect", "indirect_symbol_malformed"),
            (linked_image(entries=(4, 1, 1, 1)), "indirect", "indirect_symbol_malformed"),
            (linked_image(undefined_name=1000), "macho", "symbol_table_malformed"),
        ]
        for data, source, code in cases:
            with self.subTest(source=source, code=code), self.assertRaises(Error) as caught:
                macho_symbols.inventory(data, source, 0)
            self.assertEqual(caught.exception.code, code)

    def test_limits_and_absent_tables_report_explicit_gaps(self):
        with mock.patch.object(macho_symbols, "MAX_TABLE_ROWS", 1):
            for source, gap in (("macho", "symbol_row_limit"), ("indirect", "indirect_symbol_row_limit")):
                rows, gaps = macho_symbols.inventory(linked_image(), source, 0)
                self.assertEqual(len(rows), 1)
                self.assertEqual(gaps, [gap])
        self.assertEqual(macho_symbols.inventory(image(), "macho", 0), ([], ["symbol_table_unavailable"]))
