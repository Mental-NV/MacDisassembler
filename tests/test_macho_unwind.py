"""Bounds, page formats and coverage for Mach-O compact unwind."""
import struct
import unittest
from unittest import mock

from macscope import macho_unwind
from macscope.errors import Error
from test_macho import image, segment_image


def compact_section():
    header = struct.pack("<7I", 1, 28, 1, 32, 1, 36, 3)
    arrays = struct.pack("<2I", 0x04000000, 0x180)
    index = struct.pack("<9I", 0x20, 80, 72, 0x40, 104, 80, 0x70, 0, 80)
    lsda = struct.pack("<II", 0x20, 0x90)
    regular = struct.pack("<IHHIIII", 2, 8, 2, 0x20, 0x54000000, 0x30, 0x82000000)
    compressed = struct.pack("<IHHHHIII", 3, 12, 2, 20, 1, 0, 0x01000010, 0x02000000)
    return header + arrays + index + lsda + regular + compressed


def containing_image(payload):
    binary = bytearray(segment_image(section_size=len(payload), section_address=0x1000000b8,
                                     segment_file_size=184 + len(payload))[:184])
    binary[104:120] = b"__unwind_info".ljust(16, b"\0")
    return bytes(binary) + payload


class UnwindTests(unittest.TestCase):
    def test_regular_and_compressed_pages_keep_declared_range_evidence(self):
        info, rows, gaps = macho_unwind.inventory(containing_image(compact_section()), 0x4000)
        self.assertEqual(gaps, [])
        self.assertEqual(info["compact_unwind"]["index_count"], 3)
        self.assertEqual([(r["rva"], r["end_rva"], r["page_kind"], r["mode"]) for r in rows], [
            ("0x20", "0x30", "regular", "frame"),
            ("0x30", "0x40", "regular", "frameless"),
            ("0x40", "0x50", "compressed", "frame"),
            ("0x50", "0x70", "compressed", "frameless"),
        ])
        self.assertEqual(rows[0]["personality_slot_rva"], "0x180")
        self.assertEqual(rows[0]["lsda_rva"], "0x90")
        self.assertEqual(rows[0]["container_file_offset"], "0x4020")
        self.assertTrue(rows[1]["not_function_start_flag"])
        self.assertEqual(rows[2]["encoding"], "0x4000000")
        self.assertEqual(rows[2]["entry_slice_file_offset"], hex(184 + 116))

    def test_malformed_arrays_indices_and_lsda_flags_fail(self):
        for offset, value in ((4, 36), (52, 80), (92, 0x64000000),
                              (96, 0x40), (116, 0xff000000)):
            with self.subTest(offset=offset):
                payload = bytearray(compact_section())
                struct.pack_into("<I", payload, offset, value)
                with self.assertRaises(Error) as caught:
                    macho_unwind.inventory(containing_image(payload), 0)
                self.assertEqual(caught.exception.code, "compact_unwind_malformed")

    def test_limits_and_future_page_kind_report_partial_data(self):
        data = containing_image(compact_section())
        with mock.patch.object(macho_unwind, "MAX_TABLE_ROWS", 2):
            _, rows, gaps = macho_unwind.inventory(data, 0)
        self.assertEqual(len(rows), 2)
        self.assertEqual(gaps, ["compact_unwind_row_limit"])
        payload = bytearray(compact_section())
        struct.pack_into("<I", payload, 104, 9)
        _, rows, gaps = macho_unwind.inventory(containing_image(payload), 0)
        self.assertEqual(len(rows), 2)
        self.assertEqual(gaps, ["compact_unwind_page_unsupported"])
        self.assertEqual(macho_unwind.inventory(image(), 0)[2], ["compact_unwind_unavailable"])
