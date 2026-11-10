"""Call frame inventory retains bounded instructions and encoded pointers."""
import struct
import unittest
from unittest import mock

from macscope import eh_frame, macho_unwind
from macscope.errors import Error
from test_macho import image, segment_image


BASE = 0x100000000
OFFSET = 184


def section(*, dwarf64=False, fde_code=b"\x45\x0f\x02\x77\x08", cie_version=1,
            fde_encoding=0x10, reference=None):
    def record(payload):
        prefix = struct.pack("<IQ", 0xffffffff, len(payload)) if dwarf64 else struct.pack("<I", len(payload))
        return prefix + payload

    cie = record(bytes(4) + bytes([cie_version]) + b"zR\0\x01\x78\x10\x01" +
                 bytes([fde_encoding]) + b"\x0c\x07\x08\x90\x01")
    cie_pointer = len(cie) + (12 if dwarf64 else 4)
    pointer_va = BASE + OFFSET + cie_pointer + 4
    fde = record(struct.pack("<Iqq", cie_pointer if reference is None else reference,
                             BASE + 0x20 - pointer_va, 0x10) + b"\0" + fde_code)
    return cie + fde


def containing_image(payload):
    header = bytearray(segment_image(section_size=len(payload), section_address=BASE + OFFSET,
                                     segment_file_size=OFFSET + len(payload))[:OFFSET])
    header[104:120] = b"__eh_frame".ljust(16, b"\0")
    return bytes(header) + payload


def inventory(payload):
    return macho_unwind.inventory(containing_image(payload), 0x4000, source="dwarf")


class EhFrameTests(unittest.TestCase):
    def test_pc_relative_and_cfi_decode_in_both_record_length_formats(self):
        for dwarf64 in (False, True):
            with self.subTest(dwarf64=dwarf64):
                info, (cie, fde), gaps = inventory(section(dwarf64=dwarf64) + bytes(4))
                self.assertEqual(gaps, [])
                self.assertEqual(info["eh_frame"]["container_file_offset"], hex(0x4000 + OFFSET))
                self.assertEqual(cie["format"], "dwarf64" if dwarf64 else "dwarf32")
                self.assertEqual(cie["data_alignment"], "-0x8")
                self.assertEqual(cie["instructions"][0]["operands"], ["0x7", "0x8"])
                self.assertEqual(fde["cie_offset"], "0x0")
                self.assertEqual(fde["initial_location"]["va"], hex(BASE + 0x20))
                self.assertEqual((fde["rva"], fde["end_rva"]), ("0x20", "0x30"))
                self.assertEqual(fde["container_file_offset"], "0x4020")
                self.assertEqual([i["opcode"] for i in fde["instructions"]],
                                 ["DW_CFA_advance_loc", "DW_CFA_def_cfa_expression"])
                self.assertEqual(fde["instructions"][1]["expression_hex"], "7708")

    def test_indirect_fde_keeps_slot_and_unresolved_range(self):
        _, (_, row), gaps = inventory(section(fde_encoding=0x90))
        self.assertEqual(row["initial_location"]["slot_va"], hex(BASE + 0x20))
        self.assertIsNone(row["va"])
        self.assertEqual(gaps, ["eh_frame_fde_address_unresolved"])

    def test_unknown_fields_and_instruction_limits_are_partial(self):
        _, (_, fde), gaps = inventory(section(fde_code=b"\x45\x2d\0"))
        self.assertEqual([r["opcode"] for r in fde["instructions"]], ["DW_CFA_advance_loc"])
        self.assertIn("unparsed_instruction_offset", fde)
        self.assertEqual(gaps, ["eh_frame_cfi_opcode_unsupported"])
        _, (cie, fde), gaps = inventory(section(cie_version=2))
        self.assertEqual((cie["status"], fde["status"]), ("partial", "partial"))
        self.assertIn("eh_frame_fde_cie_unsupported", gaps)
        with mock.patch.object(eh_frame, "MAX_TOTAL_OPS", 1):
            _, (cie, fde), gaps = inventory(section())
        self.assertEqual(len(cie["instructions"]), 1)
        self.assertEqual(fde["instructions"], [])
        self.assertEqual(gaps, ["eh_frame_cfi_instruction_limit"])

    def test_malformed_length_reference_and_instruction_fail(self):
        for payload in (section()[:-1], section(reference=1), section(fde_code=b"\x0c\x01"),
                        section() + bytes(4) + b"\x01"):
            with self.subTest(payload=payload), self.assertRaises(Error) as caught:
                inventory(payload)
            self.assertEqual(caught.exception.code, "eh_frame_malformed")
        self.assertEqual(macho_unwind.inventory(image(), 0, source="dwarf")[2], ["eh_frame_unavailable"])
