"""Exercise the data-reference oracle's independent address calculations."""
import unittest

from audit_core_data_references import compare, references


class DataReferenceTests(unittest.TestCase):
    def test_rip_reference_recomputes_llvm_target(self):
        raw = bytes.fromhex("488d05f9ffffff")
        expected, unsupported = references({
            0x1000: (raw, "leaq", "-0x7(%rip), %rax ## 0x1000 <sym>"),
        }, "x86_64")
        self.assertEqual(unsupported, [])
        self.assertEqual(expected[0]["target_va"], "0x1000")
        with self.assertRaisesRegex(ValueError, "RIP-relative target"):
            references({0x1000: (raw, "leaq", "-0x7(%rip), %rax ## 0x1001")}, "x86_64")

    def test_indexed_arm_reference_is_a_static_base(self):
        expected, unsupported = references({
            0x1000: (b"", "adrp", "x8, 0x4000 <sym>"),
            0x1004: (b"", "add", "x9, x8, #0x40"),
            0x1008: (b"", "add", "x9, x9, x2, lsl #4"),
            0x100c: (b"", "ldr", "x1, [x9, #0x8]"),
        }, "arm64")
        self.assertEqual(unsupported, [])
        self.assertEqual(expected, [{
            "entry_va": "0x100c", "target_va": "0x4048", "origin_instruction_va": "0x1000",
            "interpretation": "indexed_base",
        }])
        data = compare(expected, unsupported, None, [(0x4000, 0x5000, "__DATA,__const")])
        self.assertEqual(data["references"][0]["status"], "source_instruction_absent")

    def test_page_reference_does_not_scan_past_a_branch(self):
        expected, unsupported = references({
            0x1000: (b"", "adrp", "x8, 0x4000"),
            0x1004: (b"", "b", "0x1018"),
            0x1008: (b"", "ldr", "x1, [x8]"),
        }, "arm64")
        self.assertEqual(expected, [])
        self.assertEqual(len(unsupported), 1)
