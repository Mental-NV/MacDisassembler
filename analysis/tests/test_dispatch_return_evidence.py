"""A return witness must survive the actual instructions after the direct call."""
import unittest
from unittest.mock import patch

from dispatch_linkage import table_targets
from dispatch_return_evidence import caller_observation
from recover_dispatch_returns import preserves_cfg


ROOT = 0x1000
START = 0x1100
CALL = "e8" + (ROOT - START - 5).to_bytes(4, "little", signed=True).hex()


def instructions(*rows):
    result = {}
    address = START
    for encoded, mnemonic, operands in ((CALL, "callq", "0x1000"), *rows):
        raw = bytes.fromhex(encoded)
        result[address] = raw, mnemonic, operands
        address += len(raw)
    return result


class DispatchReturnEvidenceTests(unittest.TestCase):
    def test_dispatch_table_report_keeps_verified_hex_addresses(self):
        layout = {"base_va": 0x2000, "call_va": 0x1032}
        with (patch("dispatch_linkage.thin", return_value={"arch": "x86_64"}),
              patch("dispatch_linkage.machine_layout", return_value=layout),
              patch("dispatch_linkage.table_entries", return_value=[{"target_va": "0x1100"}])):
            self.assertEqual(table_targets(b"owned fixture", {}),
                             {"base_va": "0x2000", "call_va": "0x1032", "slots": [{"target_va": "0x1100"}]})

    def test_finds_both_widths_in_rip_relative_stores(self):
        code = instructions(
            ("8915371b0000", "movl", "%edx, 0x1b37(%rip) ## 0x3000"),
            ("488905381b0000", "movq", "%rax, 0x1b38(%rip) ## 0x3008"),
        )
        evidence = caller_observation(code, START, ROOT)
        self.assertEqual(evidence["kind"], "stores")
        self.assertEqual(set(evidence["reads"]), {"status", "word"})
        self.assertIsNone(caller_observation(code, START, ROOT + 1))

    def test_call_arguments_must_keep_the_forwarded_result_until_call(self):
        status = ("89d1", "movl", "%edx, %ecx")
        word = ("4889c2", "movq", "%rax, %rdx")
        invoke = ("e800000000", "callq", "0x1110")
        self.assertEqual(caller_observation(instructions(status, word, invoke), START, ROOT)["kind"],
                         "call_arguments")
        overwrite = ("4889d9", "movq", "%rbx, %rcx")
        self.assertIsNone(caller_observation(instructions(status, word, overwrite, invoke), START, ROOT))
        self.assertIsNone(caller_observation(instructions(word, status, invoke), START, ROOT))

    def test_override_split_accepts_only_the_original_fallthrough(self):
        call = "0x1005"
        block = {"min": "0x1000", "max": "0x1009", "flow": "TERMINATOR",
                 "dsts": [], "edges_truncated": False}
        edge = {"flow": "FALL_THROUGH", "from": "0x1000", "to": call}
        left = dict(block, max="0x1004", flow="FALL_THROUGH", dsts=[edge])
        right = dict(block, min=call)
        old = {"blocks": [block]}
        new = {"blocks": [left, right], "instructions": [{"addr": "0x1000", "fallthrough": call}]}
        self.assertTrue(preserves_cfg(old, new, call))
        left["dsts"] = [dict(edge, to="0x1009")]
        self.assertFalse(preserves_cfg(old, new, call))
