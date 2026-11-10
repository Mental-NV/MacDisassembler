import unittest

from macscope import scalar_signatures as policy


class ScalarSignatureEvidenceTests(unittest.TestCase):
    def test_single_exit_rejects_a_jump_around_the_register_definition(self):
        code = {0x1000: b"\xeb\x00", 0x1002: b"\x0f\xb6\xc0", 0x1005: b"\x5d", 0x1006: b"\xc3"}
        flows = ("UNCONDITIONAL_JUMP", "FALL_THROUGH", "FALL_THROUGH", "TERMINATOR")
        record = {"instructions": [{"addr": hex(va), "flow": flow} for va, flow in zip(code, flows)]}
        self.assertTrue(policy.extended_result(code, record))
        code[0x1000] = b"\xeb\x03"
        self.assertFalse(policy.extended_result(code, record))

    def test_al_only_return_is_not_a_witness(self):
        code = {0x1000: b"\xb0\x01", 0x1002: b"\xc3"}
        record = {"instructions": [{"addr": "0x1000", "flow": "FALL_THROUGH"},
                                   {"addr": "0x1002", "flow": "TERMINATOR"}]}
        self.assertFalse(policy.extended_result(code, record))

    def test_arm_stub_requires_a_load_and_branch_through_the_same_register(self):
        image = {"sections": [{"segment": "__TEXT", "name": "__stubs", "va": "0x10000251c",
                               "file_offset": "0x0", "size": "0xc"}]}
        stub = bytes.fromhex("100000d0102640f900021fd6")
        slot, sequence = policy.arm_stub(stub, image, 0x10000251c)
        self.assertEqual(slot, "0x100004048")
        self.assertEqual(len(sequence), 3)
        self.assertIsNone(policy.arm_stub(stub[:-4] + bytes.fromhex("20021fd6"), image, 0x10000251c))
