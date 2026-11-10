import unittest

from macscope import forwarded_returns as policy


class ForwardedReturnEvidenceTests(unittest.TestCase):
    def test_only_register_preserving_epilogues_match(self):
        self.assertTrue(policy.epilogue("x86_64", [bytes.fromhex(s) for s in ("4883c410", "5d", "c3")]))
        self.assertFalse(policy.epilogue("x86_64", [bytes.fromhex(s) for s in ("31c0", "5d", "c3")]))
        self.assertTrue(policy.epilogue("arm64", [bytes.fromhex(s) for s in ("fd7b41a9", "ff830091", "c0035fd6")]))
        self.assertFalse(policy.epilogue("arm64", [bytes.fromhex(s) for s in ("e0031faa", "c0035fd6")]))

    def test_x86_byte_store_is_not_a_full_width_observer(self):
        image = {"arch": "x86_64", "segments": [{"protections": 3, "va": "0x2000", "size": "0x20"}]}
        call = b"\xe8\0\0\0\0"
        displacement = (0x2000 - (0x1005 + 7)).to_bytes(4, "little", signed=True)
        self.assertEqual(policy.observer_store(image, {0x1000: call, 0x1005: b"\x48\x89\x05" + displacement},
                                               0x1000), ([0x1000, 0x1005], 0x2000))
        self.assertIsNone(policy.observer_store(image, {0x1000: call, 0x1005: b"\x88\x05" + displacement}, 0x1000))

    def test_arm_observer_carries_the_original_register_value(self):
        image = {"arch": "arm64", "segments": [{"protections": 3, "va": "0x1000", "size": "0x1000"}]}
        code = {0x1000 + 4 * i: bytes.fromhex(s) for i, s in enumerate((
            "00000094", "e80300aa", "e00740f9", "09000090", "280500f9"))}
        self.assertEqual(policy.observer_store(image, code, 0x1000), (list(code), 0x1008))
        code[0x1004] = bytes.fromhex("e8031faa")  # mov x8, xzr
        self.assertIsNone(policy.observer_store(image, code, 0x1000))
