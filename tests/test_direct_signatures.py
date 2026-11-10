"""Direct signature recovery requires an encoded call and preserved result registers."""
import unittest

from macscope import direct_signatures, dispatch_returns, engine
from macscope.dispatch_tables import UnverifiedDispatch
from macscope.errors import Error


class DirectSignatureTests(unittest.TestCase):
    def test_forwarding_path_cannot_replace_either_result_register(self):
        code = {0x1000: bytes.fromhex("e8fb0f0000"), 0x1005: b"\x5d", 0x1006: b"\xc3"}
        self.assertEqual(direct_signatures.forwarding_return(code, 0x1000), [0x1000, 0x1005, 0x1006])
        code[0x1005] = bytes.fromhex("31d2")
        code[0x1007] = b"\xc3"
        self.assertIsNone(direct_signatures.forwarding_return(code, 0x1000))

    def test_direct_call_bytes_and_saved_reference_must_agree(self):
        code = {0x1000: bytes.fromhex("e8fb0f0000")}
        ref = {"type": "UNCONDITIONAL_CALL", "from": "0x1000", "to": "0x2000", "is_external": False}
        function = {
            "coverage": {"xrefs_from": {"status": "complete", "truncated": False, "error": None, "emitted": 1}},
            "instructions": [{"addr": "0x1000", "flow": "UNCONDITIONAL_CALL"}],
            "xrefs_from_sample": [ref],
        }
        calls = lambda: list(direct_signatures.direct_edges(code, function, {"0x2000", "0x3000"}))
        self.assertEqual(calls(), [(0x1000, "0x2000")])
        ref["to"] = "0x3000"
        self.assertEqual(calls(), [])
        function["coverage"]["xrefs_from"]["truncated"] = True
        with self.assertRaises(UnverifiedDispatch):
            calls()

    def test_worker_cannot_substitute_a_call_site(self):
        site = {"call_va": "0x1100", "target_va": "0x2000"}
        parent = {"parent_va": "0x1000", "calls": [site]}
        plan = {"entry_va": "0x1000", "requests": [parent], "policy": direct_signatures.POLICY}
        row = {"parent_va": "0x1000", "sites": [site.copy()],
               "status": "applied", "return_storage": "RDX:8,RAX:8"}
        report = {"policy": direct_signatures.POLICY, "entry_va": "0x1000", "results": [row]}
        self.assertEqual(direct_signatures.decision(plan, report)["status"], "applied")
        row["sites"][0]["call_va"] = "0x1101"
        with self.assertRaises(Error):
            direct_signatures.decision(plan, report)

    def test_existing_dispatch_query_identity_is_stable(self):
        plan = {"entry_va": "0x1000", "requests": [], "policy": dispatch_returns.POLICY}
        self.assertEqual(engine.signature_request(plan),
                         ("dispatch_return_recovery", dispatch_returns.request_identity(plan)))
