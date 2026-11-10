import unittest

from macscope import callee_parameters as policy
from macscope.direct_signatures import arm64_direct_target
from macscope.dispatch_tables import UnverifiedDispatch
from macscope.errors import Error


class CalleeParameterEvidenceTests(unittest.TestCase):
    def test_bottom_up_order_deduplicates_a_shared_callee(self):
        graph = {"root": ["leaf", "middle"], "middle": ["leaf"]}
        self.assertEqual(policy.call_order("root", graph), ["leaf", "middle"])

    def test_cycles_decline_recovery(self):
        graph = {"root": ["one"], "one": ["two"], "two": ["one"]}
        with self.assertRaisesRegex(UnverifiedDispatch, "recursive_callee_graph"):
            policy.call_order("root", graph)

    def test_arm_direct_target_sign_extends_and_rejects_an_ordinary_branch(self):
        self.assertEqual(arm64_direct_target(0x1010, bytes.fromhex("fcffff97")), 0x1000)
        self.assertIsNone(arm64_direct_target(0x1010, bytes.fromhex("fcffff17")))

    def test_report_must_show_expected_parameter_storage_and_preserved_return(self):
        proof = {"target_va": "0x1020", "path": [{"target_va": "0x1020"}]}
        plan = {"entry_va": "0x1000", "arch": "arm64", "requests": [proof]}
        result = {"target_va": "0x1020", "status": "applied",
                  "parameters": [{"register": "x0", "size": 4}], "return_unchanged": True}
        report = {"policy": policy.POLICY, "entry_va": "0x1000", "results": [result]}
        self.assertEqual(policy.decision(plan, report)["applied"][0]["path"], proof["path"])
        result["parameters"][0]["register"] = "x1"
        with self.assertRaises(Error):
            policy.decision(plan, report)
