"""The opt-in ABI proof uses encoded branches, observations and exact decisions."""
import unittest

from macscope import dispatch_returns as recovery
from macscope.dispatch_tables import UnverifiedDispatch
from macscope.errors import Error


def code_at(start, *instructions):
    code = {}
    for text in instructions:
        raw = bytes.fromhex(text)
        code[start] = raw
        start += len(raw)
    return code


class DispatchReturnProofTests(unittest.TestCase):
    def test_masked_proof_rejects_a_failure_branch_into_the_call(self):
        root = code_at(0x1000, "89f9", "80c193", "80f906", "0f92c0", "40b735", "40d2ef", "4020c7",
                       "4080ff01", "751d", "55", "4889e5", "0fb6c1", "488d0d18000000", "488b04c1",
                       "4889f7", "4889d6", "ff5008", "5d", "c3", "baa4cf8612", "31c0", "c3")
        layout = recovery.masked_layout(root)
        self.assertEqual((layout["bias"], layout["count"], layout["mask"], layout["call_va"]),
                         (0x6d, 6, 0x35, 0x1032))
        root[0x1018] = bytes.fromhex("7518")
        with self.assertRaisesRegex(UnverifiedDispatch, "unverified_dispatch_return_paths"):
            recovery.masked_layout(root)

    def test_observer_requires_both_return_values_to_survive(self):
        start, target = 0x2000, 0x1000
        direct = "e8" + (target - start - 5).to_bytes(4, "little", signed=True).hex()
        stores = code_at(start, direct, "891500000000", "48890500000000")
        self.assertEqual(recovery.observer(stores, start, target)["kind"], "stores")
        copies = code_at(start, direct, "89d1", "4889c2", "31c0", "e800000000")
        self.assertEqual(recovery.observer(copies, start, target)["kind"], "call_arguments")
        clobbered = code_at(start, direct, "89d1", "4889c2", "4889d9", "e800000000")
        self.assertIsNone(recovery.observer(clobbered, start, target))
        self.assertIsNone(recovery.observer(stores, start, target + 1))

    def test_worker_decision_binds_to_the_proved_table_without_emitting_targets(self):
        site = {"entry_va": "0x1000", "call_va": "0x1032", "target_vas": ["0x1040", "0x1060"]}
        plan = {"requests": [site]}
        row = dict(site, status="applied", prior_return_storage="RAX:8",
                   return_storage="RDX:8,RAX:8", convention="__stdcall")
        report = {"policy": recovery.POLICY, "results": [row]}
        self.assertNotIn("target_vas", recovery.decision(plan, report))
        row["target_vas"] = ["0x1040"]
        with self.assertRaises(Error):
            recovery.decision(plan, report)
