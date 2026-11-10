"""Do not treat a linker-confirmed function split at fallthrough as complete."""
import copy
import unittest

from macscope import flow_boundaries, flow_evidence
from macscope.errors import Error


class FlowBoundaryTests(unittest.TestCase):
    def snapshot(self):
        owner = {
            "entry_va": "0x100", "body_ranges": [["0x100", "0x103"]],
            "coverage": {"cfg": {"status": "complete"}, "body_ranges": {"status": "complete"}},
            "blocks": [{"max": "0x103", "dsts": [{"flow": "FALL_THROUGH", "from": "0x100", "to": "0x104"}]}],
        }
        continuation = {"entry_va": "0x104", "body_ranges": [["0x104", "0x10f"]]}
        starts = {"status": "complete", "addresses": ["0x100", "0x120"]}
        return {"image": {"loader": {"function_starts": starts}}, "functions": [owner, continuation]}

    def test_conflicting_fallthrough_reports_both_engine_entries(self):
        snapshot = self.snapshot()
        original = copy.deepcopy(snapshot)
        result = flow_boundaries.gaps(snapshot)
        self.assertEqual(snapshot, original)
        self.assertEqual(list(result), ["0x100", "0x104"])
        self.assertEqual(result["0x100"][0]["reason"], "fallthrough_into_unconfirmed_function")
        self.assertEqual(result["0x104"][0]["reason"], "unconfirmed_function_entry_reached_by_fallthrough")
        self.assertEqual(result["0x104"][0]["linker_entry_va"], "0x100")

    def test_known_boundaries_and_unproven_cfg_are_preserved(self):
        for scenario in ("confirmed_target", "different_owner", "bounded_starts", "jump", "bounded_cfg", "owned_body"):
            with self.subTest(scenario=scenario):
                snapshot = self.snapshot()
                starts = snapshot["image"]["loader"]["function_starts"]
                owner = snapshot["functions"][0]
                if scenario == "confirmed_target":
                    starts["addresses"].insert(1, "0x104")
                elif scenario == "different_owner":
                    starts["addresses"].insert(1, "0x102")
                elif scenario == "bounded_starts":
                    starts["status"] = "partial"
                elif scenario == "jump":
                    owner["blocks"][0]["dsts"][0]["flow"] = "UNCONDITIONAL_JUMP"
                elif scenario == "bounded_cfg":
                    owner["coverage"]["cfg"]["status"] = "partial"
                else:
                    owner["body_ranges"][0][1] = "0x105"
                self.assertEqual(flow_boundaries.gaps(snapshot), {})

    def test_cached_and_published_fresh_views_preserve_raw_evidence(self):
        snapshot = self.snapshot()
        for function in snapshot["functions"]:
            function.update(decompile_status="complete", pseudocode="saved code")
        selected, competing = flow_evidence.snapshot_view(snapshot)["functions"]
        for row in (selected, competing):
            self.assertEqual(row["decompile_status"], "partial")
            self.assertEqual(row["engine_decompile_status"], "complete")
            self.assertEqual(row["pseudocode"], "saved code")
        result = {"status": "complete", "coverage": {"status": "complete"},
                  "data": {"decompile_status": "complete", "pseudocode": "fresh code"}}
        fresh = flow_evidence.query_view(result, selected)
        self.assertEqual(fresh["status"], "partial")
        self.assertEqual(fresh["data"]["pseudocode"], "fresh code")
        self.assertEqual(fresh["data"]["control_flow_gaps"], selected["control_flow_gaps"])
        self.assertEqual(result["status"], "complete")
        self.assertTrue(all(row["decompile_status"] == "complete" for row in snapshot["functions"]))

    def test_recovery_requires_exact_provenance_and_consistent_coverage(self):
        request = {
            "policy": flow_boundaries.RECOVERY_POLICY, "linker_starts": ["0x100", "0x120", "0x140"],
            "image_base": "0x0", "input_sha256": "0" * 64,
        }
        report = {
            **flow_boundaries.recovery_identity(request), "status": "partial", "reason": None,
            "candidates": [
                {"owner": "0x100", "competing": "0x104", "outcome": "joined"},
                {"owner": "0x120", "competing": "0x124", "outcome": "outside_reference"},
            ],
        }
        result = {"status": "partial", "boundary_recovery": report, "functions": [{"entry_va": "0x124"}]}
        flow_boundaries.verify_recovery(result, request)
        cases = [
            dict(result, status="complete"),
            dict(result, boundary_recovery=dict(report, request_sha256="wrong")),
            dict(result, boundary_recovery=dict(report, candidates=list(reversed(report["candidates"])))),
            dict(result, functions=[{"entry_va": "0x104"}]),
        ]
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(Error) as caught:
                flow_boundaries.verify_recovery(candidate, request)
            self.assertEqual(caught.exception.code, "boundary_recovery_result")
        with self.assertRaises(Error):
            flow_boundaries.verify_recovery(result, None)
