"""ARM64 BRK p-code's indirect PC branch is not an unresolved jump table."""
import copy
import unittest
from unittest import mock

from macscope import flow_evidence as policy


class TrapFlowTests(unittest.TestCase):
    def function(self, immediate=1):
        return {
            "entry_va": "0x1000", "decompile_status": "complete",
            "pseudocode": "SoftwareBreakpoint();", "coverage": {"pseudocode": {"status": "complete"}},
            "instructions": [{"addr": "0x1000", "bytes": (0xd4200000 | immediate << 5).to_bytes(4, "little").hex(),
                              "flow": "COMPUTED_JUMP"}],
            "blocks": [{"min": "0x1000", "max": "0x1003", "flow": "COMPUTED_JUMP", "dsts": []}],
        }

    def assert_gap(self, function, **kwargs):
        reviewed = policy.review(function, **dict({"arch": "arm64"}, **kwargs))
        self.assertNotIn("control_flow_traps", reviewed)
        self.assertEqual(reviewed["control_flow_gaps"][0]["reason"], "computed_jump_destination_unavailable")
        self.assertEqual(reviewed["decompile_status"], "partial")

    def test_exact_brk_immediates_keep_raw_evidence(self):
        for immediate in (0, 1, 0xf000, 0xffff):
            with self.subTest(immediate=immediate):
                function = self.function(immediate)
                original = copy.deepcopy(function)
                reviewed = policy.review(function, arch="arm64")
                self.assertEqual(function, original)
                self.assertEqual(reviewed["blocks"], function["blocks"])
                self.assertEqual(reviewed["pseudocode"], function["pseudocode"])
                self.assertEqual(reviewed["decompile_status"], "complete")
                self.assertNotIn("control_flow_gaps", reviewed)
                proof, = reviewed["control_flow_traps"]
                self.assertEqual(proof["immediate"], immediate)
                self.assertEqual(proof["instruction_bytes"], function["instructions"][0]["bytes"])
                self.assertEqual(proof["instruction_va"], "0x1000")
                self.assertEqual(proof["engine_flow"], "COMPUTED_JUMP")
                self.assertEqual(proof["policy"], policy.TRAP_POLICY)
                self.assertEqual(policy.review(reviewed, arch="arm64"), reviewed)

    def test_architecture_must_be_explicit(self):
        for arch in (None, "x86_64", "unknown", "arm64e", "aarch64"):
            with self.subTest(arch=arch):
                self.assert_gap(self.function(), arch=arch)

    def test_wrong_opcode_and_width_are_never_traps(self):
        # BR x0, BLR x0, HLT, NOP, and mutations to BRK's fixed bits.
        for encoded in ("00001fd6", "00003fd6", "000040d4", "1f2003d5", "010020d4",
                        "000000d4", "000020", "000020d400", "000020d4 ", "zz0020d4", None):
            with self.subTest(encoded=encoded):
                function = self.function()
                function["instructions"][0]["bytes"] = encoded
                self.assert_gap(function)

    def test_missing_malformed_duplicate_and_stale_instructions(self):
        for scenario in ("absent", "empty", "malformed", "address", "duplicate", "conflicting", "stale", "flow"):
            with self.subTest(scenario=scenario):
                function = self.function()
                row = function["instructions"][0]
                if scenario == "absent":
                    del function["instructions"]
                elif scenario == "empty":
                    function["instructions"] = []
                elif scenario == "malformed":
                    function["instructions"] = [None]
                elif scenario == "address":
                    row["addr"] = "bad"
                elif scenario in ("duplicate", "conflicting"):
                    function["instructions"].append(dict(row, bytes=row["bytes"] if scenario == "duplicate" else "00001fd6"))
                elif scenario == "stale":
                    row["addr"] = "0x1004"
                else:
                    row["flow"] = "FALL_THROUGH"
                self.assert_gap(function)

    def test_terminal_instruction_must_match_inclusive_block_end(self):
        for first, last, address in (("0x1000", "0x1000", "0x1000"), ("0x1000", "0x1004", "0x1000"),
                                     ("0x1004", "0x1003", "0x1000"), ("0x1001", "0x1004", "0x1001"),
                                     ("0x1000", "invalid", "0x1000")):
            with self.subTest(first=first, last=last, address=address):
                function = self.function()
                function["blocks"][0].update(min=first, max=last)
                function["instructions"][0]["addr"] = address
                self.assert_gap(function)

    def test_text_never_supplies_proof_or_hides_warnings(self):
        function = self.function()
        function["pseudocode"] += "\n/* WARNING: Treating indirect jump as call */"
        function["blocks"].append({"min": "0x1004", "max": "0x1007", "flow": "COMPUTED_JUMP", "dsts": []})
        function["instructions"].append({"addr": "0x1004", "bytes": "00001fd6", "flow": "COMPUTED_JUMP"})
        reviewed = policy.review(function, arch="arm64")
        self.assertEqual(reviewed["pseudocode"], function["pseudocode"])
        self.assertEqual([gap["reason"] for gap in reviewed["control_flow_gaps"]],
                         ["computed_jump_destination_unavailable", "decompiler_unresolved_jump"])
        self.assertEqual(reviewed["control_flow_gaps"][0]["block_min"], "0x1004")
        self.assertEqual(reviewed["engine_decompile_status"], "complete")
        self.assertEqual(policy.review(reviewed, arch="arm64"), reviewed)
        function["instructions"] = []
        self.assert_gap(function)

    def test_trap_alone_does_not_erase_printed_warning(self):
        function = self.function()
        function["pseudocode"] = "/* WARNING: Could not recover jumptable at 0x1000 */"
        reviewed = policy.review(function, arch="arm64")
        self.assertEqual(reviewed["decompile_status"], "partial")
        self.assertEqual([gap["reason"] for gap in reviewed["control_flow_gaps"]], ["decompiler_unresolved_jump"])

    def test_unrelated_partial_and_boundary_gaps_are_preserved(self):
        function = self.function()
        function.update(decompile_status="partial", decompile_error="timeout")
        function["coverage"]["pseudocode"]["status"] = "partial"
        reviewed = policy.review(function, arch="arm64", boundary_gaps=[{"reason": "unconfirmed_function_entry_reached_by_fallthrough"}])
        self.assertEqual(reviewed["decompile_status"], "partial")
        self.assertEqual(reviewed["decompile_error"], "timeout")
        self.assertEqual(reviewed["control_flow_review"], policy.flow_boundaries.POLICY)
        self.assertEqual(reviewed["control_flow_gaps"], [{"reason": "unconfirmed_function_entry_reached_by_fallthrough"}])

    def test_explicit_saved_instructions_support_fresh_review(self):
        saved = self.function()
        fresh = {key: value for key, value in saved.items() if key not in ("instructions", "blocks")}
        reviewed = policy.review(fresh, arch="arm64", blocks=saved["blocks"], instructions=saved["instructions"])
        self.assertEqual(reviewed["decompile_status"], "complete")
        self.assertEqual(len(reviewed["control_flow_traps"]), 1)

    def test_snapshot_retains_trap_only_proofs_without_degrading_status(self):
        snapshot = {"image": {"arch": "arm64"}, "functions": [self.function()], "status": "complete"}
        original = copy.deepcopy(snapshot)
        reviewed = policy.snapshot_view(snapshot)
        self.assertEqual(snapshot, original)
        self.assertEqual(reviewed["status"], "complete")
        self.assertEqual(len(reviewed["functions"][0]["control_flow_traps"]), 1)
        self.assertEqual(policy.snapshot_view(reviewed), reviewed)

    def test_previous_proof_is_revalidated_not_trusted(self):
        reviewed = policy.review(self.function(), arch="arm64")
        reviewed["instructions"][0]["bytes"] = "00001fd6"
        self.assert_gap(reviewed)

    def test_bounded_review_fails_closed(self):
        with mock.patch.object(policy, "MAX_TRAP_INSTRUCTIONS", 0):
            self.assert_gap(self.function())
        with mock.patch.object(policy, "MAX_TRAP_PROOFS", 0):
            self.assert_gap(self.function())
