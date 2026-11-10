"""Protect the recovered-C evaluator's input and score boundaries."""
import unittest

from audit_core_behavior import core_extents, history_declaration, summarize
from audit_core_instructions import compare, compare_call_references


class CoreBehaviorTests(unittest.TestCase):
    def test_evaluator_maps_exact_unique_concrete_bodies(self):
        self.assertEqual(core_extents({
            0x100: (0x110, {"calc_add", "helper"}),
            0x200: (0x220, {"helper"}),
        }), {"calc_add": (0x100, 0x110)})
        with self.assertRaisesRegex(ValueError, "Ambiguous evaluator body"):
            core_extents({0x100: (0x110, {"calc_add"}), 0x200: (0x210, {"calc_add"})})

    def test_only_the_mapped_recovered_dependency_is_admitted(self):
        text = "long FUN_100(long param_1,ulong param_2) { return FUN_200(param_1) + (param_2 & 0xfU); }"
        self.assertIsNone(history_declaration(text, "FUN_100", 4, ()))
        self.assertEqual(history_declaration(text, "FUN_100", 4, ("FUN_200",)), "integer")
        self.assertIsNone(history_declaration(text + "\n#define X 1", "FUN_100", 4, ("FUN_200",)))
        self.assertIsNone(history_declaration(text.replace("ulong param_2", "int param_2"),
                                              "FUN_100", 4, ("FUN_200",)))

    def test_wide_counter_failure_does_not_count_as_a_full_pass(self):
        summary = summarize([
            {"status": "passed", "results": {}, "llvm_instruction_bytes": 50},
            {"status": "passed", "results": {}, "llvm_instruction_bytes": 100,
             "wide_counter": {"status": "undefined_behavior"}},
            {"status": "aggregate_array_syntax", "llvm_instruction_bytes": 300},
        ])
        self.assertEqual(summary["concrete_routines"], 3)
        self.assertEqual(summary["routine_domains_completed"], 2)
        self.assertEqual(summary["routine_domains_passed"], 1)
        self.assertEqual(summary["llvm_bytes_for_completed_domains"], 150)
        self.assertEqual(summary["llvm_bytes_for_passed_domains"], 50)

    def test_tail_call_adjudication_requires_matching_target_and_linker_stub(self):
        instruction = {"addr": "0x100", "bytes": "eb7e", "text": "JMP 0x180",
                       "flow": "CALL_TERMINATOR", "fallthrough": None}
        body = {"instructions": [instruction], "coverage": {"instructions": {
            "status": "complete", "truncated": False, "error": None, "emitted": 1,
        }}}
        decoded = {0x100: (b"\xeb\x7e", "jmp", "0x180 <other>")}
        measured = compare(body, decoded, "x86_64", 0x102, {0x180: "_linker_stub"})
        self.assertEqual(measured["status"], "matched")
        self.assertEqual(measured["stub_tail_calls"], [
            {"entry": "0x100", "target": "0x180", "stub": "_linker_stub"},
        ])
        self.assertEqual(compare(body, decoded, "x86_64", 0x102, {})["status"], "disagreement")
        instruction["fallthrough"] = "0x102"
        self.assertEqual(compare(body, decoded, "x86_64", 0x102, {0x180: "_linker_stub"})["status"],
                         "disagreement")

    def test_indirect_call_target_and_incomplete_references_cannot_pass(self):
        decoded = {0x100: (b"", "callq", "0x180"), 0x105: (b"", "callq", "*%rax")}
        direct = {"from": "0x100", "to": "0x180", "type": "UNCONDITIONAL_CALL"}
        record = {"xrefs_from_sample": [direct], "coverage": {"xrefs_from": {
            "status": "complete", "truncated": False, "error": None, "emitted": 1,
        }}}
        self.assertEqual(compare_call_references(record, decoded, "x86_64", ())["status"], "matched")
        record["xrefs_from_sample"].append({"from": "0x105", "to": "0x184", "type": "COMPUTED_CALL"})
        self.assertEqual(compare_call_references(record, decoded, "x86_64", ())["status"],
                         "incomplete_outgoing_references")
        record["coverage"]["xrefs_from"]["emitted"] = 2
        actual = compare_call_references(record, decoded, "x86_64", ())
        self.assertEqual(actual["status"], "disagreement")
        self.assertEqual(actual["reported_targets_at_indirect_calls"], [{"entry": "0x105", "target": "0x184"}])
