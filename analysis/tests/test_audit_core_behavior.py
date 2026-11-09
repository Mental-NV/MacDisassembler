"""Protect the recovered-C evaluator's input and score boundaries."""
import unittest

from audit_core_behavior import core_extents, history_declaration, summarize


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
