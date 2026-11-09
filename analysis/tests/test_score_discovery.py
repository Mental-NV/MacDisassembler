"""Regression tests for evaluator-side function classification."""
import unittest

from test_decompiler_review import function, result
from score_discovery import dwarf_functions, score


class DiscoveryTests(unittest.TestCase):
    def test_dwarf_counts_only_linker_confirmed_concrete_subprograms(self):
        fixture = """
0x00000001: DW_TAG_subprogram
              DW_AT_low_pc (0x00000100)
              DW_AT_high_pc (0x00000104)
              DW_AT_name ("first")
0x00000002:   DW_TAG_formal_parameter
                DW_AT_name ("parameter")
0x00000003: DW_TAG_subprogram
              DW_AT_low_pc (0x00000100)
              DW_AT_high_pc (0x00000104)
              DW_AT_abstract_origin (0x00000001 "alias")
0x00000004: DW_TAG_subprogram
              DW_AT_name ("abstract")
0x00000005: DW_TAG_subprogram
              DW_AT_ranges (0x0
0x00000006: DW_TAG_subprogram
              DW_AT_low_pc (0x00000110)
              DW_AT_high_pc (0x00000120)
0x00000007: DW_TAG_subprogram
              DW_AT_low_pc (0x00000200)
              DW_AT_high_pc (0x00000204)
"""
        truth, exclusions = dwarf_functions(fixture, {0x100, 0x200}, (0x100, 0x150))
        self.assertEqual(truth, {0x100: (0x104, {"first", "alias"})})
        self.assertEqual(exclusions, {
            "abstract_or_declaration": 1, "split_range": 1, "outside_text": 1, "unconfirmed_entry": 1,
        })

    def test_score_separates_exact_bodies_missing_entries_and_unscored_candidates(self):
        functions = [function(addr, "same") for addr in ("0x100", "0x110", "0x114", "0x130")]
        for record in functions:
            entry = record["entry_va"]
            record["body_ranges"] = [[entry, hex(int(entry, 16) + 3)]]
        functions[1]["body_ranges"] = [["0x110", "0x111"], ["0x116", "0x117"]]
        functions[1]["coverage"]["body_ranges"]["emitted"] = 2
        engine = result()
        engine.update(function_count_enumerated=4, function_count_total_reported_by_engine=4)
        engine["coverage"]["functions"].update(emitted=4, total=4)
        truth = {0x100: (0x104, {"first"}), 0x110: (0x118, {"second"}), 0x120: (0x124, {"third"})}
        measurement = score({"engine": engine, "functions": functions}, truth, {0x100, 0x110, 0x120})
        self.assertEqual(measurement["entry_matches"], 2)
        self.assertEqual(measurement["exact_entry_and_body"], 1)
        self.assertEqual(measurement["body_disagreements"][0]["dwarf_only_bytes"], 4)
        self.assertEqual(measurement["missing_entries"][0]["entry_va"], "0x120")
        self.assertEqual(measurement["interior_candidates"][0]["containing_dwarf_entry"], "0x110")
        self.assertEqual(measurement["outside_cohort"][0]["entry_va"], "0x130")

    def test_incomplete_body_cannot_pass_as_an_exact_match(self):
        engine = result()
        engine["functions"][0]["coverage"]["body_ranges"]["truncated"] = True
        with self.assertRaisesRegex(ValueError, "Incomplete Ghidra function body"):
            score({"engine": engine, "functions": engine["functions"]}, {0x100: (0x104, {"first"})}, {0x100})
