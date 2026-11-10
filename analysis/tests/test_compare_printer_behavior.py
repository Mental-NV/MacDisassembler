"""Protect the combined cached behavior score when a capture is partial."""
import json
from pathlib import Path
import tempfile
import unittest

from compare_printer_behavior import CORE_ROUTINES, result_rows, summarize


class PrinterBehaviorTests(unittest.TestCase):
    def test_incomplete_pseudocode_retains_its_instruction_denominator(self):
        key = ("DebugAnalysis-x86_64", "stripped", "baseline/1")
        capture = dict(zip(("case", "symbols", "profile"), key))
        capture.update(export_sha256="export", analysis_id="analysis")
        pair = {key: {"control_export_sha256": "export", "control_analysis_id": "analysis"}}
        incomplete = {"status": "incomplete_pseudocode", "llvm_instruction_bytes": 10}
        routines = {name: incomplete for name in CORE_ROUTINES}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / "first.json", root / "second.json"
            first.write_text(json.dumps({"status": "partial", "captures": [dict(capture, routines=routines)]}))
            one_routine = {CORE_ROUTINES[0]: incomplete}
            second.write_text(json.dumps({"status": "partial", "captures": [dict(capture, routines=one_routine)]}))
            rows = result_rows((first, second), pair, "control")
            summary = summarize(rows.values())
            self.assertEqual(summary["cases"], len(CORE_ROUTINES))
            self.assertEqual(summary["instruction_bytes"], 10 * len(CORE_ROUTINES))
            self.assertEqual(summary["passed_bytes"], 0)

            one_routine[CORE_ROUTINES[0]] = dict(incomplete, status="passed", results={})
            second.write_text(json.dumps({"status": "partial", "captures": [dict(capture, routines=one_routine)]}))
            with self.assertRaisesRegex(ValueError, "pseudocode provenance"):
                result_rows((first, second), pair, "control")
