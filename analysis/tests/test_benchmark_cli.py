"""Engine-free checks for benchmark percentile and sample requirements."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_cli import reported_times, summarize


class BenchmarkSummaryTests(unittest.TestCase):
    def test_nearest_rank_p95_checks_twenty_samples(self):
        result = summarize({"analyze": [0.5] * 18 + [59.0, 70.0]})["analyze"]
        self.assertEqual(result["samples"], 20)
        self.assertEqual(result["p95_seconds"], 59.0)
        self.assertEqual(result["maximum_seconds"], 70.0)
        self.assertTrue(result["target_met"])

    def test_smoke_runs_do_not_pass_the_performance_gate(self):
        result = summarize({"inspect": [0.5], "decompile_fresh": [2.0]})
        self.assertIsNone(result["inspect"]["target_met"])
        self.assertNotIn("target_met", result["decompile_fresh"])

    def test_p95_at_the_target_does_not_pass(self):
        result = summarize({"decompile_cached": [5.0] * 20})["decompile_cached"]
        self.assertFalse(result["target_met"])

    def test_reported_times_are_optional_and_unambiguous(self):
        startup = "INFO  Headless startup complete (1183 ms) (AnalyzeHeadless)  \n"
        analysis = "     Total Time   1 secs\n"
        self.assertEqual(reported_times(startup + analysis),
                         {"headless_startup": 1.183, "autoanalysis_reported": 1})
        self.assertEqual(reported_times(startup + startup), {})
