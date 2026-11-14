"""Synthetic-only tests for the export benchmark harness.

All records are invented owned fixtures; no TickTick artifact, engine run,
or Ghidra execution is involved. The harness accepts and returns plain
JSON-compatible records and never rewrites pseudocode.
"""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import export_benchmark as harness


def make_receipt(kind="isolated", **overrides):
    record = {
        "schema_version": 1,
        "receipt_kind": kind,
        "image": {"image_id": "owned-image-1", "arch": "arm64",
                  "input_sha256": "a" * 64, "slice_sha256": "b" * 64},
        "selection": {"addresses": ["0x1000", "0x1040"]},
        "counts": {"attempted": 2, "succeeded": 1, "partial": 1, "failed": 0},
        "wall_seconds": 10.0 if kind == "isolated" else 5.0,
        "intervals": {"worker_seconds": 9.0 if kind == "isolated" else 4.0,
                      "launch_to_ready_seconds": 2.0,
                      "decompile_call_seconds": 0.05,
                      "program_database_open_seconds": None},
        "coverage": {"scope": "owned two-address selection", "status": "partial",
                     "returned_count": 2, "known_total": 2,
                     "next_cursor": None, "truncation_reason": None},
        "limitations": ["Synthetic owned fixture; not a TickTick measurement."],
        "evidence_refs": ["fixture:job-%s-1" % kind, "fixture:job-%s-2" % kind],
        "status": "partial",
    }
    for key, value in overrides.items():
        record[key] = value
    return record


class ReceiptValidationTests(unittest.TestCase):
    def test_accepts_synthetic_receipt_and_sorts_selection(self):
        receipt = make_receipt(selection={"addresses": ["0x1040", "0x1000"]})
        normalized = harness.validate_receipt(receipt)
        self.assertEqual(normalized["selection"]["addresses"], ["0x1000", "0x1040"])
        self.assertEqual(normalized["schema_version"], 1)

    def test_rejects_malformed_records(self):
        bad_versions = [
            dict(make_receipt(), schema_version="1"),
            dict(make_receipt(), schema_version=2),
            dict(make_receipt(), receipt_kind="batch"),
            dict(make_receipt(),
                 image={"image_id": "x", "arch": "arm64", "input_sha256": "zz"}),
            dict(make_receipt(),
                 image={"image_id": "x", "arch": "riscv", "input_sha256": "a" * 64}),
            dict(make_receipt(), selection={"addresses": []}),
            dict(make_receipt(), selection={"addresses": ["0x1000", "0x1000"]}),
            dict(make_receipt(), selection={"addresses": ["not-an-address"]}),
            dict(make_receipt(),
                 counts={"attempted": 2, "succeeded": 2, "partial": 1, "failed": 0}),
            dict(make_receipt(), wall_seconds=-1.0),
            dict(make_receipt(), intervals={}),
            dict(make_receipt(), intervals={"a": -0.5}),
            dict(make_receipt(), coverage="complete"),
            dict(make_receipt(), limitations=[]),
            dict(make_receipt(), evidence_refs="job-1"),
            dict(make_receipt(), pseudocode="should never be accepted"),
        ]
        for index, bad in enumerate(bad_versions):
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    harness.validate_receipt(bad)

    def test_rejects_non_json_values(self):
        bad = make_receipt()
        bad["coverage"] = {"scope": float("nan")}
        with self.assertRaises(ValueError):
            harness.validate_receipt(bad)


class ComparisonTests(unittest.TestCase):
    def test_comparable_pair_reports_speedup_and_copies_coverage(self):
        isolated = make_receipt("isolated")
        comparison = harness.compare_receipts(copy.deepcopy(isolated),
                                              make_receipt("bulk"))
        self.assertTrue(comparison["comparable"])
        self.assertEqual(comparison["schema_version"], 1)
        self.assertEqual(comparison["reasons"], [])
        self.assertEqual(comparison["coverage"], isolated["coverage"])
        comparison["coverage"]["scope"] = "mutated"
        self.assertEqual(isolated["coverage"]["scope"],
                         "owned two-address selection")
        wall = comparison["wall"]
        self.assertAlmostEqual(wall["speedup_isolated_over_bulk"], 2.0)
        self.assertTrue(wall["speedup_reported"])
        self.assertEqual(comparison["image"]["input_sha256"], "a" * 64)
        self.assertEqual(comparison["image"]["arch"], "arm64")
        self.assertEqual(comparison["selection"]["addresses"], ["0x1000", "0x1040"])
        self.assertTrue(comparison["limitations"])

    def test_comparison_is_deterministic(self):
        first = harness.compare_receipts(make_receipt("isolated"), make_receipt("bulk"))
        second = harness.compare_receipts(make_receipt("isolated"), make_receipt("bulk"))
        self.assertEqual(first, second)
        self.assertEqual(json.dumps(first, sort_keys=True),
                         json.dumps(second, sort_keys=True))
        json.loads(json.dumps(first))  # plain JSON-compatible output

    def test_intervals_carried_without_summing_overlaps(self):
        comparison = harness.compare_receipts(make_receipt("isolated"),
                                              make_receipt("bulk"))
        table = comparison["intervals"]
        self.assertEqual(table["worker_seconds"]["isolated_seconds"], 9.0)
        self.assertEqual(table["worker_seconds"]["bulk_seconds"], 4.0)
        self.assertAlmostEqual(table["worker_seconds"]["ratio_isolated_over_bulk"], 2.25)
        # Unmeasured stays explicit; no invented zero.
        self.assertIsNone(table["program_database_open_seconds"]["isolated_seconds"])
        self.assertIsNone(table["program_database_open_seconds"]["ratio_isolated_over_bulk"])
        # No summed total may appear: overlapping intervals must not be added.
        self.assertNotIn("total_seconds", comparison)
        self.assertNotIn("total_seconds", table)

    def test_partial_counts_compare_when_equal(self):
        # Partial outcomes are explicit coverage, not a mismatch.
        comparison = harness.compare_receipts(make_receipt("isolated"),
                                              make_receipt("bulk"))
        self.assertTrue(comparison["comparable"])
        self.assertEqual(comparison["counts_isolated"]["partial"], 1)

    def test_count_mismatch_is_incomparable_without_speedup(self):
        bulk = make_receipt("bulk",
                            counts={"attempted": 2, "succeeded": 2,
                                    "partial": 0, "failed": 0})
        comparison = harness.compare_receipts(make_receipt("isolated"), bulk)
        self.assertFalse(comparison["comparable"])
        self.assertIsNone(comparison["wall"]["speedup_isolated_over_bulk"])
        self.assertFalse(comparison["wall"]["speedup_reported"])
        self.assertTrue(any("counts" in reason for reason in comparison["reasons"]))

    def test_coverage_mismatch_is_incomparable_without_speedup(self):
        bulk = make_receipt("bulk")
        bulk["coverage"] = dict(bulk["coverage"], returned_count=1)
        comparison = harness.compare_receipts(make_receipt("isolated"), bulk)
        self.assertFalse(comparison["comparable"])
        self.assertFalse(comparison["coverages_match"])
        self.assertIsNone(comparison["wall"]["speedup_isolated_over_bulk"])
        # Output coverage is copied from the isolated input, not invented.
        self.assertEqual(comparison["coverage"],
                         make_receipt("isolated")["coverage"])

    def test_image_and_selection_mismatch_are_incomparable(self):
        bulk = make_receipt("bulk")
        bulk["image"] = dict(bulk["image"], input_sha256="c" * 64)
        comparison = harness.compare_receipts(make_receipt("isolated"), bulk)
        self.assertFalse(comparison["comparable"])
        self.assertIsNone(comparison["wall"]["speedup_isolated_over_bulk"])

        bulk = make_receipt("bulk", selection={"addresses": ["0x1000", "0x1080"]})
        comparison = harness.compare_receipts(make_receipt("isolated"), bulk)
        self.assertFalse(comparison["comparable"])
        self.assertTrue(any("selection" in reason for reason in comparison["reasons"]))

    def test_zero_wall_time_reports_no_speedup(self):
        bulk = make_receipt("bulk", wall_seconds=0.0)
        comparison = harness.compare_receipts(make_receipt("isolated"), bulk)
        self.assertFalse(comparison["comparable"])
        self.assertIsNone(comparison["wall"]["speedup_isolated_over_bulk"])
        self.assertFalse(comparison["wall"]["speedup_reported"])

    def test_wrong_kinds_are_incomparable(self):
        comparison = harness.compare_receipts(make_receipt("bulk"),
                                              make_receipt("bulk"))
        self.assertFalse(comparison["comparable"])
        self.assertTrue(any("isolated" in reason for reason in comparison["reasons"]))

    def test_evidence_preserved_by_reference_only(self):
        comparison = harness.compare_receipts(make_receipt("isolated"),
                                              make_receipt("bulk"))
        self.assertEqual(comparison["evidence_refs"]["isolated"],
                         ["fixture:job-isolated-1", "fixture:job-isolated-2"])
        text = json.dumps(comparison)
        self.assertNotIn("pseudocode", text)

    def test_cli_round_trip_through_files(self):
        with tempfile.TemporaryDirectory() as directory:
            isolated_path = Path(directory) / "isolated.json"
            bulk_path = Path(directory) / "bulk.json"
            out_path = Path(directory) / "comparison.json"
            isolated_path.write_text(json.dumps(make_receipt("isolated")))
            bulk_path.write_text(json.dumps(make_receipt("bulk")))
            self.assertEqual(harness.main([str(isolated_path), str(bulk_path),
                                           "--output", str(out_path)]), 0)
            comparison = json.loads(out_path.read_text())
            self.assertTrue(comparison["comparable"])


class RecoveryRegressionTests(unittest.TestCase):
    def test_address_normalization_and_numeric_sort(self):
        receipt = make_receipt(selection={"addresses": ["0x10", "0xA"]})
        normalized = harness.validate_receipt(receipt)
        self.assertEqual(normalized["selection"]["addresses"], ["0xa", "0x10"])
        receipt["selection"]["addresses"] = ["0x0a", "0xA"]
        with self.assertRaises(ValueError):
            harness.validate_receipt(receipt)

    def test_nested_raw_evidence_rejected(self):
        for key in harness.FORBIDDEN_RAW_KEYS:
            receipt = make_receipt()
            receipt["coverage"] = {"nested": [{key: "private code"}]}
            with self.assertRaises(ValueError):
                harness.validate_receipt(receipt)

    def test_no_ratios_for_incomparable_receipts(self):
        bulk = make_receipt("bulk")
        bulk["image"]["input_sha256"] = "c" * 64
        output = harness.compare_receipts(make_receipt(), bulk)
        self.assertFalse(output["comparable"])
        self.assertTrue(all(row["ratio_isolated_over_bulk"] is None
                            for row in output["intervals"].values()))

    def test_unsuccessful_or_unfinished_runs_have_no_speedup(self):
        for changes in (
            {"status": "cancelled"}, {"status": "failed"}, {"status": "timeout"},
            {"counts": {"attempted": 1, "succeeded": 1, "partial": 0, "failed": 0}},
            {"counts": {"attempted": 2, "succeeded": 1, "partial": 0, "failed": 1}},
            {"evidence_refs": []},
        ):
            with self.subTest(changes=changes):
                output = harness.compare_receipts(make_receipt(**changes),
                                                   make_receipt("bulk", **changes))
                self.assertFalse(output["comparable"])
                self.assertIsNone(output["wall"]["speedup_isolated_over_bulk"])

    def test_excess_attempts_rejected(self):
        with self.assertRaises(ValueError):
            harness.validate_receipt(make_receipt(counts={
                "attempted": 3, "succeeded": 3, "partial": 0, "failed": 0}))

    def test_missing_selection_id_not_silently_equal(self):
        first = make_receipt()
        first["selection"]["selection_id"] = "frozen-one"
        self.assertFalse(harness.compare_receipts(first, make_receipt("bulk"))["comparable"])

    def test_finite_output_at_numeric_extremes(self):
        result = harness.compare_receipts(make_receipt(wall_seconds=1e308),
                                           make_receipt("bulk", wall_seconds=1e-308))
        self.assertFalse(result["comparable"])
        json.dumps(result, allow_nan=False)
        self.assertEqual(harness.summarize_samples([1e308, 1e308])["median_seconds"], 1e308)
        self.assertEqual(harness.summarize_samples([5e-324])["median_seconds"], 5e-324)
        self.assertEqual(harness.summarize_samples([9007199254740993])["median_seconds"], 9007199254740993)
        underflow = harness.compare_receipts(make_receipt(wall_seconds=5e-324),
                                             make_receipt("bulk", wall_seconds=1e308))
        self.assertFalse(underflow["comparable"])
        self.assertIsNone(underflow["wall"]["speedup_isolated_over_bulk"])
        with self.assertRaises(ValueError):
            harness.validate_receipt(make_receipt(wall_seconds=10**1000))

    def test_cli_refuses_existing_output_and_reports_write_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first.json", root / "second.json"
            first.write_text(json.dumps(make_receipt()))
            second.write_text(json.dumps(make_receipt("bulk")))
            original = first.read_bytes()
            self.assertEqual(harness.main([str(first), str(second), "--output", str(first)]), 2)
            self.assertEqual(first.read_bytes(), original)
            self.assertEqual(harness.main([str(first), str(second), "--output", str(root / "absent" / "out.json")]), 2)


class SummaryTests(unittest.TestCase):
    def test_summary_reports_median_without_p95_below_twenty(self):
        summary = harness.summarize_samples([3.0, 1.0, 2.0])
        self.assertEqual(summary,
                         {"samples": 3, "minimum_seconds": 1.0,
                          "median_seconds": 2.0, "maximum_seconds": 3.0})
        self.assertNotIn("p95_seconds", summary)

    def test_summary_reports_p95_at_twenty_samples(self):
        values = [float(index) for index in range(1, 21)]
        summary = harness.summarize_samples(values)
        self.assertEqual(summary["samples"], 20)
        self.assertEqual(summary["p95_seconds"], 19.0)

    def test_summary_rejects_bad_samples(self):
        for bad in ([], [-1.0], [float("inf")], ["x"]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                harness.summarize_samples(bad)

    def test_summary_is_deterministic(self):
        values = [2.0, 1.0, 2.0, 3.0]
        self.assertEqual(harness.summarize_samples(values),
                         harness.summarize_samples(list(reversed(values))))


if __name__ == "__main__":
    unittest.main()
