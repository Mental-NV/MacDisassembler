from unittest.mock import patch

from macscope import body_ownership, cli, engine, storage
from test_core import TemporaryCase, synthetic_snapshot


class RangeDisassemblyTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.workspace = self.project()
        self.snapshot, self.record = synthetic_snapshot(self.workspace)

    def args(self, *words):
        return cli.parser().parse_args(["disasm", "--project", str(self.workspace.path), *words])

    def query(self, interval):
        with patch.object(storage.Project, "snapshot", return_value=(self.snapshot, self.record)), \
                patch.object(engine, "dependencies") as dependencies:
            result = cli.execute(self.args("--range", interval))
            dependencies.assert_not_called()
            return result

    def test_adjacent_records_and_identical_overlap_are_sorted_and_deduplicated(self):
        first, second, third = self.snapshot["functions"]
        instruction = first["instructions"][0]
        next_instruction = dict(instruction, addr="0x100000004")
        first["instructions"] = [next_instruction, instruction]
        second["instructions"] = [instruction.copy()]
        third["address_space"] = "other"
        third["instructions"] = [dict(instruction, bytes="ff")]
        result = self.query("0x100000000:0x100000008")
        data = result["data"]
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["coverage"]["known_total"], 2)
        self.assertEqual(result["analysis_id"], self.snapshot["analysis_id"])
        self.assertEqual(data["covered_bytes"], 8)
        self.assertEqual(data["gaps"], [])
        self.assertEqual(data["instructions"], [dict(instruction, function_ids=["function-0", "function-1"]),
                                                dict(next_instruction, function_ids=["function-0"])])
        self.assertNotIn("function_ids", instruction)

    def test_cut_instructions_and_unrecorded_bytes_have_distinct_gaps(self):
        result = self.query("0x100000001:0x100000012")
        data = result["data"]
        self.assertEqual(result["status"], "partial")
        self.assertIsNone(result["coverage"]["known_total"])
        self.assertEqual(data["instructions"], [])
        self.assertEqual(data["covered_bytes"], 0)
        self.assertEqual(data["gaps"], [
            {"start_va": "0x100000001", "end_va": "0x100000004", "reason": "instruction_crosses_range_boundary"},
            {"start_va": "0x100000004", "end_va": "0x100000010", "reason": "no_saved_instruction"},
            {"start_va": "0x100000010", "end_va": "0x100000012", "reason": "instruction_crosses_range_boundary"},
        ])
        untouched = self.query("0x100000030:0x100000034")
        self.assertEqual(untouched["status"], "partial")
        self.assertEqual(untouched["data"]["gaps"][0]["reason"], "no_saved_instruction")

    def test_shared_body_keeps_agreeing_bytes_and_records_both_owners(self):
        first, second, _ = self.snapshot["functions"]
        second["body_ranges"].append(first["body_ranges"][0])
        second["instructions"].append(first["instructions"][0].copy())
        result = self.query("0x100000000:0x100000004")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["coverage"]["truncation_reason"], "function_body_overlap")
        self.assertEqual(result["data"]["covered_bytes"], 4)
        self.assertEqual(result["data"]["gaps"], [])
        self.assertEqual(result["data"]["body_ownership"]["witnesses"], [
            {"function_id":"function-0", "other_function_id":"function-1",
             "start_va":"0x100000000", "last_va":"0x100000003"},
            {"function_id":"function-1", "other_function_id":"function-0",
             "start_va":"0x100000000", "last_va":"0x100000003"},
        ])
        clear = self.query("0x100000010:0x100000014")
        self.assertEqual(clear["status"], "complete")
        self.assertNotIn("body_ownership",clear["data"])
        with patch.object(body_ownership,"MAX_RANGES",1):
            limited = self.query("0x100000000:0x100000004")
        self.assertTrue(limited["data"]["body_ownership"]["scan_truncated"])
        self.assertEqual(limited["coverage"]["truncation_reason"],"function_body_review_limit")

    def test_contradictory_records_do_not_hide_a_non_overlapping_instruction(self):
        first, second, _ = self.snapshot["functions"]
        original = first["instructions"][0]
        second["instructions"].extend([
            dict(original, bytes="00000000"), dict(original, addr="0x100000002"),
            dict(original, addr="0x100000005"),
        ])
        result = self.query("0x100000000:0x100000014")
        self.assertEqual(result["status"], "partial")
        self.assertEqual([row["addr"] for row in result["data"]["instructions"]], ["0x100000010"])
        self.assertEqual(result["data"]["covered_bytes"], 4)
        self.assertEqual(result["data"]["gaps"][0], {
            "start_va": "0x100000000", "end_va": "0x100000009", "reason": "conflicting_instructions"})

    def test_range_and_function_selectors_are_exclusive_and_range_is_bounded(self):
        for selector in ("--address", "--name", "--function-id"):
            with self.subTest(selector=selector):
                self.error("usage", self.args, "--range", "0x1:0x2", selector, "value")
        for interval in ("0x1", "1:0x2", "0x2:0x1", "0x2:0x2", "0x1:0x1002", "0x1:0x2:0x3",
                         "0x1:0x10000000000000000"):
            with self.subTest(interval=interval):
                self.error("disasm_range", cli.execute, self.args("--range", interval))
        original = cli.execute(self.args("--address", "0x100000000"))
        self.assertEqual(original["data"]["function_id"], "function-0")
        self.assertNotIn("gaps", original["data"])
