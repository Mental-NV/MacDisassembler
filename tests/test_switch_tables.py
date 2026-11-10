import unittest

from macscope import flow_evidence, switch_tables as policy
from macscope.dispatch_tables import UnverifiedDispatch
from macscope.errors import Error


class GuardedSwitchTests(unittest.TestCase):
    def fixture(self):
        # The guarded index starts at 42 and ranges from 0 through 5.
        prefix = ["0fbe45fb", "83c0d6", "89c1", "48894de0", "83e805", "7722",
                  "488b4de0", "488d0527000000", "48630c88", "4801c8", "ffe0"]
        rows = []
        address = 0x1000
        for index, encoded in enumerate(prefix):
            raw = bytes.fromhex(encoded)
            flow = {5: "CONDITIONAL_JUMP", 10: "COMPUTED_JUMP"}.get(index, "FALL_THROUGH")
            rows.append({"addr": hex(address), "bytes": encoded, "flow": flow})
            address += len(raw)
        jump = address - 2
        guard = int(rows[5]["addr"], 16)
        default = guard + 2 + 0x22
        table = int(rows[7]["addr"], 16) + 7 + 0x27
        self.assertEqual(table % 4, 0)
        targets = [address + 4, address, default, address + 8, default, address + 12]
        payload = b"".join(bytes.fromhex(raw) for raw in prefix)
        payload += b"\x90" * (default - address) + b"\xc3"
        payload += b"\0" * (table - 0x1000 - len(payload))
        payload += b"".join((target - table).to_bytes(4, "little", signed=True) for target in targets)
        rows.append({"addr": hex(default), "bytes": "c3", "flow": "TERMINATOR"})
        image = {"arch": "x86_64", "sections": [{"segment": "__TEXT", "name": "__text", "va": "0x1000",
                 "file_offset": "0x0", "size": hex(len(payload)), "protections": 5}],
                 "loader": {"function_starts": {"status": "complete", "addresses": ["0x1000", "0x1100"]},
                            "data_in_code": {"status": "complete", "records": [
                                {"slice_file_offset": hex(table - 0x1000), "kind": "0x4", "length": 24}]}}}
        blocks = [{"flow": "COMPUTED_JUMP", "min": hex(jump), "max": hex(jump + 1), "dsts": []}]
        root = {"entry_va": "0x1000", "instructions": rows, "blocks": blocks,
                "body_ranges": [["0x1000", hex(jump + 1)], [hex(default), hex(default)]],
                "coverage": {"instructions": {"status": "complete", "emitted": len(rows)},
                             "cfg": {"status": "complete", "emitted": 1},
                             "body_ranges": {"status": "complete", "emitted": 2}}}
        return payload, image, root, targets

    def test_request_binds_instruction_and_table_bytes_to_ordered_destinations(self):
        payload, image, root, targets = self.fixture()
        proof, = policy.requests(payload, image, root)
        self.assertEqual(proof["targets"], list(map(hex, targets)))
        self.assertEqual(proof["gap_bytes"], "90" * (targets[2] - targets[1]))
        with self.assertRaisesRegex(UnverifiedDispatch, "switch_instruction_bytes_disagree"):
            policy.requests(b"\x90" + payload[1:], image, root)
        image["loader"]["data_in_code"]["records"][0]["length"] = 20
        with self.assertRaisesRegex(UnverifiedDispatch, "unverified_switch_data_in_code"):
            policy.requests(payload, image, root)

    def test_guard_requires_the_same_spill_and_default_branch(self):
        _, _, root, targets = self.fixture()
        rows = [(int(row["addr"], 16), bytes.fromhex(row["bytes"]), row["flow"])
                for row in root["instructions"][:-1]]
        for index, replacement in ((5, "751a"), (6, "488b4dd8")):
            with self.subTest(replacement=replacement):
                altered = rows.copy()
                address, _, flow = altered[index]
                altered[index] = address, bytes.fromhex(replacement), flow
                with self.assertRaisesRegex(UnverifiedDispatch, "unsupported_switch_guard"):
                    policy.layout(altered, targets[2])

    def test_native_decision_preserves_duplicate_targets_and_case_indexes(self):
        payload, image, root, targets = self.fixture()
        proof, = policy.requests(payload, image, root)
        plan = {"entry_va": root["entry_va"], "requests": [proof]}
        report = dict(proof, policy=policy.POLICY, entry_va=root["entry_va"], status="applied", labels=list(range(6)))
        applied = policy.decision(plan, report)
        self.assertEqual(applied["targets"], list(map(hex, targets)))
        self.assertEqual(applied["labels"], report["labels"])
        for update in ({"targets": list(dict.fromkeys(report["targets"]))}, {"labels": [0, 1, 2, 3, 5, 4]}):
            with self.subTest(update=update), self.assertRaises(Error) as rejected:
                policy.decision(plan, dict(report, **update))
            self.assertEqual(rejected.exception.code, "switch_table_result")

    def test_fresh_review_only_clears_the_verified_edge_gap(self):
        other = {"flow": "COMPUTED_JUMP", "min": "0x1040", "max": "0x1044", "dsts": []}
        saved = [{"flow": "COMPUTED_JUMP", "min": "0x1010", "max": "0x1012", "dsts": []}, other]
        recovery = {"status": "applied", "jump_va": "0x1011", "jump_end_va": "0x1012",
                    "targets": ["0x1020", "0x1020", "0x1030"]}
        blocks = policy.reviewed_blocks(saved, recovery)
        self.assertEqual([edge["to"] for edge in blocks[0]["dsts"]], ["0x1020", "0x1030"])
        self.assertEqual(saved[0]["dsts"], [])
        result = flow_evidence.review({"decompile_status": "complete", "pseudocode": ""}, blocks=blocks)
        self.assertEqual(result["decompile_status"], "partial")
        gap, = result["control_flow_gaps"]
        self.assertEqual(gap["block_max"], other["max"])
