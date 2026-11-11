"""Owned flow evidence: independently located sites and immutable receipts."""
import copy
import json
import unittest
from unittest.mock import patch

from macscope import cli, engine, evidence, flow_evidence, flow_gap_evidence as gaps, focused, focused_tailcalls, jobs, storage
import test_query_resume


class GapLocationTests(unittest.TestCase):
    def function(self, arch="arm64"):
        encoded = "00001fd6" if arch == "arm64" else "ffe0"
        entry = "0x1000"
        end = hex(int(entry, 16) + len(encoded) // 2 - 1)
        function = {
            "function_id": "a" * 64, "image_id": "b" * 64, "slice_sha256": "c" * 64,
            "arch": arch, "entry_va": entry, "body_ranges": [[entry, end]],
            "origin": {"mode": "focused_readonly_import", "extent": {"policy": "macscope-focused-import/2", "entry_va": entry,
                                  "extent_sha256": "d" * 64, "program_sha256": "e" * 64}},
            "instructions": [{"addr": entry, "bytes": encoded, "flow": "COMPUTED_JUMP", "fallthrough": None}],
            "blocks": [{"min": entry, "max": end, "flow": "COMPUTED_JUMP", "dsts": [], "edges_truncated": False}],
            "decompile_status": "complete", "pseudocode": "return;", "coverage": {},
        }
        return function

    def reviewed(self, function):
        return gaps.annotate(flow_evidence.review(function, arch=function["arch"]))

    def test_arm64_and_variable_width_x86_terminal_sites_use_instruction_bytes(self):
        for arch in ("arm64", "x86_64"):
            with self.subTest(arch=arch):
                function = self.function(arch)
                before = copy.deepcopy(function)
                result = self.reviewed(function)
                row, = result["control_flow_gaps"]
                location = row["evidence"]["location"]
                self.assertEqual((location["kind"], location["instruction_va"]), ("instruction", "0x1000"))
                self.assertEqual(location["instruction_bytes"], function["instructions"][0]["bytes"])
                self.assertEqual(row["evidence"]["function"]["slice_sha256"], "c" * 64)
                self.assertEqual(function, before)
                self.assertEqual(gaps.annotate(result), result)
                self.assertEqual(result["decompile_status"], "partial")

    def test_explicit_edge_source_is_preserved_with_original_effective_flow(self):
        function = self.function()
        function["instructions"][0].update(bytes="00040014", flow="CALL_TERMINATOR",
                                            original_flow="UNCONDITIONAL_JUMP", flow_override="CALL_RETURN")
        plan = {"policy": focused_tailcalls.POLICY, "arch": "arm64", "reason": None, "candidates": [
            {"source_va": "0x1000", "source_bytes": "00040014", "target_va": "0x2000",
             "target_kind": "linker_function_start", "target_bytes": "c0035fd6"}]}
        function["origin"]["extent"]["tail_calls"] = plan
        function["tail_call_recovery"] = {"policy": focused_tailcalls.POLICY,
            "request_sha256": focused_tailcalls.request_digest(plan),
            "decisions": [{"source_va": "0x1000", "outcome": "applied"}]}
        gap = {"reason": "focused_tail_call_unverified", "from": "0x1000", "to": "0x2000", "flow": "CALL_TERMINATOR"}
        function["control_flow_gaps"] = [gap]
        result = gaps.annotate(function)["control_flow_gaps"][0]
        self.assertEqual({key: value for key, value in result.items() if key != "evidence"}, gap)
        location = result["evidence"]["location"]
        self.assertEqual((location["original_flow"], location["effective_flow"]),
                         ("UNCONDITIONAL_JUMP", "CALL_TERMINATOR"))

    def test_warning_address_never_becomes_site_even_when_matching_instruction(self):
        function = self.function()
        function["pseudocode"] = "/* WARNING: Could not recover jumptable at 0x1000 */"
        result = self.reviewed(function)
        warning = result["control_flow_gaps"][1]
        self.assertEqual(warning["warning"], "Could not recover jumptable at 0x1000")
        self.assertEqual(warning["evidence"]["location"],
                         {"kind": "unavailable", "reason": "warning_has_no_independent_site"})
        self.assertEqual(result["pseudocode"], function["pseudocode"])

    def test_smallest_captured_block_is_fallback_not_function_extent(self):
        function = self.function()
        function["instructions"] = []
        function["blocks"].append({"min": "0x1000", "max": "0x101f", "flow": "COMPUTED_JUMP", "dsts": []})
        function["control_flow_gaps"] = [{"reason": "focused_flow_destination_unavailable", "from": "0x1002"}]
        location = gaps.annotate(function)["control_flow_gaps"][0]["evidence"]["location"]
        self.assertEqual(location, {"kind": "block_range", "block_min": "0x1000", "block_max": "0x1003",
                                    "reason": "instruction_evidence_unavailable"})

    def test_missing_duplicate_bad_width_and_overlapping_instructions_do_not_supply_site(self):
        for scenario in ("missing", "duplicate", "overlap", "bad_hex", "bad_width", "wrong_end"):
            with self.subTest(scenario=scenario):
                function = self.function()
                instruction = function["instructions"][0]
                if scenario == "missing": function["instructions"] = []
                elif scenario == "duplicate": function["instructions"].append(dict(instruction))
                elif scenario == "overlap": function["instructions"].append(dict(instruction, addr="0x1002"))
                elif scenario == "bad_hex": instruction["bytes"] = "0x00001fd6"
                elif scenario == "bad_width": instruction["bytes"] = "00001fd600"
                else: function["blocks"][0]["max"] = "0x1004"
                location = self.reviewed(function)["control_flow_gaps"][0]["evidence"]["location"]
                self.assertEqual(location["kind"], "block_range")

    def test_native_operation_address_is_not_an_invented_transfer_site(self):
        function = self.function()
        function["control_flow_gaps"] = [{"reason": "native_operations_outside_body",
                                           "scope": {"outside_body_addresses": ["0x2000"]}}]
        location = gaps.annotate(function)["control_flow_gaps"][0]["evidence"]["location"]
        self.assertEqual(location, {"kind": "unavailable", "reason": "native_scope_does_not_identify_transfer"})

    def test_names_and_selectors_do_not_upgrade_classification(self):
        for name in ("objc_msgSend", "wrapper", "dispatch:setHidden:", "owned_internal"):
            function = self.function()
            function["names"] = [{"name": name, "origin": "user"}]
            function["selector"] = "setHidden:"
            classification = self.reviewed(function)["control_flow_gaps"][0]["evidence"]["classification"]
            self.assertEqual(classification, {"kind": "unclassified", "reason": "classification_not_evaluated"})

    def test_site_collection_limits_fail_closed(self):
        for key in ("MAX_INSTRUCTIONS", "MAX_BLOCKS"):
            with patch.object(gaps, key, 0):
                location = self.reviewed(self.function())["control_flow_gaps"][0]["evidence"]["location"]
                self.assertNotEqual(location["kind"], "instruction")

    def test_no_gap_does_not_add_fields(self):
        function = self.function()
        self.assertIs(gaps.annotate(function), function)


class GapReceiptTests(test_query_resume.FocusedResumeTests):
    """Exercise the actual writer/reader and CLI capture, using owned worker rows."""
    def worker_with_gap(self, *args, **kwargs):
        result, job = self.worker(*args, **kwargs)
        function = result["functions"][0]
        # Keep the owned source RET bytes untouched; a warning alone must not
        # borrow that valid instruction's address to manufacture a precise site.
        function["pseudocode"] = "/* WARNING: Could not recover jumptable at " + self.entry + " */\nreturn;"
        return result, job

    def capture(self):
        with patch.object(engine, "dependencies", return_value=self.deps), \
                patch.object(engine, "run", side_effect=self.worker_with_gap):
            return self.resume()

    def test_capture_replay_and_json_html_handoff_preserve_evidence_offline(self):
        captured = self.capture()
        self.assertEqual(captured["status"], "partial")
        original = captured["data"]["control_flow_gaps"]
        self.assertEqual(original[0]["evidence"]["location"]["kind"], "unavailable")
        path = self.workspace.path / "jobs" / self.original / "query-result.json"
        raw = path.read_bytes()
        pin = {"image_id": self.image_id, "arch": "arm64", "artifact_sha256": self.image["artifact_sha256"],
               "slice_sha256": self.image["sha256"], "import_program_sha256": self.image["engine_baseline_sha256"]}
        manifest = {"schema": evidence.LEADS_SCHEMA, "images": [pin], "leads": [
            {"id": "owned", "image_id": self.image_id, "kind": "address", "value": self.entry,
             "query_job": self.original}]}
        leads = self.root / "leads.json"
        storage.write_json(leads, manifest)
        with patch.object(engine, "run", side_effect=AssertionError("Offline receipt must not start Ghidra")), \
                patch.object(engine, "dependencies", side_effect=AssertionError("Offline receipt must not probe Java")):
            replay = self.resume()
            handoff = self.run_cli("evidence", "--leads", str(leads))
            again = self.run_cli("evidence", "--leads", str(leads))
        self.assertEqual(replay["data"]["control_flow_gaps"], original)
        self.assertEqual(handoff["data"]["leads"][0]["function"]["control_flow_gaps"], original)
        self.assertEqual(handoff["data"]["leads"][0]["function"]["engine_decompile_status"], "complete")
        self.assertEqual(storage.canonical(handoff), storage.canonical(again))
        html = cli.render(handoff, "html")
        self.assertEqual(html, cli.render(again, "html"))
        self.assertIn(gaps.POLICY.encode(), html)
        self.assertIn(b"Could not recover jumptable", html)
        self.assertEqual(path.read_bytes(), raw)

    def test_malformed_new_fields_fail_writer_and_reader_even_with_recomputed_digests(self):
        self.capture()
        path = self.workspace.path / "jobs" / self.original / "query-result.json"
        original = json.loads(path.read_bytes())
        producer_path, producer = jobs.get(self.workspace, self.attempt)
        mutations = {
            "policy": lambda ev: ev.update(policy="unsupported"),
            "extra": lambda ev: ev.update(extra=True),
            "identity": lambda ev: ev["function"].update(function_id="f" * 64),
            "site_from_warning": lambda ev: ev.update(location={"kind": "instruction", "instruction_va": self.entry,
                                            "instruction_bytes": self.code.hex(), "byte_verification": "selected_extent",
                                            "original_flow": "TERMINATOR", "effective_flow": "TERMINATOR"}),
            "empty_reason": lambda ev: ev["location"].update(reason=None),
            "claimed_linkage": lambda ev: ev["classification"].update(kind="verified_linkage"),
            "callee": lambda ev: ev["classification"].update(runtime_callee="objc_msgSend"),
        }
        for scenario, mutate in mutations.items():
            with self.subTest(scenario=scenario):
                corrupt = copy.deepcopy(original)
                mutate(corrupt["result"]["data"]["control_flow_gaps"][0]["evidence"])
                self.error("query_receipt", jobs.publish_query, self.workspace, self.original,
                           self.request, corrupt["result"])
                corrupt["result_sha256"] = storage.identity(corrupt["result"])
                storage.write_json(path, corrupt, force=True)
                storage.write_json(producer_path, dict(producer, focused_result_sha256=corrupt["result_sha256"]), force=True)
                before = path.read_bytes()
                self.error("query_receipt", jobs.query_receipt, self.workspace, self.original, self.request)
                self.assertEqual(path.read_bytes(), before)

    def test_legacy_v2_receipt_is_not_augmented_or_rewritten(self):
        self.proof, _ = focused.select(self.workspace, self.image, self.entry, policy="macscope-focused-import/2")
        self.proof["program_sha256"] = self.image["engine_baseline_sha256"]
        self.request = jobs.focused_request(self.workspace, self.image, self.proof)
        self.record.update(focused_import=self.proof, focused_request=self.request)
        self.write_job(self.original, self.record)
        self.capture()
        path = self.workspace.path / "jobs" / self.original / "query-result.json"
        receipt = json.loads(path.read_bytes())
        for gap in receipt["result"]["data"]["control_flow_gaps"]:
            del gap["evidence"]
        receipt["result_sha256"] = storage.identity(receipt["result"])
        producer_path, producer = jobs.get(self.workspace, self.attempt)
        storage.write_json(producer_path, dict(producer, focused_result_sha256=receipt["result_sha256"]), force=True)
        storage.write_json(path, receipt, force=True)
        before = path.read_bytes()
        with patch.object(engine, "run", side_effect=AssertionError("Legacy replay must remain offline")):
            result = self.resume()
        self.assertNotIn("evidence", result["data"]["control_flow_gaps"][0])
        self.assertEqual(path.read_bytes(), before)

    def test_raw_gap_cannot_outlive_its_source_warning(self):
        self.capture()
        receipt = jobs.query_receipt(self.workspace, self.original, self.request)
        changed = copy.deepcopy(receipt)
        changed["data"]["pseudocode"] = "return;"
        self.error("query_receipt", jobs.publish_query, self.workspace, self.original, self.request, changed)

    def test_partial_extension_and_false_complete_results_are_rejected(self):
        self.capture()
        receipt = jobs.query_receipt(self.workspace, self.original, self.request)
        for scenario in ("missing_evidence", "function_complete", "envelope_complete", "bad_extent", "wrong_extent", "wrong_mode"):
            with self.subTest(scenario=scenario):
                changed = copy.deepcopy(receipt)
                if scenario == "missing_evidence":
                    other = dict(changed["data"]["control_flow_gaps"][0])
                    del other["evidence"]
                    changed["data"]["control_flow_gaps"].append(other)
                elif scenario == "function_complete": changed["data"]["decompile_status"] = "complete"
                elif scenario == "envelope_complete": changed["status"] = "complete"
                elif scenario == "bad_extent": changed["data"]["origin"]["extent"] = []
                elif scenario == "wrong_extent": changed["data"]["origin"]["extent"]["extent_sha256"] = "f" * 64
                else: changed["data"]["origin"]["mode"] = "unverified"
                self.error("query_receipt", jobs.publish_query, self.workspace, self.original, self.request, changed)

    def assert_rejected_after_rehash(self, original, mutate, code="query_receipt"):
        path = self.workspace.path / "jobs" / self.original / "query-result.json"
        producer_path, producer = jobs.get(self.workspace, self.attempt)
        corrupt = copy.deepcopy(original)
        mutate(corrupt["result"]["data"])
        self.error(code, jobs.publish_query, self.workspace, self.original, self.request, corrupt["result"])
        corrupt["result_sha256"] = storage.identity(corrupt["result"])
        storage.write_json(path, corrupt, force=True)
        storage.write_json(producer_path, dict(producer, focused_result_sha256=corrupt["result_sha256"]), force=True)
        before = path.read_bytes()
        self.error(code, jobs.query_receipt, self.workspace, self.original, self.request)
        with patch.object(engine, "run", side_effect=AssertionError("Malformed receipt must not launch")):
            self.error(code, self.resume)
        self.assertEqual(path.read_bytes(), before)

    def test_malformed_or_oversized_cfg_is_rejected_before_detector_replay(self):
        self.capture()
        path = self.workspace.path / "jobs" / self.original / "query-result.json"
        original = json.loads(path.read_bytes())
        block = original["result"]["data"]["blocks"][0]
        cases = [None, [1], [dict(block, dsts=[1], flow="COMPUTED_JUMP")],
                 [dict(block, dsts=None)], [dict(block, flow={})],
                 [dict(block, dsts=[{"flow": "COMPUTED_JUMP", "from": [], "to": None}])],
                 [block] * (gaps.MAX_BLOCKS + 1),
                 [dict(block, dsts=[{"flow": "FALL_THROUGH", "from": self.entry, "to": self.entry}]
                                 * (gaps.MAX_EDGES + 1))]]
        for index, blocks in enumerate(cases):
            with self.subTest(index=index):
                self.assert_rejected_after_rehash(original, lambda function: function.update(blocks=blocks))

    def test_unproved_original_flow_and_override_are_rejected_after_rehash(self):
        self.capture()
        path = self.workspace.path / "jobs" / self.original / "query-result.json"
        original = json.loads(path.read_bytes())
        for fields in ({"original_flow": {"arbitrary": "not-a-flow"}}, {"original_flow": ["TERMINATOR"]},
                       {"original_flow": ""}, {"original_flow": "UNCONDITIONAL_JUMP"}, {"flow_override": None},
                       {"flow_override": "CALL_RETURN", "original_flow": "UNCONDITIONAL_JUMP"}):
            with self.subTest(fields=fields):
                code = "focused_tail_calls" if fields.get("flow_override") == "CALL_RETURN" else "query_receipt"
                self.assert_rejected_after_rehash(original, lambda function: function["instructions"][0].update(fields), code)
