"""Owned saved-slice evidence and new analyzed receipt validation."""
import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from macscope import annotations, cli, engine, flow_evidence, html_export, jobs, saved_flow_gap_evidence as saved, storage
from macscope.errors import Error
from test_macho import segment_image


class SavedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name)
        (path / "inputs").mkdir()
        binary = segment_image(section_flags=0x80000400)[:-4] + bytes.fromhex("00001fd6")
        digest = hashlib.sha256(binary).hexdigest()
        self.image = dict(image_id="a" * 64, sha256=digest, artifact_sha256=digest, arch="arm64",
                          active_analysis="b" * 64)
        self.input = path / "inputs" / (self.image["image_id"] + ".macho")
        self.input.write_bytes(binary)
        self.function = dict(function_id="c" * 64, image_id=self.image["image_id"], arch="arm64",
                             entry_va="0x100000100", engine_entry="0x100000100",
                             body_ranges=[["0x100000100", "0x100000103"]], decompile_status="complete",
                             pseudocode="/* WARNING: Could not recover jumptable at 0x100000100 */",
                             coverage={}, instructions=[dict(addr="0x100000100", bytes="00001fd6", flow="COMPUTED_JUMP")],
                             blocks=[dict(min="0x100000100", max="0x100000103", flow="COMPUTED_JUMP", dsts=[], edges_truncated=False)])
        self.snapshot = dict(image=self.image, functions=[self.function], analysis_id="b" * 64, status="complete")
        self.source = dict(snapshot_sha256="d" * 64, analysis_program_sha256="e" * 64)
        self.project = SimpleNamespace(path=path, select=lambda *args, **kw: self.image,
                                       snapshot=lambda image: (self.snapshot, self.source))
        self.request = dict(image_id=self.image["image_id"], source_analysis_id="b" * 64,
                            source_snapshot_sha256="d" * 64, source_program_sha256="e" * 64,
                            slice_sha256=digest, artifact_sha256=digest,
                            function_id="c" * 64, entry_va=self.function["entry_va"])

    def selected(self):
        return flow_evidence.snapshot_view(self.snapshot)["functions"][0]

    def result(self):
        return saved.annotate_query(self.project, self.image, self.snapshot, self.source,
                                    dict(data=dict(self.selected(), origin={"mode": "fresh_readonly"}),
                                         status="partial", analysis_id="b" * 64), self.request)

    def test_cached_exact_warning_and_deterministic_source_preservation(self):
        original = copy.deepcopy(self.snapshot)
        selected = self.selected()
        result = saved.annotate_selected(self.project, self.image, self.snapshot, self.source, selected)
        first, warning = result["control_flow_gaps"]
        self.assertEqual(first["evidence"]["location"]["instruction_bytes"], "00001fd6")
        self.assertEqual(first["evidence"]["location"]["byte_verification"], "saved_slice")
        self.assertEqual(warning["evidence"]["location"]["kind"], "unavailable")
        self.assertEqual(self.snapshot, original)
        again = saved.annotate_selected(self.project, self.image, self.snapshot, self.source, result)
        self.assertEqual(storage.canonical(result), storage.canonical(again))

    def test_fresh_reader_validation_and_rehashed_mutations(self):
        result = self.result()
        saved.validate_result(self.project, result, self.request)
        for mutate in (
            lambda r: r["data"]["control_flow_gaps"][0]["evidence"].update(policy="unknown"),
            lambda r: r["data"]["control_flow_gaps"][0]["evidence"]["location"].update(instruction_bytes="01001fd6"),
            lambda r: r["data"]["control_flow_gaps"].pop(),
            lambda r: r["data"].update(flow_gap_sources=[]),
            lambda r: r["data"]["control_flow_gaps"][0]["evidence"]["function"].update(program_sha256="0" * 64),
            lambda r: r.update(status="complete"),
        ):
            forged = copy.deepcopy(result)
            mutate(forged)
            storage.identity(forged)  # A newly recomputed digest is not authority.
            with self.assertRaises(Error) as caught:
                saved.validate_result(self.project, forged, self.request)
            self.assertEqual(caught.exception.code, "query_receipt")

    def test_old_receipt_noop_never_reads_project(self):
        old = dict(data=self.selected())
        original = copy.deepcopy(old)
        saved.validate_result(None, old, {})
        self.assertEqual(old, original)

    def test_wrong_source_unknown_and_duplicate_fail_typed(self):
        for mode in ("missing", "duplicate", "unknown"):
            snapshot = copy.deepcopy(self.snapshot)
            if mode == "missing": snapshot["functions"] = []
            elif mode == "duplicate": snapshot["functions"] *= 2
            else: snapshot["functions"][0]["function_id"] = "f" * 64
            with self.assertRaises(Error):
                saved.annotate_selected(self.project, self.image, snapshot, self.source, self.selected())

    def test_source_byte_and_slice_hash_mismatch_fail(self):
        result = self.result()
        self.function["instructions"][0]["bytes"] = "01001fd6"
        with self.assertRaises(Error): saved.validate_result(self.project, result, self.request)
        self.function["instructions"][0]["bytes"] = "00001fd6"
        self.input.write_bytes(self.input.read_bytes()[:-1] + b"x")
        with self.assertRaises(Error): saved.validate_result(self.project, result, self.request)

    def test_incoming_boundary_never_uses_predecessor_bytes(self):
        self.image["loader"] = {"function_starts": {"status": "complete", "addresses": ["0x100000100", "0x100000120"]}}
        self.function["coverage"] = {"cfg": {"status": "complete"}, "body_ranges": {"status": "complete"}}
        self.function["blocks"][0]["dsts"] = [dict(flow="FALL_THROUGH", **{"from": "0x100000100", "to": "0x100000104"})]
        second = dict(self.function, function_id="f" * 64, entry_va="0x100000104", engine_entry="0x100000104",
                      body_ranges=[["0x100000104", "0x100000107"]], instructions=[], blocks=[], pseudocode="return;")
        self.snapshot["functions"].append(second)
        selected = flow_evidence.snapshot_view(self.snapshot)["functions"][1]
        annotated = saved.annotate_selected(self.project, self.image, self.snapshot, self.source, selected)
        self.assertEqual(annotated["control_flow_gaps"][0]["evidence"]["location"],
                         {"kind": "unavailable", "reason": "source_belongs_to_related_function"})

    def test_assisted_switch_result_unchanged(self):
        response = dict(data=dict(self.selected(), origin={"switch_table_recovery": {"status": "applied"}}))
        self.assertIs(saved.annotate_query(self.project, self.image, self.snapshot, self.source, response, self.request), response)

    def test_production_writer_reader_and_rehashed_receipt(self):
        """The real immutable receipt path must invoke the extension validator."""
        job_id = "1" * 32
        directory = self.project.path / "jobs" / job_id
        directory.mkdir(parents=True)
        request = dict(self.request, schema=jobs.QUERY_REQUEST)
        result = self.result()
        result["data"]["origin"]["job_id"] = job_id
        producer = dict(mode="query", status="complete", query_request=request)
        with patch.object(jobs, "get", return_value=(directory / "job.json", producer)):
            published = jobs.publish_query(self.project, job_id, request, result)
            path = directory / "query-result.json"
            before = path.read_bytes()
            self.assertEqual(jobs.query_receipt(self.project, job_id, request), published)
            self.assertEqual(path.read_bytes(), before)
            forged = copy.deepcopy(published)
            forged["data"]["control_flow_gaps"][0]["evidence"]["classification"]["kind"] = "verified_linkage_boundary"
            receipt = dict(schema=jobs.QUERY_RECEIPT, request_sha256=storage.identity(request),
                           result_sha256=storage.identity(forged), result=forged)
            path.chmod(0o600)
            path.write_bytes(storage.canonical(receipt) + b"\n")
            with self.assertRaises(Error) as caught:
                jobs.query_receipt(self.project, job_id, request)
            self.assertEqual(caught.exception.code, "query_receipt")
            with self.assertRaises(Error):
                jobs.publish_query(self.project, "2" * 32, request, forged)

    def test_missing_or_duplicate_instructions_only_support_block(self):
        for rows in ([], [*self.function["instructions"], *self.function["instructions"]]):
            with self.subTest(rows=rows):
                self.function["instructions"] = rows
                result = saved.annotate_selected(self.project, self.image, self.snapshot, self.source, self.selected())
                self.assertEqual(result["control_flow_gaps"][0]["evidence"]["location"]["kind"], "block_range")

    def test_unknown_raw_gap_cannot_be_added_to_a_rehashed_receipt(self):
        result = self.result()
        forged = copy.deepcopy(result["data"]["control_flow_gaps"][0])
        forged["reason"] = "invented_reason"
        result["data"]["control_flow_gaps"].append(forged)
        with self.assertRaises(Error): saved.validate_result(self.project, result, self.request)

    def test_native_scope_malformed_is_typed(self):
        result = self.result()
        for malformed in ([], 42, {"status": "partial"}):
            result["data"]["native_scope"] = malformed
            with self.assertRaises(Error) as caught:
                saved.validate_result(self.project, result, self.request)
            self.assertEqual(caught.exception.code, "query_receipt")

    def test_warning_only_still_checks_saved_slice_integrity(self):
        self.function["blocks"] = []
        self.function["instructions"] = []
        selected = self.selected()
        self.input.write_bytes(b"damaged")
        with self.assertRaises(Error):
            saved.annotate_selected(self.project, self.image, self.snapshot, self.source, selected)

    def test_cached_public_cli_projections_preserve_pins_and_annotations(self):
        self.function.update(names=[{"name": "owned", "origin": "ghidra"}])
        note = dict(kind="name", engine_entry=self.function["entry_va"], value="owned_renamed", revision=1)
        original = copy.deepcopy(self.snapshot)
        with (patch.object(cli, "Project", return_value=self.project),
              patch.object(annotations, "read", return_value=(1, [note])),
              patch.object(engine, "run", side_effect=AssertionError("cached query launched worker"))):
            for command in (("functions", "show"), ("decompile",), ("cfg",), ("disasm",)):
                args = cli.parser().parse_args([*command, "--project", str(self.project.path),
                                                "--address", self.function["entry_va"], "--json"])
                first = cli.execute(args)
                second = cli.execute(args)
                self.assertEqual(storage.canonical(first), storage.canonical(second))
                self.assertEqual(first["status"], "partial")
                gap = first["data"]["control_flow_gaps"][0]
                self.assertEqual(gap["evidence"]["function"]["snapshot_sha256"], self.source["snapshot_sha256"])
                if command[0] in ("functions", "decompile"):
                    self.assertEqual(first["data"]["names"][-1]["name"], "owned_renamed")
        self.assertEqual(self.snapshot, original)

    def test_actual_fresh_producer_publishes_durable_slim_result(self):
        self.project.project_id = "9" * 64
        self.function.update(names=[{"name": "owned", "origin": "ghidra"}], is_thunk=False, is_external=False)
        job_id = "7" * 32
        directory = self.project.path / "jobs" / job_id
        directory.mkdir(parents=True)
        args = cli.parser().parse_args(["decompile", "--fresh", "--project", str(self.project.path),
                                        "--address", self.function["entry_va"]])
        request = jobs.query_request(self.project, self.image, self.function, self.source, 0, None,
                                     flow_gap_policy=saved.POLICY)
        worker_function = dict(pseudocode=self.function["pseudocode"], decompile_status="complete",
                               pseudocode_truncated=False, coverage={"pseudocode": {"status": "complete"}})
        job = dict(job_id=job_id, analysis_profile="owned-test", mode="query", status="complete", query_request=request)
        worker = dict(functions=[worker_function], bridge_version="owned-test")
        with (patch.object(engine, "run", return_value=(worker, job)) as run,
              patch.object(jobs, "get", return_value=(directory / "job.json", job))):
            result = cli.fresh_decompile(args, self.project, self.image, self.selected(), self.source,
                                         0, deps={"owned": True})
            self.assertEqual(run.call_args.kwargs["query_request"]["flow_gap_policy"], saved.POLICY)
            self.assertIn(saved.SOURCE_FIELD, result["data"])
            self.assertNotIn("instructions", result["data"])
            self.assertEqual(result["data"]["control_flow_gaps"][0]["evidence"]["derivation"],
                             "fresh_query_with_saved_flow")
            before = (directory / "query-result.json").read_bytes()
            self.assertEqual(jobs.query_receipt(self.project, job_id, request), result)
            self.assertEqual((directory / "query-result.json").read_bytes(), before)
            self.assertEqual(result["data"]["engine_decompile_status"], "complete")
            self.assertEqual(result["data"]["decompile_status"], "partial")

    def test_switch_fresh_keeps_legacy_receipt_and_adds_boundary_once(self):
        self.project.project_id = "9" * 64
        self.function.update(names=[{"name": "owned", "origin": "ghidra"}], is_thunk=False, is_external=False)
        selected = self.selected()
        boundary = dict(reason="fallthrough_into_unconfirmed_function", source="ghidra_cfg_and_linker_starts",
                        **{"from": "0x100000100", "to": "0x100000104", "linker_entry_va": "0x100000100"})
        selected["control_flow_gaps"].append(boundary)
        job_id = "8" * 32
        directory = self.project.path / "jobs" / job_id
        directory.mkdir(parents=True)
        args = cli.parser().parse_args(["decompile", "--fresh", "--project", str(self.project.path),
                                        "--address", self.function["entry_va"]])
        decision = {"status": "not_applied"}
        recovery = ("switch_table_recovery", {})
        request = jobs.query_request(self.project, self.image, self.function, self.source, 0, None,
                                     signature_recovery=recovery)
        job = dict(job_id=job_id, analysis_profile="owned-test", mode="query", status="complete", query_request=request)
        worker = dict(functions=[dict(pseudocode=self.function["pseudocode"], decompile_status="complete",
                                      pseudocode_truncated=False, coverage={"pseudocode": {"status": "complete"}})],
                      bridge_version="owned-test", switch_table_recovery=decision)
        with (patch.object(engine, "run", return_value=(worker, job)),
              patch.object(engine, "signature_request", return_value=recovery),
              patch.object(jobs, "get", return_value=(directory / "job.json", job))):
            returned = cli.fresh_decompile(args, self.project, self.image, selected, self.source,
                                           0, deps={}, signature_plan={"owned": True})
            self.assertNotIn(saved.SOURCE_FIELD, returned["data"])
            self.assertEqual(returned["data"]["control_flow_gaps"].count(boundary), 1)
            path = directory / "query-result.json"
            before = path.read_bytes()
            receipt = jobs.query_receipt(self.project, job_id, request)
            self.assertNotIn(boundary, receipt["data"]["control_flow_gaps"])
            self.assertFalse(any("evidence" in gap for gap in receipt["data"]["control_flow_gaps"]))
            replay = flow_evidence.query_view(receipt, selected)
            self.assertEqual(replay, returned)
            self.assertEqual(path.read_bytes(), before)


    def test_saved_derived_html_preserves_pins_and_escapes_raw_warning(self):
        self.function["pseudocode"] = "/* WARNING: Could not recover jumptable at <script> */"
        function = saved.annotate_selected(self.project, self.image, self.snapshot, self.source, self.selected())
        snapshot = dict(self.snapshot, functions=[function], engine={})
        response = cli.envelope("export", snapshot, self.snapshot["analysis_id"], "partial",
                                cli.coverage("owned selected derived evidence", 1, 1, True))
        first = html_export.render(response)
        self.assertEqual(first, html_export.render(response))
        self.assertIn(saved.POLICY.encode(), first)
        self.assertIn(self.source["snapshot_sha256"].encode(), first)
        self.assertIn(b"&lt;script&gt;", first)
        self.assertNotIn(b"<script>", first)

    def test_legacy_cached_source_without_durable_pins_is_unchanged(self):
        selected = self.selected()
        original = copy.deepcopy(selected)
        for source in ({}, {"snapshot_sha256": "d" * 64}, {"analysis_program_sha256": "e" * 64}):
            with self.subTest(source=source):
                # No independent bytes can be claimed without both source pins.
                self.assertIs(saved.annotate_selected(None, self.image, self.snapshot, source, selected), selected)
                self.assertEqual(selected, original)
        self.function.update(names=[{"name": "owned", "origin": "ghidra"}])
        self.project.snapshot = lambda image: (self.snapshot, {})
        with (patch.object(cli, "Project", return_value=self.project),
              patch.object(annotations, "read", return_value=(0, [])),
              patch.object(engine, "run", side_effect=AssertionError("legacy read launched worker"))):
            for command in (("functions", "show"), ("decompile",), ("cfg",), ("disasm",)):
                args = cli.parser().parse_args([*command, "--project", str(self.project.path),
                                                "--address", self.function["entry_va"], "--json"])
                result = cli.execute(args)
                self.assertEqual(result["status"], "partial")
                self.assertTrue(result["data"]["control_flow_gaps"])
                self.assertFalse(any("evidence" in gap for gap in result["data"]["control_flow_gaps"]))

    def test_invalid_provided_pin_or_new_evidence_never_downgrades_to_legacy(self):
        selected = self.selected()
        for key in ("snapshot_sha256", "analysis_program_sha256"):
            for value in (None, "bad-digest", [], 3):
                with self.subTest(key=key, value=value):
                    with self.assertRaises(Error) as caught:
                        saved.annotate_selected(None, self.image, self.snapshot, {key: value}, selected)
                    self.assertEqual(caught.exception.code, "query_receipt")
        annotated = saved.annotate_selected(self.project, self.image, self.snapshot, self.source, selected)
        with self.assertRaises(Error):
            saved.annotate_selected(None, self.image, self.snapshot, {}, annotated)

    def test_request_policy_rejects_rehashed_extension_removal_and_false_complete(self):
        job_id = "6" * 32
        directory = self.project.path / "jobs" / job_id
        directory.mkdir(parents=True)
        request = dict(self.request, schema=jobs.QUERY_REQUEST, flow_gap_policy=saved.POLICY)
        result = self.result()
        result["data"]["origin"]["job_id"] = job_id
        producer = dict(mode="query", status="complete", query_request=request)
        def remove_extensions(row):
            row["data"].pop(saved.SOURCE_FIELD)
            for gap in row["data"]["control_flow_gaps"]:
                gap.pop("evidence")
        def remove_all(row):
            row["data"].pop(saved.SOURCE_FIELD)
            row["data"].pop("control_flow_gaps")
        def false_complete(row):
            remove_all(row)
            row["status"] = "complete"
            row["data"]["decompile_status"] = "complete"
        with patch.object(jobs, "get", return_value=(directory / "job.json", producer)):
            jobs.publish_query(self.project, job_id, request, result)
            self.assertEqual(jobs.query_receipt(self.project, job_id, request), result)
            for change in (remove_extensions, remove_all, false_complete):
                forged = copy.deepcopy(result)
                change(forged)
                path = directory / "query-result.json"
                receipt = dict(schema=jobs.QUERY_RECEIPT, request_sha256=storage.identity(request),
                               result_sha256=storage.identity(forged), result=forged)
                path.chmod(0o600)
                path.write_bytes(storage.canonical(receipt) + b"\n")
                with self.subTest(change=change.__name__):
                    with self.assertRaises(Error) as caught:
                        jobs.query_receipt(self.project, job_id, request)
                    self.assertEqual(caught.exception.code, "query_receipt")
                    with self.assertRaises(Error):
                        jobs.publish_query(self.project, "5" * 32, request, forged)

    def test_required_policy_without_source_gaps_forbids_extension_and_fabricated_gaps(self):
        self.function.update(blocks=[], instructions=[], pseudocode="return;")
        request = dict(self.request, flow_gap_policy=saved.POLICY)
        data = dict(self.function, origin={"mode": "fresh_readonly"})
        result = dict(data=data, status="complete", analysis_id=self.snapshot["analysis_id"])
        saved.validate_result(self.project, result, request)
        for mutation in ({saved.SOURCE_FIELD: {"policy": saved.POLICY}},
                         {"control_flow_gaps": [{"reason": "invented"}]}):
            forged = dict(result, data=dict(data, **mutation))
            with self.assertRaises(Error): saved.validate_result(self.project, forged, request)
        with self.assertRaises(Error) as caught:
            saved.validate_result(self.project, result, dict(request, switch_table_recovery={}))
        self.assertEqual(caught.exception.code, "query_receipt")
        assisted = dict(result, data=dict(data, origin={"mode": "fresh_readonly", "switch_table_recovery": {}}))
        with self.assertRaises(Error) as caught:
            saved.validate_result(self.project, assisted, request)
        self.assertEqual(caught.exception.code, "query_receipt")
        for policy in (None, "unknown", [], 3):
            with self.assertRaises(Error) as caught:
                saved.validate_result(None, {}, dict(request, flow_gap_policy=policy))
            self.assertEqual(caught.exception.code, "query_receipt")

    def test_range_budget_is_checked_before_instruction_index(self):
        self.function["body_ranges"] *= saved.sites.MAX_RANGES + 1
        with patch.object(saved.sites, "instruction_index", side_effect=AssertionError("unbounded scan")) as index:
            indexed, reason = saved._verify(self.project, self.image, self.function)
            self.assertEqual((indexed, reason), ({}, "instruction_evidence_limit"))
            index.assert_not_called()
        for ranges in (None, {}, "bad", 42):
            with self.subTest(ranges=ranges):
                self.function["body_ranges"] = ranges
                function = dict(self.function, control_flow_gaps=[{"reason": "computed_jump_destination_unavailable"}])
                with patch.object(saved.sites, "instruction_index", side_effect=AssertionError("malformed scan")) as index:
                    with self.assertRaises(Error) as caught:
                        saved.annotate_selected(self.project, self.image, self.snapshot, self.source, function)
                    self.assertEqual(caught.exception.code, "query_receipt")
                    index.assert_not_called()

    def test_new_complete_fresh_query_pins_policy_without_inventing_gaps(self):
        self.project.project_id = "9" * 64
        self.function.update(names=[{"name": "owned", "origin": "ghidra"}], is_thunk=False, is_external=False,
                             blocks=[], instructions=[], pseudocode="return;")
        job_id = "4" * 32
        directory = self.project.path / "jobs" / job_id
        directory.mkdir(parents=True)
        args = cli.parser().parse_args(["decompile", "--fresh", "--project", str(self.project.path),
                                        "--address", self.function["entry_va"]])
        request = jobs.query_request(self.project, self.image, self.function, self.source, 0, None,
                                     flow_gap_policy=saved.POLICY)
        worker_function = dict(pseudocode="return;", decompile_status="complete", pseudocode_truncated=False,
                               coverage={"pseudocode": {"status": "complete"}})
        job = dict(job_id=job_id, analysis_profile="owned-test", mode="query", status="complete", query_request=request)
        worker = dict(functions=[worker_function], bridge_version="owned-test")
        with (patch.object(engine, "run", return_value=(worker, job)) as run,
              patch.object(jobs, "get", return_value=(directory / "job.json", job))):
            result = cli.fresh_decompile(args, self.project, self.image, self.function, self.source, 0, deps={})
            self.assertEqual(run.call_args.kwargs["query_request"], request)
            self.assertEqual(result["status"], "complete")
            self.assertNotIn(saved.SOURCE_FIELD, result["data"])
            self.assertNotIn("control_flow_gaps", result["data"])
            self.assertEqual(jobs.query_receipt(self.project, job_id, request), result)
