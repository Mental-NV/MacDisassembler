"""Engine-free tests for research evidence integrity and exact fixture regressions."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "analysis"))
import validate_decompiler_evidence as evidence
import prototype_experiment as experiment


def function(entry="0x100", name="_calc_engine_input_digit", code="return;"):
    return {"entry_va": entry, "name": name, "signature": "undefined function(void)",
            "calling_convention": "unknown", "pseudocode": code,
            "decompile_status": "complete", "body_ranges": [[entry, "0x103"]],
            "instructions": [], "blocks": [], "instruction_count": 0, "block_count": 0,
            "is_external": False, "is_thunk": False, "pseudocode_truncated": False,
            "instructions_truncated": False, "blocks_truncated": False, "edges_truncated": False,
            "coverage": {name: {"status": "complete", "truncated": False, "error": None,
                                "emitted": count} for name, count in
                         [("body_ranges", 1), ("instructions", 0), ("cfg", 0), ("pseudocode", 1)]}}


def result(mode="default"):
    return {"schema": "macscope-bridge/1", "ghidra_version": "12.2",
            "mode": "query" if mode == "callee" else "analyze",
            "validation": {"headless_analysis_enabled": mode != "callee"},
            "executable_sha256": "0" * 64, "analysis_timed_out": False,
            "functions_truncated": False, "output_budget_reached": False,
            "status": "complete", "errors": [], "functions": [function()],
            "function_count_enumerated": 1, "function_count_total_reported_by_engine": 1,
            "coverage": {"functions": {"status": "complete", "truncated": False,
                                       "error": None, "emitted": 1, "total": 1}},
            "analysis_profile": {"name": experiment.PROFILE + mode, "applied": True},
            "effective_analysis_options": {"DWARF": "false", "Decompiler Parameter ID":
                                          "true" if mode == "paramid" else "false"}}


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)

    def snapshot(self, arch="arm64"):
        raw = bytes.fromhex("02000014" if arch == "arm64" else "eb06")
        f = function()
        f["body_ranges"] = [["0x100", hex(0x100 + len(raw) - 1)]]
        f["instructions"] = [{"addr": "0x100", "bytes": raw.hex(),
                             "text": "b 0x108" if arch == "arm64" else "JMP 0x108",
                             "flow": "UNCONDITIONAL_JUMP",
                             "location": {"slice_file_offset": "0x0"}}]
        s = {"image": {"arch": arch, "sha256": evidence.sha(raw)}, "functions": [f]}
        llvm = "100: " + ("14000002" if arch == "arm64" else "eb 06") + " \tb\t0x108 <target>\n"
        return s, raw, llvm

    def test_duplicate_names_are_not_collapsed(self):
        fs = [function("0x100", "same"), function("0x200", "same")]
        self.assertEqual(len(evidence.index_functions(fs)), 2)

    def test_normalized_external_null_vas_keep_engine_identity(self):
        first = function(None, "_external")
        first.update(address_space="EXTERNAL", engine_entry="EXTERNAL:00000001", is_external=True)
        second = copy.deepcopy(first); second["engine_entry"] = "EXTERNAL:00000002"
        self.assertEqual(len(evidence.index_functions([first, second])), 2)
        first.pop("engine_entry")
        with self.assertRaises(ValueError):
            evidence.index_functions([first])

    def test_duplicate_addresses_and_empty_population_rejected(self):
        for fs in ([function(), function()], []):
            with self.assertRaises(ValueError):
                evidence.index_functions(fs)

    def test_compare_same_identity_and_machine_facets(self):
        a = result(); b = copy.deepcopy(a)
        b["functions"][0]["pseudocode"] = "changed;"
        compared = evidence.compare_results(a, b)
        self.assertTrue(compared["unchanged_machine_facets"])
        self.assertEqual(len(compared["changes"]["pseudocode"]), 1)

    def test_equal_incomplete_inventories_never_pass_comparison(self):
        for field, value in (
            ("functions_truncated", True), ("output_budget_reached", True),
            ("analysis_timed_out", True), ("errors", ["Analysis failed"]),
            ("function_count_enumerated", 2), ("function_count_total_reported_by_engine", 2),
            ("coverage", {}),
        ):
            incomplete = result()
            incomplete.update(status="partial")
            incomplete[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                evidence.compare_results(incomplete, copy.deepcopy(incomplete))
        for field, value in (
            ("status", "failed"), ("truncated", True), ("error", "Iteration failed"),
            ("emitted", 0), ("total", 2),
        ):
            incomplete = result()
            incomplete["coverage"]["functions"][field] = value
            with self.subTest(facet_field=field), self.assertRaises(ValueError):
                evidence.compare_results(incomplete, copy.deepcopy(incomplete))

    def test_unmeasured_partial_facets_do_not_block_comparison(self):
        partial = result()
        partial["status"] = "partial"
        partial["functions"][0]["coverage"]["xrefs_from_sample"] = {
            "status": "partial", "truncated": True, "emitted": 200,
        }
        compared = evidence.compare_results(result(), partial)
        self.assertTrue(compared["unchanged_machine_facets"])

    def test_compare_detects_machine_or_status_changes(self):
        for field, value in [("body_ranges", []), ("instructions", [{"addr": "0x100"}]),
                             ("blocks", [{"min": "0x100"}]), ("decompile_status", "failed")]:
            a = result(); b = copy.deepcopy(a); b["functions"][0][field] = value
            with self.subTest(field=field):
                # Malformed/incomplete counts are rejected before equality is considered.
                with self.assertRaises(ValueError):
                    evidence.compare_results(a, b)

    def test_compare_rejects_input_and_entry_mismatch(self):
        a = result(); b = copy.deepcopy(a); b["executable_sha256"] = "1" * 64
        with self.assertRaises(ValueError): evidence.compare_results(a, b)
        b = copy.deepcopy(a); b["functions"][0]["entry_va"] = "0x200"
        with self.assertRaises(ValueError): evidence.compare_results(a, b)

    def test_added_option_is_not_silently_ignored(self):
        a = result(); b = copy.deepcopy(a)
        b["effective_analysis_options"]["Unexpected"] = "true"
        self.assertEqual(evidence.compare_results(a, b)["option_deltas"],
                         {"Unexpected": [None, "true"]})

    def test_exact_known_bad_and_good_regressions(self):
        bad = [function(code="_calc_latch_error(iVar1,param_1,3);")]
        self.assertTrue(evidence.calculator_call_regression(bad)["known_extra_argument_observed"])
        good = [function(code="if ((param_2 < 0) || (9 < param_2)) "
                              "_calc_latch_error((long)param_1,3);")]
        self.assertTrue(evidence.calculator_call_regression(good)
                        ["expected_inferred_call_and_guard_observed"])

    def test_unknown_or_conflicting_pseudocode_is_not_a_pass(self):
        for code in ("return;", "_calc_latch_error((long)param_1,3);",
                     "if ((param_2 < 0) || (9 < param_2)) _calc_latch_error((long)param_1,3); "
                     "_calc_latch_error(iVar1,param_1,3);"):
            self.assertFalse(evidence.calculator_call_regression([function(code=code)])
                             ["expected_inferred_call_and_guard_observed"])
        with self.assertRaises(ValueError):
            evidence.calculator_call_regression([function(), function("0x200")])

    def test_arm_word_and_x86_byte_order(self):
        for arch in ("arm64", "x86_64"):
            s, raw, llvm = self.snapshot(arch)
            with self.subTest(arch=arch):
                r = evidence.adjudicate_snapshot(s, raw, llvm)
                self.assertEqual(r["status"], "passed")
                self.assertEqual(r["instructions_checked"], 1)
                self.assertEqual(r["direct_targets_checked"], 1)
                self.assertEqual(r["direct_targets_unmeasured"], 0)

    def test_llvm_empty_duplicate_and_bad_arch_rejected(self):
        for text, arch in [("", "arm64"), ("100: 00 \tret", "arm64"),
                           ("100: 90 \tnop\n100: 90 \tnop", "x86_64"),
                           ("100: 00 \tret", "arm64e")]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                evidence.parse_llvm(text, arch)

    def test_equal_counts_do_not_hide_bytes_boundaries_or_target_changes(self):
        s, raw, llvm = self.snapshot()
        for changed in (llvm.replace("14000002", "14000003"),
                        llvm.replace("100:", "101:"), llvm.replace("0x108", "0x10c")):
            self.assertEqual(evidence.adjudicate_snapshot(s, raw, changed)["status"], "failed")

    def test_wrong_binary_identity_fails(self):
        s, raw, llvm = self.snapshot()
        with self.assertRaises(ValueError):
            evidence.adjudicate_snapshot(s, b"wrong", llvm)

    def test_raw_offset_and_emitted_bytes_are_checked(self):
        for offset in ("0x1000", "-0x1"):
            s, raw, llvm = self.snapshot()
            s["functions"][0]["instructions"][0]["location"]["slice_file_offset"] = offset
            self.assertEqual(evidence.adjudicate_snapshot(s, raw, llvm)["status"], "failed")

    def test_incomplete_empty_or_duplicate_instructions_fail(self):
        for kind in ("truncated", "duplicate", "empty", "outside"):
            s, raw, llvm = self.snapshot(); f = s["functions"][0]
            if kind == "truncated": f["instructions_truncated"] = True
            if kind == "duplicate": f["instructions"] *= 2
            if kind == "empty": f["instructions"] = []
            if kind == "outside": f["body_ranges"] = [["0x200", "0x203"]]
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                evidence.adjudicate_snapshot(s, raw, llvm)

    def test_unmeasured_direct_target_is_explicit(self):
        s, raw, llvm = self.snapshot()
        r = evidence.adjudicate_snapshot(s, raw, llvm.replace("0x108 <target>", "target"))
        self.assertEqual(r["direct_targets_checked"], 0)
        self.assertEqual(r["direct_targets_unmeasured"], 1)

    def test_exclusive_evidence_output(self):
        p = self.path / "report.json"
        evidence.write_new_json(p, {"old": True})
        with self.assertRaises(FileExistsError):
            evidence.write_new_json(p, {"old": False})
        self.assertEqual(evidence.read_json(p), {"old": True})

    def test_cli_offline_text_does_not_launch_a_process(self):
        s, raw, llvm = self.snapshot()
        (self.path / "binary").write_bytes(raw)
        (self.path / "llvm.txt").write_text(llvm)
        (self.path / "export.json").write_text(json.dumps({"data": s}))
        with mock.patch.object(evidence.subprocess, "run") as run:
            code = evidence.main(["--binary", str(self.path / "binary"), "--export",
                str(self.path / "export.json"), "--llvm-text", str(self.path / "llvm.txt"),
                "--output", str(self.path / "report.json")])
        self.assertEqual(code, 0); run.assert_not_called()


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)

    def test_valid_result_is_operation_completion_only(self):
        experiment.validate_result(result(), "0" * 64, "default")

    def test_invalid_result_states_fail_closed(self):
        for field, value in [("schema", "other"), ("executable_sha256", "bad"),
                             ("analysis_timed_out", True), ("functions_truncated", True),
                             ("output_budget_reached", True), ("status", "failed"),
                             ("function_count_enumerated", 2), ("errors", ["failure"])]:
            x = result(); x[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                experiment.validate_result(x, "0" * 64, "default")

    def test_profile_and_source_options_checked(self):
        for change in ("marker", "applied", "paramid", "source"):
            x = result()
            if change == "marker": x["analysis_profile"]["name"] = "wrong"
            if change == "applied": x["analysis_profile"]["applied"] = False
            if change == "paramid": x["effective_analysis_options"]["Decompiler Parameter ID"] = "true"
            if change == "source": x["effective_analysis_options"]["DWARF"] = "true"
            with self.subTest(change=change), self.assertRaises(ValueError):
                experiment.validate_result(x, "0" * 64, "default")

    def test_dormant_reopen_options_require_noanalysis_query(self):
        a = result("callee")
        a["effective_analysis_options"]["External Symbol Resolver"] = "true"
        experiment.validate_result(a, "0" * 64, "callee")
        a["validation"]["headless_analysis_enabled"] = True
        with self.assertRaises(ValueError):
            experiment.validate_result(a, "0" * 64, "callee")
        a["validation"]["headless_analysis_enabled"] = False
        a["mode"] = "analyze"
        with self.assertRaises(ValueError):
            experiment.validate_result(a, "0" * 64, "callee")

    def test_native_failures_and_empty_pseudocode_rejected(self):
        for status in ("failed", "timeout", "cancelled"):
            x = result(); x["functions"][0]["decompile_status"] = status
            with self.assertRaises(ValueError):
                experiment.validate_result(x, "0" * 64, "default")
        x = result(); x["functions"][0]["pseudocode"] = ""
        with self.assertRaises(ValueError):
            experiment.validate_result(x, "0" * 64, "default")

    def test_prepare_scripts_versions_experiment_without_editing_production(self):
        source = ROOT / "src/macscope/bridge/MacscopeProfile.java"
        before = source.read_bytes()
        for mode in ("default", "paramid", "callee"):
            destination = self.path / mode
            hashes = experiment.prepare_scripts(destination, mode)
            bridge = (destination / "MacscopeBridge.java").read_text()
            self.assertIn(experiment.PROFILE + mode, bridge)
            self.assertIn("MacscopeBridge.java", hashes)
            if mode != "callee":
                profile = (destination / "MacscopeProfile.java").read_text()
                self.assertIn(experiment.PROFILE + mode, profile)
                marker = experiment.PARAMETER_MARKER if mode == "paramid" else experiment.MARKER
                self.assertNotIn(marker, profile)
        self.assertEqual(source.read_bytes(), before)

    def test_profile_adapter_rejects_drift_or_unknown_mode(self):
        with self.assertRaises(ValueError):
            experiment.prepare_scripts(self.path / "bad", "unknown")
        with mock.patch.object(experiment, "MARKER", '"not-present"'), self.assertRaises(ValueError):
            experiment.prepare_scripts(self.path / "drift", "default")

    def make_manifest(self):
        d = self.path / "analyst/DebugAnalysis-arm64-sym"; d.mkdir(parents=True)
        data = b"owned fixture for path/hash test"
        p = d / "CorpusFixture"; p.write_bytes(data)
        m = {"schema": "macscope-phase1-manifest/2", "source": {"semantics_version": "1.1"},
             "artifacts": [{"name": "CorpusFixture", "config": "DebugAnalysis", "arch": "arm64",
                            "symbols": "sym", "container": "thin", "sha256": evidence.sha(data)}]}
        (self.path / "manifest.json").write_text(json.dumps(m))
        return p, m

    def test_fixture_manifest_hash_and_unique_match(self):
        p, m = self.make_manifest()
        self.assertEqual(experiment.fixture_input(self.path, "DebugAnalysis-arm64")[0], p.resolve())
        p.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            experiment.fixture_input(self.path, "DebugAnalysis-arm64")
        m["artifacts"] *= 2; (self.path / "manifest.json").write_text(json.dumps(m))
        with self.assertRaises(ValueError):
            experiment.fixture_input(self.path, "DebugAnalysis-arm64")

    def test_fixture_symlink_and_old_manifest_rejected(self):
        p, m = self.make_manifest(); saved = self.path / "elsewhere"; p.rename(saved); p.symlink_to(saved)
        with self.assertRaises(ValueError):
            experiment.fixture_input(self.path, "DebugAnalysis-arm64")
        m["schema"] = "macscope-phase1-manifest/1"
        (self.path / "manifest.json").write_text(json.dumps(m))
        with self.assertRaises(ValueError):
            experiment.fixture_input(self.path, "DebugAnalysis-arm64")

    def test_equal_but_incomplete_facets_never_pass_comparison(self):
        for key in ("pseudocode_truncated", "instructions_truncated", "blocks_truncated",
                    "edges_truncated", "instructions_error", "cfg_error", "signature_error"):
            a = result()
            a["functions"][0][key] = True if key.endswith("truncated") else "failed"
            with self.subTest(key=key), self.assertRaises(ValueError):
                evidence.compare_results(a, copy.deepcopy(a))
        for key in ("body_ranges", "instructions", "cfg", "pseudocode"):
            a = result(); a["functions"][0]["coverage"][key]["truncated"] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                evidence.compare_results(a, copy.deepcopy(a))

    def test_internal_not_requested_is_rejected(self):
        a = result(); a["functions"][0]["decompile_status"] = "not_requested"
        with self.assertRaises(ValueError):
            experiment.validate_result(a, "0" * 64, "default")
        a["functions"][0]["is_external"] = True
        experiment.validate_result(a, "0" * 64, "default")

    def summary_fixture(self):
        case = "DebugAnalysis-x86_64"
        context = {"schema": "macscope-prototype-context/1", "fixture_cases": [case],
                   "planned_cases": [case + "-default", case + "-paramid"],
                   "fixture_provenance": {}}
        evidence.write_new_json(self.path / "context.json", context)
        for mode in ("default", "paramid"):
            label = case + "-" + mode
            directory = self.path / label; directory.mkdir(); (directory / "scripts").mkdir()
            (directory / "scripts/Script.java").write_text("trusted test script")
            (directory / "sandbox.sb").write_text("test profile")
            (directory / "job.json").write_text("{}")
            evidence.write_new_json(directory / "result.json", result(mode))
            record = {"label": label, "mode": mode, "status": "complete",
                      "input_sha256": "0" * 64,
                      "scripts": {"Script.java": evidence.sha((directory / "scripts/Script.java").read_bytes())}}
            for key, name in [("result_sha256", "result.json"), ("job_sha256", "job.json"),
                              ("sandbox_sha256", "sandbox.sb")]:
                record[key] = evidence.sha((directory / name).read_bytes())
            evidence.write_new_json(directory / "case.json", record)
        return self.path / (case + "-default")

    def test_summarize_rechecks_hashes_without_engine(self):
        directory = self.summary_fixture()
        with mock.patch.object(experiment.engine, "run_process") as run:
            report = experiment.summarize(self.path)
        run.assert_not_called(); self.assertEqual(report["completed_cases"], 2)
        for name in ("result.json", "job.json", "sandbox.sb", "scripts/Script.java"):
            file = directory / name; original = file.read_bytes(); file.write_bytes(original + b" ")
            with self.subTest(name=name), self.assertRaises(ValueError):
                experiment.summarize(self.path)
            file.write_bytes(original)

    def test_summary_refuses_failed_or_incomplete_plan(self):
        directory = self.summary_fixture()
        record = evidence.read_json(directory / "case.json"); record["status"] = "failed"
        (directory / "case.json").write_text(json.dumps(record))
        with self.assertRaises(ValueError): experiment.summarize(self.path)
        context = evidence.read_json(self.path / "context.json")
        context["fixture_cases"] = []; context["planned_cases"] = []
        (self.path / "context.json").write_text(json.dumps(context))
        with self.assertRaises(ValueError): experiment.summarize(self.path)

    def test_no_opt_in_never_launches_or_checks_engine(self):
        with mock.patch.object(experiment.engine, "dependencies") as dep:
            with self.assertRaises(ValueError):
                experiment.run(argparse.Namespace(experimental_trusted_input=False))
        dep.assert_not_called()

    def test_existing_output_is_never_reused(self):
        with mock.patch.object(experiment.engine, "dependencies") as dep:
            with self.assertRaises(FileExistsError):
                experiment.run(argparse.Namespace(experimental_trusted_input=True,
                                                   output_dir=self.path))
        dep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
