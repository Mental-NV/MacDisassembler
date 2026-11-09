"""Engine-free coverage for explicit profile selection and provenance, no JVM."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from macscope import cli, engine, storage
from macscope.errors import Error


def raw_result(name="baseline", mode="analyze"):
    profile = engine.analysis_profile(name)
    opts = {"Decompiler Parameter ID": "true" if profile["parameter_inference"] else "false",
            "DWARF": "false"}
    function = {"name": "_unrelated_function", "entry_va": "0x100000000",
                "body_ranges": [["0x100000000", "0x100000003"]],
                "signature": "long function(long value)", "pseudocode": "return value + 1;",
                "decompile_status": "complete", "is_external": False, "is_thunk": False,
                "blocks": [], "instructions": [{"addr": "0x100000000", "bytes": "c0035fd6",
                                              "text": "ret", "flow": "TERMINATOR", "fallthrough": None}]}
    return {"schema": "macscope-bridge/1", "mode": mode, "ghidra_version": "12.2",
            "executable_format": "Mac OS X Mach-O", "executable_sha256": "b" * 64,
            "language_id": "AARCH64:LE:64:AppleSilicon", "compiler_spec_id": "default",
            "image_base": "0x100000000", "status": "complete", "functions": [function],
            "analysis_profile": {"name": profile["marker"], "applied": True,
                                 "ghidra_version": "12.2",
                                 "parameter_inference_enabled": profile["parameter_inference"]},
            "effective_analysis_options": opts,
            "coverage": {"effective_analysis_options": {"status": "complete", "truncated": False,
                                                       "error": None, "emitted": len(opts)}},
            "validation": {"headless_analysis_enabled": mode != "query"}}


class ProfileTests(unittest.TestCase):
    def error(self, code, fn, *args):
        with self.assertRaises(Error) as caught:
            fn(*args)
        self.assertEqual(caught.exception.code, code)

    def test_default_is_baseline_and_opt_in_is_explicit(self):
        parser = cli.parser()
        self.assertEqual(parser.parse_args(["analyze", "--project", "p"]).profile, "baseline")
        self.assertEqual(parser.parse_args(["analyze", "--project", "p", "--profile",
                                           "parameter-inference"]).profile, "parameter-inference")
        self.assertFalse(engine.analysis_profile()["parameter_inference"])

    def test_profiles_are_versioned_distinct_and_return_independent_records(self):
        baseline = engine.analysis_profile(); candidate = engine.analysis_profile("parameter-inference")
        self.assertNotEqual(baseline["identity"], candidate["identity"])
        self.assertNotEqual(baseline["marker"], candidate["marker"])
        candidate["marker"] = "changed"
        self.assertNotEqual(engine.analysis_profile("parameter-inference")["marker"], "changed")

    def test_unknown_and_deep_never_fall_back(self):
        for name in ("deep", "typo", None):
            self.error("unsupported_profile", engine.analysis_profile, name)

    def test_both_profile_results_validate(self):
        for name in engine.ANALYSIS_PROFILES:
            engine.validate_analysis_profile(raw_result(name), engine.analysis_profile(name), "analyze")

    def test_marker_metadata_and_parameter_flag_must_match(self):
        for key, value in (("name", "wrong"), ("applied", False), ("ghidra_version", "other"),
                           ("parameter_inference_enabled", False)):
            raw = raw_result("parameter-inference"); raw["analysis_profile"][key] = value
            self.error("profile_mismatch", engine.validate_analysis_profile, raw,
                       engine.analysis_profile("parameter-inference"), "analyze")

    def test_analyzer_flag_must_match_and_be_present(self):
        for options in ({}, {"Decompiler Parameter ID": "false"}):
            raw = raw_result("parameter-inference"); raw["effective_analysis_options"] = options
            self.error("profile_options_mismatch", engine.validate_analysis_profile, raw,
                       engine.analysis_profile("parameter-inference"), "analyze")

    def test_missing_incomplete_or_failed_option_inventory_fails(self):
        for key, value in (("status", "partial"), ("truncated", True), ("error", "failed"), ("emitted", 1)):
            raw = raw_result(); raw["coverage"]["effective_analysis_options"][key] = value
            self.error("profile_options_incomplete", engine.validate_analysis_profile, raw,
                       engine.analysis_profile(), "analyze")
        raw = raw_result(); raw["coverage"] = {}
        self.error("profile_options_incomplete", engine.validate_analysis_profile, raw,
                   engine.analysis_profile(), "analyze")

    def test_source_analyzers_rejected_during_analysis(self):
        raw = raw_result(); raw["effective_analysis_options"]["DWARF"] = "true"
        self.error("profile_source_option", engine.validate_analysis_profile, raw,
                   engine.analysis_profile(), "analyze")

    def test_dormant_query_options_do_not_authorize_autoanalysis(self):
        raw = raw_result(mode="query"); raw["effective_analysis_options"]["DWARF"] = "true"
        engine.validate_analysis_profile(raw, engine.analysis_profile(), "query")
        raw["validation"]["headless_analysis_enabled"] = True
        self.error("query_analysis", engine.validate_analysis_profile, raw,
                   engine.analysis_profile(), "query")

    def test_changed_requested_profile_record_fails(self):
        requested = engine.analysis_profile(); requested["parameter_inference"] = True
        self.error("profile_contract", engine.validate_analysis_profile, raw_result(), requested, "analyze")

    def test_saved_snapshot_profile_controls_reopened_query(self):
        for name in engine.ANALYSIS_PROFILES:
            expected = engine.analysis_profile(name)
            self.assertEqual(engine.profile_for_snapshot({"identity": {"profile": expected["identity"]}}),
                             expected)
        self.error("unsupported_profile", engine.profile_for_snapshot,
                   {"identity": {"profile": "future/99"}})

    def test_normalized_id_and_provenance_distinguish_profiles(self):
        image = {"image_id": "a" * 64, "sha256": "b" * 64, "arch": "arm64", "offset": "0x0",
                 "sections": [{"va": "0x100000000", "size": "0x100", "file_offset": "0x0"}]}
        outputs = []
        for name in engine.ANALYSIS_PROFILES:
            spec = engine.analysis_profile(name)
            raw = raw_result(name)
            snapshot = cli.normalize(raw, image, {"ghidra_version": "12.2"},
                                     {"limits": {}, "analysis_profile": spec})
            self.assertEqual(snapshot["identity"]["profile"], spec["identity"])
            self.assertEqual(snapshot["identity"]["profile_configuration"], spec)
            self.assertEqual(snapshot["analysis_profile"], spec)
            outputs.append(snapshot)
        self.assertNotEqual(outputs[0]["analysis_id"], outputs[1]["analysis_id"])
        self.assertNotEqual(outputs[0]["functions"][0]["function_id"], outputs[1]["functions"][0]["function_id"])
        self.assertEqual(outputs[0]["functions"][0]["pseudocode"], outputs[1]["functions"][0]["pseudocode"])
        self.assertTrue(any("may be wrong" in limit for limit in outputs[1]["limitations"]))


    def test_reference_iteration_order_does_not_change_snapshot(self):
        image = {"image_id": "a" * 64, "sha256": "b" * 64, "arch": "arm64",
                 "offset": "0x0", "sections": []}
        raw = raw_result()
        refs = [{"from": "0x100002360", "to": "0x100000000", "type": "CALL"},
                {"from": "0x10000231c", "to": "0x100000000", "type": "CALL"}]
        for key in ("xrefs_to_entry", "xrefs_from_sample"):
            raw["functions"][0][key] = refs + refs[:1]
        reverse = copy.deepcopy(raw)
        for key in ("xrefs_to_entry", "xrefs_from_sample"):
            reverse["functions"][0][key].reverse()
        manifest = {"limits": {}, "analysis_profile": engine.analysis_profile()}
        a = cli.normalize(raw, image, {}, manifest)
        b = cli.normalize(reverse, image, {}, manifest)
        self.assertEqual(a, b)
        self.assertEqual(len(a["functions"][0]["xrefs_to_entry"]), 3)
        self.assertEqual(raw["functions"][0]["xrefs_to_entry"], refs + refs[:1])

    def test_query_profile_mismatch_fails(self):
        self.error("profile_mismatch", engine.validate_analysis_profile,
                   raw_result("baseline", "query"), engine.analysis_profile("parameter-inference"), "query")

    def test_legacy_baseline_identity_resolves_without_new_fields(self):
        self.assertEqual(engine.profile_for_snapshot({"identity": {"profile": "baseline/1"}}),
                         engine.analysis_profile())


class ProfileRunnerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else None)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.project = storage.Project.create(self.root / "workspace")
        self.image = {"image_id": "a" * 64, "sha256": "b" * 64, "arch": "arm64"}
        base = self.project.path / "engine" / self.image["image_id"]; base.mkdir()
        (base / "program").write_text("no-analysis imported Program")
        self.deps = {"ghidra_path": str(self.root / "ghidra"), "java_home": str(self.root / "java")}
        self.seen = None

    def args(self, profile="baseline"):
        return cli.parser().parse_args(["analyze", "--project", str(self.project.path),
            "--profile", profile, "--experimental-trusted-input"])

    def mock_runner(self, name, mode="analyze"):
        def run(argv, *, cwd, **kwargs):
            self.seen = argv
            (cwd / "launcher.log").write_bytes(b"")
            (cwd / "bridge.json").write_text(json.dumps(raw_result(name, mode)))
        return run

    def test_opt_in_reaches_prescript_and_job_provenance(self):
        for name in engine.ANALYSIS_PROFILES:
            with self.subTest(name=name), mock.patch.object(engine, "run_process",
                                                          side_effect=self.mock_runner(name)):
                _, job = engine.run(self.project, self.image, "analyze", self.args(name), self.deps)
            self.assertEqual(job["analysis_profile"], engine.analysis_profile(name))
            next_arg = self.seen[self.seen.index("MacscopeProfile.java") + 1]
            self.assertEqual(next_arg, "parameter-inference" if name != "baseline" else "-scriptPath")

    def test_wrong_profile_worker_result_is_failed_not_published(self):
        with mock.patch.object(engine, "run_process", side_effect=self.mock_runner("baseline")):
            with self.assertRaises(Error) as caught:
                engine.run(self.project, self.image, "analyze", self.args("parameter-inference"), self.deps)
        self.assertEqual(caught.exception.code, "profile_mismatch")
        jobs = list((self.project.path / "jobs").glob("*/job.json"))
        self.assertEqual(len(jobs), 1)
        self.assertEqual(json.loads(jobs[0].read_text())["status"], "failed")
        self.assertEqual(list((self.project.path / "snapshots").glob("*")), [])

    def test_query_uses_saved_profile_not_analyze_argument_default(self):
        old = "c" * 32
        source = self.project.path / "jobs" / old / "program"; source.mkdir(parents=True)
        (source / "saved").write_text("parameter-inference analyzed Program")
        before = engine.tree_digest(source)
        snapshot = {"identity": {"profile": "parameter-inference/1"}}
        record = {"job_id": old, "analysis_program_sha256": before}
        with mock.patch.object(storage.Project, "snapshot", return_value=(snapshot, record)), \
             mock.patch.object(engine, "run_process", side_effect=self.mock_runner("parameter-inference", "query")):
            _, job = engine.run(self.project, self.image, "query", self.args(), self.deps)
        self.assertEqual(job["analysis_profile"]["name"], "parameter-inference")
        self.assertIn("-noanalysis", self.seen); self.assertIn("-readOnly", self.seen)
        self.assertNotIn("-preScript", self.seen)
        self.assertEqual(engine.tree_digest(source), before)


    def test_cli_rejected_profile_keeps_existing_active_snapshot(self):
        content = b"owned synthetic input"
        image = dict(self.image, sha256=hashlib.sha256(content).hexdigest(),
                     offset="0x0", sections=[],
                     engine_baseline_sha256=engine.tree_digest(
                         self.project.path / "engine" / self.image["image_id"]))
        (self.project.path / "inputs" / (image["image_id"] + ".macho")).write_bytes(content)
        snapshot = {"analysis_id": "previous", "identity": {"profile": "baseline/1"}}
        payload = storage.canonical(snapshot) + b"\n"
        old = self.project.path / "snapshots" / "previous.json"
        storage.atomic(old, payload, mode=0o400)
        record = {"snapshot_sha256": hashlib.sha256(payload).hexdigest(), "job_id": "old"}
        with self.project.db(False) as db:
            db.execute("INSERT INTO images(id,arch,metadata,imported,active_analysis) VALUES(?,?,?,1,?)",
                       (image["image_id"], image["arch"], json.dumps(image), "previous"))
            db.execute("INSERT INTO analyses(id,image_id,payload) VALUES(?,?,?)",
                       ("previous", image["image_id"], json.dumps(record)))
        wrong = raw_result("baseline")
        job = {"limits": {}, "analysis_profile": engine.analysis_profile("parameter-inference")}
        with mock.patch.object(engine, "dependencies", return_value=self.deps), \
             mock.patch.object(engine, "run", return_value=(wrong, job)):
            with self.assertRaises(Error) as caught:
                cli.execute(self.args("parameter-inference"))
        self.assertEqual(caught.exception.code, "profile_mismatch")
        self.assertEqual(self.project.select()["active_analysis"], "previous")
        self.assertEqual(old.read_bytes(), payload)
        self.assertEqual(len(list((self.project.path / "snapshots").iterdir())), 1)

    def test_unsupported_profile_fails_before_job_creation(self):
        before = list((self.project.path / "jobs").iterdir())
        with mock.patch.object(engine, "run_process") as run:
            with self.assertRaises(Error):
                engine.run(self.project, self.image, "analyze", self.args("deep"), self.deps)
        run.assert_not_called()
        self.assertEqual(list((self.project.path / "jobs").iterdir()), before)


if __name__ == "__main__":
    unittest.main()
