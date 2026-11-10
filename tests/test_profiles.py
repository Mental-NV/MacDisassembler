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
from test_core import synthetic_program
from test_macho import image as macho_fixture


def raw_result(name="baseline", mode="analyze"):
    profile = engine.analysis_profile(name)
    opts = {"Decompiler Parameter ID": "true" if profile["parameter_inference"] else "false",
            "DWARF": "false"}
    if name == "deep":
        opts.update({
            "Reference": "true",
            "Reference.Create Address Tables": "true",
            "Reference.Address Table Alignment": "1",
            "Reference.Address Table Minimum Size": "2",
            "Reference.Relocation Table Guide": "true",
            "Reference.Switch Table References": "false",
            "Aggressive Instruction Finder": "false",
        })
    function = {"name": "_unrelated_function", "entry_va": "0x100000000",
                "body_ranges": [["0x100000000", "0x100000003"]],
                "signature": "long function(long value)", "pseudocode": "return value + 1;",
                "decompile_status": "complete", "is_external": False, "is_thunk": False,
                "pseudocode_truncated": False, "coverage": {"pseudocode": {"status": "complete"}},
                "blocks": [], "instructions": [{"addr": "0x100000000", "bytes": "c0035fd6",
                                              "text": "ret", "flow": "TERMINATOR", "fallthrough": None}]}
    return {"schema": "macscope-bridge/1", "mode": mode, "ghidra_version": "12.2",
            "bridge_version": engine.BRIDGE_VERSION,
            "executable_format": "Mac OS X Mach-O", "executable_sha256": "b" * 64,
            "language_id": "AARCH64:LE:64:AppleSilicon", "compiler_spec_id": "default",
            "image_base": "0x100000000", "status": "complete", "functions": [function],
            "function_count_enumerated": 1,
            "decompile_summary": {"attempted": 1},
            "decompiler_timing": {"open_program": {"opened": True, "elapsed_ns": 20},
                                  "calls": [{"entry": function["entry_va"], "elapsed_ns": 10}]},
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

    def test_unknown_never_falls_back(self):
        for name in ("typo", None):
            self.error("unsupported_profile", engine.analysis_profile, name)

    def test_all_profile_results_validate(self):
        for name in engine.ANALYSIS_PROFILES:
            engine.validate_analysis_profile(raw_result(name), engine.analysis_profile(name), "analyze")

    def test_decompiler_timing_is_checked_and_removed_from_normalized_input(self):
        raw = raw_result("baseline")
        self.assertEqual(engine.decompiler_timing(raw, 1), {
            "open_program": {"opened": True, "elapsed_ns": 20}, "call_count": 1, "total_call_ns": 10,
        })
        self.assertNotIn("decompiler_timing", raw)
        self.error("decompiler_timing", engine.decompiler_timing, raw, 1)
        raw = raw_result("baseline")
        raw["decompiler_timing"]["calls"][0]["elapsed_ns"] = True
        self.error("decompiler_timing", engine.decompiler_timing, raw, 1)
        raw = raw_result("baseline")
        raw["decompiler_timing"]["calls"].clear()
        self.error("decompiler_timing", engine.decompiler_timing, raw, 1)

    def test_deep_requires_extra_discovery_and_disabled_switch_inference(self):
        for mode in ("analyze", "query"):
            for option in ("Reference.Create Address Tables", "Reference.Relocation Table Guide",
                           "Reference.Switch Table References", "Aggressive Instruction Finder"):
                with self.subTest(mode=mode, option=option):
                    raw = raw_result("deep", mode)
                    opts = raw["effective_analysis_options"]
                    opts[option] = "false" if opts[option] == "true" else "true"
                    self.error("profile_options_mismatch", engine.validate_analysis_profile,
                               raw, engine.analysis_profile("deep"), mode)

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
        self.assertEqual(len({item["analysis_id"] for item in outputs}), len(outputs))
        self.assertEqual(len({item["functions"][0]["function_id"] for item in outputs}), len(outputs))
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
        self.image["engine_baseline_sha256"] = engine.tree_digest(base)
        self.deps = {"ghidra_path": str(self.root / "ghidra"), "java_home": str(self.root / "java")}
        self.seen = None

    def args(self, profile="baseline"):
        return cli.parser().parse_args(["analyze", "--project", str(self.project.path),
            "--profile", profile, "--experimental-trusted-input"])

    def mock_runner(self, name, mode="analyze"):
        def run(argv, *, cwd, **kwargs):
            self.seen = argv
            (cwd / "launcher.log").write_bytes(b"")
            raw = raw_result(name, mode)
            raw["java_runtime"] = {"home": self.deps["java_home"], "version": "25.0.5.0.3", "arch": "aarch64"}
            (cwd / "bridge.json").write_text(json.dumps(raw))
        return run

    def test_opt_in_reaches_prescript_and_job_provenance(self):
        for name in engine.ANALYSIS_PROFILES:
            with self.subTest(name=name), mock.patch.object(engine, "run_process",
                                                          side_effect=self.mock_runner(name)):
                result, job = engine.run(self.project, self.image, "analyze", self.args(name), self.deps)
            self.assertEqual(job["analysis_profile"], engine.analysis_profile(name))
            self.assertEqual(job["java_runtime"]["home"], self.deps["java_home"])
            self.assertNotIn("java_runtime", result)
            directory = self.project.path / "jobs" / job["job_id"]
            self.assertEqual(json.loads((directory / "job.json").read_bytes())["java_runtime"], job["java_runtime"])
            self.assertEqual(Path(job["environment"]["HOME"]), directory / "home")
            self.assertEqual(job["sandbox_sha256"], engine.job_sandbox_sha256(self.project, self.deps, job["job_id"]))
            self.assertNotEqual(job["sandbox_sha256"], engine.job_sandbox_sha256(self.project, self.deps, "1" * 32))
            next_arg = self.seen[self.seen.index("MacscopeProfile.java") + 1]
            self.assertEqual(next_arg, name if name != "baseline" else "-scriptPath")

    def test_worker_cannot_silently_substitute_a_jdk(self):
        def reply(argv, *, cwd, **kwargs):
            (cwd / "launcher.log").write_bytes(b"")
            raw = raw_result()
            raw["java_runtime"] = {"home": str(self.root / "other-java"), "version": "25.0.5.0.3", "arch": "aarch64"}
            (cwd / "bridge.json").write_text(json.dumps(raw))

        with mock.patch.object(engine, "run_process", side_effect=reply), self.assertRaises(Error) as rejected:
            engine.run(self.project, self.image, "analyze", self.args(), self.deps)
        self.assertEqual(rejected.exception.code, "worker_jdk_mismatch")
        self.assertEqual(rejected.exception.exit_code, 4)
        manifest = self.project.path / "jobs" / rejected.exception.partial["job_id"] / "job.json"
        self.assertEqual(json.loads(manifest.read_bytes())["status"], "failed")

    def test_worker_rejects_auxiliary_jdk_drift_before_launch_or_publication(self):
        library = self.root / "owned-library.dylib"
        for before_launch in (True, False):
            with self.subTest(before_launch=before_launch), mock.patch.object(
                    engine, "jdk_libraries", return_value=[("owned", library, library)]):
                library.write_bytes(b"selected bytes")
                deps = dict(self.deps, jdk_auxiliary_sha256=engine.jdk_library_digest())
                if before_launch:
                    library.write_bytes(b"changed bytes")

                def reply(*args, **kwargs):
                    self.mock_runner("baseline")(*args, **kwargs)
                    library.write_bytes(b"changed bytes")

                with mock.patch.object(engine, "run_process", side_effect=reply) as runner, \
                        self.assertRaises(Error) as rejected:
                    engine.run(self.project, self.image, "analyze", self.args(), deps)
                self.assertEqual(rejected.exception.code, "worker_jdk_auxiliary_mismatch")
                self.assertEqual(runner.call_count, 0 if before_launch else 1)
                job = self.project.path / "jobs" / rejected.exception.partial["job_id"]
                self.assertEqual(json.loads((job / "job.json").read_bytes())["status"], "failed")

    def test_program_copy_declines_nested_links_before_launch(self):
        outside = self.project.path / "prior-canary"
        outside.write_bytes(b"owned outside marker")
        baseline = self.project.path / "engine" / self.image["image_id"]
        (baseline / "unexpected-link").symlink_to(outside)
        with mock.patch.object(engine, "run_process") as run:
            with self.assertRaises(Error) as caught:
                engine.run(self.project, self.image, "analyze", self.args(), self.deps)
        self.assertEqual(caught.exception.code, "analysis_program_integrity")
        run.assert_not_called()

    def test_analysis_and_plain_query_decline_changed_program_copies(self):
        previous = "c" * 32
        saved = self.project.path / "jobs" / previous / "program"
        synthetic_program(saved, b"saved analyzed Program")
        snapshot = {"identity": {"profile": "baseline/1"}}
        record = {"job_id": previous, "analysis_program_sha256": engine.tree_digest(saved)}
        baseline = self.project.path / "engine" / self.image["image_id"]
        original_copy = engine.shutil.copytree

        def alter_copy(source, destination, *arguments, **options):
            result = original_copy(source, destination, *arguments, **options)
            if Path(destination).name == "program":
                (Path(destination) / "copy-control").write_text("changed Program copy")
            return result

        with mock.patch.object(storage.Project, "snapshot", return_value=(snapshot, record)), \
             mock.patch.object(engine.shutil, "copytree", side_effect=alter_copy), \
             mock.patch.object(engine, "run_process", side_effect=AssertionError("unexpected worker launch")) as launch:
            for mode, code in (("analyze", "baseline_integrity"), ("query", "analysis_program_integrity")):
                with self.subTest(mode=mode):
                    with self.assertRaises(Error) as caught:
                        engine.run(self.project, self.image, mode, self.args(), self.deps)
                    self.assertEqual(caught.exception.code, code)
                    directory = self.project.path / "jobs" / caught.exception.partial["job_id"]
                    manifest = json.loads((directory / "job.json").read_bytes())
                    self.assertEqual(manifest["status"], "failed")
                    self.assertNotIn("pid", manifest)
                    self.assertFalse((directory / "launcher.log").exists())
            launch.assert_not_called()
        self.assertEqual(engine.tree_digest(baseline), self.image["engine_baseline_sha256"])
        self.assertEqual(engine.tree_digest(saved), record["analysis_program_sha256"])

    def test_wrong_profile_worker_result_is_failed_not_published(self):
        with mock.patch.object(engine, "run_process", side_effect=self.mock_runner("baseline")):
            with self.assertRaises(Error) as caught:
                engine.run(self.project, self.image, "analyze", self.args("parameter-inference"), self.deps)
        self.assertEqual(caught.exception.code, "profile_mismatch")
        jobs = list((self.project.path / "jobs").glob("*/job.json"))
        self.assertEqual(len(jobs), 1)
        self.assertEqual(json.loads(jobs[0].read_text())["status"], "failed")
        self.assertEqual(list((self.project.path / "snapshots").glob("*")), [])

    def test_invalid_bridge_json_and_evidence_shape_record_failed_jobs(self):
        raw = raw_result()
        raw['java_runtime'] = {'home': self.deps['java_home'], 'version': '25.0.5.0.3', 'arch': 'aarch64'}
        valid = storage.canonical(raw)
        function = raw['functions'][0]
        invalid = {
            'nonobject': b'[]',
            'duplicate': b'{"status":"failed",' + valid[1:],
            'nonfinite': b'{"unexpected":1e999,' + valid[1:],
            'deep': b'{"unexpected":' + b'[' * 65 + b'0' + b']' * 65 + b',' + valid[1:],
            'status': storage.canonical(dict(raw, status='unknown')),
            'coverage': storage.canonical(dict(raw, coverage={'effective_analysis_options': []})),
            'functions': storage.canonical(dict(raw, functions=[None])),
            'function_count': storage.canonical(dict(raw, function_count_enumerated=0)),
            'pseudocode_facet': storage.canonical(dict(raw, functions=[dict(function, coverage={})])),
            'instructions': storage.canonical(dict(raw, functions=[dict(function, instructions=[None])])),
        }

        def reply(argv, *, cwd, **kwargs):
            (cwd / 'launcher.log').write_bytes(b'')
            (cwd / 'bridge.json').write_bytes(payload)

        with mock.patch.object(engine, 'run_process', side_effect=reply):
            for name, payload in invalid.items():
                with self.subTest(name=name):
                    with self.assertRaises(Error) as caught:
                        engine.run(self.project, self.image, 'analyze', self.args(), self.deps)
                    self.assertEqual(caught.exception.code, 'bridge_result')
                    job = self.project.path / 'jobs' / caught.exception.partial['job_id'] / 'job.json'
                    record = json.loads(job.read_bytes())
                    self.assertEqual((record['status'], record['error']['code']), ('failed', 'bridge_result'))
        self.assertEqual(list((self.project.path / 'snapshots').glob('*')), [])

    def test_query_uses_saved_profile_not_analyze_argument_default(self):
        old = "c" * 32
        source = self.project.path / "jobs" / old / "program"
        synthetic_program(source, b"parameter-inference analyzed Program")
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

    def test_selected_query_checks_engine_pin_and_exact_worker_entry(self):
        job_id = "c" * 32
        source = self.project.path / "jobs" / job_id / "program"
        synthetic_program(source, b"analyzed Program")
        before = engine.tree_digest(source)
        snapshot = {"identity": {"profile": "baseline/1",
                                 "engine": {"ghidra_tree_sha256": "pinned"}}}
        record = {"job_id": job_id, "analysis_program_sha256": before}
        self.image["active_analysis"] = "saved"
        entry = "0x100000000"
        self.deps["ghidra_tree_sha256"] = "wrong"

        def reply(argv, *, cwd, **kwargs):
            self.seen = argv
            (cwd / "launcher.log").write_bytes(b"")
            raw = raw_result("baseline", "query")
            raw["java_runtime"] = {"home": self.deps["java_home"], "version": "25.0.5.0.3", "arch": "aarch64"}
            raw["selected_entry"] = entry
            (cwd / "bridge.json").write_text(json.dumps(raw))

        with mock.patch.object(storage.Project, "snapshot", return_value=(snapshot, record)), \
             mock.patch.object(engine, "run_process", side_effect=reply) as run:
            with self.assertRaises(Error) as caught:
                engine.run(self.project, self.image, "query", self.args(), self.deps, entry=entry)
            self.assertEqual(caught.exception.code, "query_engine_mismatch")
            run.assert_not_called()
            self.deps["ghidra_tree_sha256"] = "pinned"
            _, job = engine.run(self.project, self.image, "query", self.args(), self.deps, entry=entry)
            self.assertEqual(job["source_analysis_id"], "saved")
            self.assertEqual(job["selected_entry"], entry)
            self.assertEqual(job["limits"]["max_functions"], 1)
            self.assertEqual(Path(job["environment"]["HOME"]), self.project.path / "jobs" / job["job_id"] / "home")
            offset = self.seen.index("MacscopeBridge.java")
            self.assertEqual(self.seen[offset + 2:offset + 6], ["query", "1", "15", entry])
            run.side_effect = self.mock_runner("baseline", "query")
            with self.assertRaises(Error) as caught:
                engine.run(self.project, self.image, "query", self.args(), self.deps, entry=entry)
            self.assertEqual(caught.exception.code, "query_result_mismatch")
        self.assertEqual(engine.tree_digest(source), before)


    def test_cli_rejected_analysis_keeps_existing_active_snapshot(self):
        content = macho_fixture()
        digest = hashlib.sha256(content).hexdigest()
        image = dict(self.image, sha256=digest, artifact_sha256=digest,
                     offset="0x0", sections=[],
                     engine_baseline_sha256=engine.tree_digest(
                         self.project.path / "engine" / self.image["image_id"]))
        (self.project.path / "inputs" / (image["image_id"] + ".macho")).write_bytes(content)
        previous = "c" * 64
        snapshot = {"analysis_id": previous, "identity": {"profile": "baseline/1"},
                    "image": image, "status": "complete", "engine": {}, "functions": []}
        payload = storage.canonical(snapshot) + b"\n"
        old = self.project.path / "snapshots" / (previous + ".json")
        storage.atomic(old, payload, mode=0o400)
        record = {"snapshot_sha256": hashlib.sha256(payload).hexdigest(), "job_id": "old"}
        with self.project.db(False) as db:
            db.execute("INSERT INTO images(id,arch,metadata,imported,active_analysis) VALUES(?,?,?,1,?)",
                       (image["image_id"], image["arch"], json.dumps(image), previous))
            db.execute("INSERT INTO analyses(id,image_id,payload) VALUES(?,?,?)",
                       (previous, image["image_id"], json.dumps(record)))
        wrong = raw_result("baseline")
        job = {"job_id": "d" * 32, "limits": {}, "analysis_profile": engine.analysis_profile("parameter-inference")}
        job_path = self.project.path / "jobs" / job["job_id"] / "job.json"
        job_path.parent.mkdir()
        with mock.patch.object(engine, "dependencies", return_value=self.deps), \
             mock.patch.object(engine, "run", return_value=(wrong, job)):
            with self.assertRaises(Error) as caught:
                cli.execute(self.args("parameter-inference"))
        self.assertEqual(caught.exception.code, "profile_mismatch")
        raw = raw_result("parameter-inference")
        function = raw["functions"][0]
        for functions, code in (
                ([function, dict(function, entry_va="0x0100000000")], "snapshot_function_identity"),
                ([dict(function, instructions=[dict(function["instructions"][0], bytes="invalid")])], "snapshot_format")):
            with self.subTest(code=code), mock.patch.object(engine, "dependencies", return_value=self.deps), \
                 mock.patch.object(engine, "run", return_value=(dict(raw, functions=functions), job)):
                with self.assertRaises(Error) as caught:
                    cli.execute(self.args("parameter-inference"))
                self.assertEqual(caught.exception.code, code)
                record = json.loads(job_path.read_bytes())
                self.assertEqual((record["status"], record["error"]["code"]), ("failed", code))
        nested = None
        for _ in range(storage.MAX_JSON_DEPTH - 1):
            nested = [nested]
        deep_raw = dict(raw, extra=nested)
        self.assertEqual(storage.strict_json(storage.canonical(deep_raw)), deep_raw)
        with mock.patch.object(engine, "dependencies", return_value=self.deps), \
             mock.patch.object(engine, "run", return_value=(deep_raw, job)):
            with self.assertRaises(Error) as caught:
                cli.execute(self.args("parameter-inference"))
        self.assertEqual(caught.exception.code, "snapshot_format")
        self.assertEqual(json.loads(job_path.read_bytes())["status"], "failed")
        with mock.patch.object(engine, "dependencies", return_value=self.deps), \
             mock.patch.object(engine, "run", return_value=(raw, job)):
            with self.assertRaises(Error) as caught:
                cli.execute(self.args("parameter-inference"))
        self.assertEqual(caught.exception.code, "analysis_program_integrity")
        self.assertEqual(json.loads(job_path.read_bytes())["status"], "failed")
        with mock.patch.object(engine, "dependencies", return_value=self.deps), \
             mock.patch.object(engine, "run", return_value=(wrong, job)), \
             mock.patch.object(cli, "normalize", return_value={"analysis_id": "too-large"}), \
             mock.patch.object(cli, "MAX_SNAPSHOT_BYTES", 1):
            with self.assertRaises(Error) as caught:
                cli.execute(self.args("parameter-inference"))
        self.assertEqual(caught.exception.code, "snapshot_limit")
        self.assertEqual(self.project.select()["active_analysis"], previous)
        self.assertEqual(old.read_bytes(), payload)
        self.assertEqual(len(list((self.project.path / "snapshots").iterdir())), 1)

    def test_unsupported_profile_fails_before_job_creation(self):
        before = list((self.project.path / "jobs").iterdir())
        args = self.args()
        args.profile = "typo"
        with mock.patch.object(engine, "run_process") as run:
            with self.assertRaises(Error) as caught:
                engine.run(self.project, self.image, "analyze", args, self.deps)
        self.assertEqual(caught.exception.code, "unsupported_profile")
        run.assert_not_called()
        self.assertEqual(list((self.project.path / "jobs").iterdir()), before)


if __name__ == "__main__":
    unittest.main()
