"""Recover an exact import slice across worker and index publication failures."""
from unittest.mock import patch

from macscope import cli, engine, import_state, jobs, macho, storage
from test_core import TemporaryCase
from test_macho import image


class ImportResumeTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.workspace = self.project()
        self.data = image()
        result = macho.inspect_bytes(self.data)
        self.image = dict(result["slices"][0], artifact_sha256=result["artifact_sha256"], input_name="owned")
        self.prior = "a" * 32
        self.producer = "b" * 32
        self.deps = {"ghidra_path": "/engine", "java_home": "/java"}
        self.baseline = self.workspace.path / "engine" / self.image["image_id"]
        self.source = self.workspace.path / "jobs" / self.producer / "program"
        import_state.stage_inputs(self.workspace, self.image, self.data)
        self.prior_path = self.workspace.path / "jobs" / self.prior / "job.json"
        self.prior_path.parent.mkdir()
        self.record = {
            "job_id": self.prior, "mode": "import", "image_id": self.image["image_id"],
            "status": "cancelled", "analysis_profile": None,
            "import_request": import_state.request_for(self.workspace, self.image),
            "limits": engine.worker_limits(
                self.args("import", "owned", "--timeout", "75", "--heap-mib", "768"), 1000,
            ),
            "dependencies": self.deps,
            "sandbox_sha256": engine.job_sandbox_sha256(self.workspace, self.deps, self.prior),
        }
        storage.write_json(self.prior_path, self.record)

    def args(self, *words):
        return cli.parser().parse_args([*words, "--project", str(self.workspace.path), "--json"])

    def resume(self, job_id=None):
        return cli.execute(self.args("jobs", "resume", job_id or self.prior, "--experimental-trusted-input"))

    def worker(self, *args, **kwargs):
        self.source.mkdir(parents=True)
        (self.source / "image.gpr").write_bytes(b"owned prepared Program")
        job = dict(self.record, job_id=self.producer, status="complete", resumed_from=self.prior,
                   sandbox_sha256=engine.job_sandbox_sha256(self.workspace, self.deps, self.producer))
        storage.write_json(self.source.parent / "job.json", job)
        self.assertEqual(kwargs["import_request"], self.record["import_request"])
        self.assertEqual(kwargs["resumed_from"], self.prior)
        self.assertEqual(engine.worker_limits(args[3], args[3].max_functions), self.record["limits"])
        raw = {"schema": "macscope-bridge/1", "mode": "import", "status": "complete",
               "bridge_version": engine.BRIDGE_VERSION, "ghidra_version": "12.2",
               "validation": {"headless_analysis_enabled": False},
               "executable_format": "Mac OS X Mach-O", "language_id": "AARCH64:LE:64:AppleSilicon",
               "compiler_spec_id": "default", "executable_sha256": self.image["sha256"]}
        storage.write_json(self.source.parent / "bridge.json", raw)
        (self.source.parent / "launcher.log").write_bytes(b"owned worker completed")
        return raw, job

    def test_finish_prepared_import_before_and_after_promotion_without_relaunch(self):
        with (
            patch.object(engine, "dependencies", return_value=self.deps),
            patch.object(engine, "run", side_effect=self.worker) as run,
        ):
            with patch.object(import_state.os, "rename", side_effect=OSError("simulated interrupted promotion")):
                failure = self.error("import_publication", self.resume)
                self.assertEqual(failure.partial, {"job_id": self.prior, "attempt_job_id": self.producer})
            self.assertTrue(self.source.is_dir())
            self.assertTrue(self.baseline.with_suffix(".import.json").is_file())
            self.assertEqual(self.workspace.images(), [])
            with self.workspace.db(False) as db:
                db.execute(jobs.PUBLISH_IMPORT)
                db.execute("CREATE TRIGGER refuse_receipt BEFORE INSERT ON import_publications "
                           "BEGIN SELECT RAISE(ABORT, 'simulated interruption'); END")
            failure = self.error("import_publication", self.resume)
            self.assertEqual(failure.partial, {"job_id": self.prior, "attempt_job_id": self.producer})
            self.assertTrue(self.baseline.is_dir())
            self.assertFalse(self.source.exists())
            self.assertEqual(self.workspace.images(), [])
            self.assertIsNone(jobs.publication(self.workspace, self.prior, "import"))
            with self.workspace.db(False) as db:
                db.execute("DROP TRIGGER refuse_receipt")
            restarted = self.resume()
            self.assertEqual(restarted["data"]["job_id"], self.producer)
            self.assertFalse(restarted["data"]["reused_restart"])
            self.assertTrue(self.resume()["data"]["reused_restart"])
            self.error("job_completed", self.resume, self.producer)
            run.assert_called_once()
        self.assertEqual(self.workspace.select()["engine_baseline_sha256"], engine.tree_digest(self.baseline))

    def test_prepared_import_rejects_corrupt_journal_and_producer_without_relaunch(self):
        journal_path = self.baseline.with_suffix(".import.json")
        program = self.source / "image.gpr"
        producer_path = self.source.parent / "job.json"
        with patch.object(engine, "dependencies", return_value=self.deps), \
             patch.object(engine, "run", side_effect=self.worker) as run:
            with patch.object(import_state.os, "rename", side_effect=OSError("interrupted promotion")):
                self.error("import_publication", self.resume)
            original = journal_path.read_bytes()
            journal = storage.strict_json(original)
            producer = jobs.load(producer_path)
            self.assertEqual(producer["import_program_sha256"], journal["program_sha256"])
            self.assertEqual(journal["schema"], import_state.JOURNAL_SCHEMA)
            wrong_loader = dict(journal["loader_evidence"], language_id="x86:LE:64:default")
            for payload in (b'{"job_id":"duplicate",' + original[1:],
                            storage.canonical(dict(journal, loader_evidence=wrong_loader)),
                            storage.canonical({key: value for key, value in journal.items() if key != "schema"})):
                storage.atomic(journal_path, payload, force=True)
                self.error("import_journal", self.resume)
            program.write_bytes(b"changed Program")
            storage.write_json(journal_path, dict(journal, program_sha256=engine.tree_digest(self.source)), force=True)
            self.error("import_journal", self.resume)
            program.write_bytes(b"owned prepared Program")
            storage.atomic(journal_path, original, force=True)
            storage.write_json(producer_path, dict(producer, status="failed"), force=True)
            self.error("import_journal", self.resume)
            self.assertTrue(self.source.is_dir())
            self.assertFalse(self.baseline.exists())
            self.assertEqual(self.workspace.images(), [])
            storage.write_json(producer_path, producer, force=True)
            self.assertEqual(self.resume()["data"]["job_id"], self.producer)
            run.assert_called_once()

    def test_legacy_journal_requires_its_original_worker_report(self):
        journal_path = self.baseline.with_suffix(".import.json")
        producer_path = self.source.parent / "job.json"
        bridge_path = self.source.parent / "bridge.json"
        with patch.object(engine, "dependencies", return_value=self.deps), \
             patch.object(engine, "run", side_effect=self.worker) as run:
            with patch.object(import_state.os, "rename", side_effect=OSError("interrupted promotion")):
                self.error("import_publication", self.resume)
            journal = storage.strict_json(journal_path.read_bytes())
            del journal["schema"]
            storage.write_json(journal_path, journal, force=True)
            producer = jobs.load(producer_path)
            del producer["import_program_sha256"]
            storage.write_json(producer_path, producer, force=True)
            raw = bridge_path.read_bytes()
            storage.atomic(bridge_path, b'{"mode":"import",' + raw[1:], force=True)
            self.error("import_journal", self.resume)
            self.assertEqual(self.workspace.images(), [])
            storage.atomic(bridge_path, raw, force=True)
            self.assertEqual(self.resume()["data"]["job_id"], self.producer)
            run.assert_called_once()

    def test_changed_artifact_is_rejected_without_a_worker(self):
        artifact = self.workspace.path / "inputs" / (self.image["artifact_sha256"] + ".artifact")
        storage.atomic(artifact, b"changed", force=True)
        with patch.object(engine, "run") as run:
            self.error("input_integrity", self.resume)
        self.assertEqual(self.workspace.images(), [])
        run.assert_not_called()
