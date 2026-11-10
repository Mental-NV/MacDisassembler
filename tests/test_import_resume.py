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
        job = dict(self.record, job_id=self.producer, status="complete",
                   sandbox_sha256=engine.job_sandbox_sha256(self.workspace, self.deps, self.producer))
        storage.write_json(self.source.parent / "job.json", job)
        self.assertEqual(kwargs["import_request"], self.record["import_request"])
        self.assertEqual(kwargs["resumed_from"], self.prior)
        self.assertEqual(engine.worker_limits(args[3], args[3].max_functions), self.record["limits"])
        return ({"validation": {"headless_analysis_enabled": False},
                 "executable_format": "Mac OS X Mach-O", "language_id": "arm64",
                 "compiler_spec_id": "test", "executable_sha256": self.image["sha256"]},
                job)

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

    def test_changed_artifact_is_rejected_without_a_worker(self):
        artifact = self.workspace.path / "inputs" / (self.image["artifact_sha256"] + ".artifact")
        storage.atomic(artifact, b"changed", force=True)
        with patch.object(engine, "run") as run:
            self.error("input_integrity", self.resume)
        self.assertEqual(self.workspace.images(), [])
        run.assert_not_called()
