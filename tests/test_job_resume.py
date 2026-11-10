"""Exact analysis restart requests and atomic publication receipts."""
import hashlib
import json
from unittest.mock import patch

from macscope import cli, engine, jobs, storage
from test_core import TemporaryCase


class JobResumeTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.workspace = self.project()
        self.image_id = "1" * 64
        self.prior = "a" * 32
        self.output_id = "2" * 64
        self.deps = {"ghidra_path": "/engine", "java_home": "/java", "ghidra_tree_sha256": "3" * 64}
        data = b"owned test input"
        digest = hashlib.sha256(data).hexdigest()
        baseline = self.workspace.path / "engine" / self.image_id
        baseline.mkdir()
        (baseline / "program").write_bytes(b"untouched import")
        self.image = {
            "image_id": self.image_id, "arch": "arm64", "sha256": digest, "artifact_sha256": digest,
            "engine_baseline_sha256": engine.tree_digest(baseline),
        }
        self.artifact = self.workspace.path / "inputs" / (digest + ".artifact")
        self.artifact.write_bytes(data)
        (self.workspace.path / "inputs" / (self.image_id + ".macho")).write_bytes(data)
        with self.workspace.db(False) as db:
            db.execute("INSERT INTO images(id,arch,metadata,imported) VALUES(?,?,?,1)",
                       (self.image_id, "arm64", json.dumps(self.image)))
        self.prior_path = self.workspace.path / "jobs" / self.prior / "job.json"
        self.prior_path.parent.mkdir()
        self.record = {
            "job_id": self.prior, "mode": "analyze", "image_id": self.image_id, "status": "complete",
            "analysis_request": jobs.analysis_request(self.workspace, self.workspace.select()),
            "analysis_profile": engine.analysis_profile("parameter-inference"),
            "limits": engine.worker_limits(
                self.args("analyze", "--timeout", "75", "--function-timeout", "9", "--heap-mib", "768"),
                120,
            ),
            "dependencies": self.deps,
            "sandbox_sha256": engine.job_sandbox_sha256(self.workspace, self.deps, self.prior),
            "argv": ["/recorded/argv/must/not/run"],
        }
        storage.write_json(self.prior_path, self.record)

    def args(self, *words):
        return cli.parser().parse_args([*words, "--project", str(self.workspace.path), "--json"])

    def resume(self):
        return cli.execute(self.args("jobs", "resume", self.prior, "--experimental-trusted-input"))

    def fake_worker(self, job_id):
        attempt = self.workspace.path / "jobs" / job_id
        (attempt / "program").mkdir(parents=True)
        storage.write_json(attempt / "job.json", dict(self.record, job_id=job_id, resumed_from=self.prior))
        snapshot = {
            "analysis_id": self.output_id, "image": self.image, "functions": [], "engine": {},
            "analysis_profile": self.record["analysis_profile"], "status": "complete", "limitations": [],
        }
        return ({}, {"job_id": job_id}), snapshot

    def test_worker_complete_without_receipt_can_restart_and_failed_publication_rolls_back(self):
        with self.workspace.db(False) as db:
            db.execute(jobs.PUBLISH)
            db.execute("CREATE TRIGGER refuse_receipt BEFORE INSERT ON analysis_publications "
                       "BEGIN SELECT RAISE(ABORT, 'simulated interruption'); END")
        failed, snapshot = self.fake_worker("b" * 32)
        succeeded, _ = self.fake_worker("c" * 32)
        with (
            patch.object(engine, "dependencies", return_value=self.deps),
            patch.object(engine, "run", side_effect=[failed, succeeded]) as runner,
            patch.object(cli, "normalize", return_value=snapshot),
        ):
            self.error("analysis_publication", self.resume)
            self.assertIsNone(self.workspace.select()["active_analysis"])
            self.assertIsNone(jobs.publication(self.workspace, self.prior))
            with self.workspace.db(False) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0], 0)
                db.execute("DROP TRIGGER refuse_receipt")
            restarted = self.resume()
            self.assertEqual(restarted["analysis_id"], self.output_id)
            self.assertEqual(restarted["data"]["resumed_from"], self.prior)
            self.assertFalse(restarted["data"]["reused_restart"])
            for call in runner.call_args_list:
                replay = call.args[3]
                self.assertEqual(replay.profile, "parameter-inference")
                self.assertEqual(engine.worker_limits(replay, replay.max_functions), self.record["limits"])
                self.assertEqual(call.kwargs["resumed_from"], self.prior)
            self.assertTrue(self.resume()["data"]["reused_restart"])
            self.assertEqual(runner.call_count, 2)
        self.assertEqual(jobs.publication(self.workspace, self.prior),
                         {"job_id": "c" * 32, "analysis_id": self.output_id})

    def test_refusals_leave_previous_attempt_and_workspace_untouched(self):
        scenarios = (
            ("job_resume_unsupported", {"mode": "import"}),
            ("job_resume_unsupported", {"analysis_request": None}),
            ("job_resume_ownership", {"status": "running"}),
            ("job_resume_inputs", {"analysis_request": dict(self.record["analysis_request"], project_id="other")}),
            ("job_resume_conflict", {"analysis_request": dict(self.record["analysis_request"], previous_analysis_id="other")}),
            ("job_manifest", {"limits": dict(self.record["limits"], timeout_seconds=True)}),
            ("job_manifest", {"limits": dict(self.record["limits"], startup_timeout_seconds=True)}),
            ("job_resume_policy", {"limits": dict(self.record["limits"], jobs=2)}),
            ("job_resume_engine", {
                "sandbox_sha256": engine.job_sandbox_sha256(self.workspace, self.deps, "b" * 32),
            }),
        )
        with patch.object(engine, "dependencies", return_value=self.deps), patch.object(engine, "run") as runner:
            for error, changes in scenarios:
                with self.subTest(error=error):
                    storage.write_json(self.prior_path, dict(self.record, **changes), force=True)
                    self.error(error, self.resume)
            storage.write_json(self.prior_path, self.record, force=True)
            self.artifact.write_bytes(b"changed")
            self.error("input_integrity", self.resume)
        self.assertIsNone(jobs.publication(self.workspace, self.prior))
        self.assertIsNone(self.workspace.select()["active_analysis"])
        runner.assert_not_called()

    def test_replay_uses_recorded_startup_limit_or_legacy_policy(self):
        resume = self.args("jobs", "resume", self.prior, "--experimental-trusted-input")
        old_limits = dict(self.record["limits"])
        self.assertEqual(old_limits.pop("startup_timeout_seconds"), 300)
        with patch.object(engine, "dependencies", return_value=self.deps):
            for budget in (None, 12):
                with self.subTest(budget=budget):
                    limits = old_limits if budget is None else dict(old_limits, startup_timeout_seconds=budget)
                    record = dict(self.record, limits=limits)
                    replay, _ = cli.replay_worker_request(resume, self.workspace, record)
                    self.assertEqual(replay.startup_timeout, budget)
                    self.assertEqual(engine.worker_limits(replay, replay.max_functions), limits)
