"""A recorded fresh query reopens the exact archived analysis and annotations."""
import hashlib
import json
from unittest.mock import patch

from macscope import annotations, cli, direct_signatures, dispatch_returns, engine, jobs, storage
from test_core import TemporaryCase


class QueryResumeTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.workspace = self.project()
        self.prior, self.producer = "a" * 32, "b" * 32
        self.aid, self.latest = "1" * 64, "2" * 64
        self.image_id, self.function_id = "3" * 64, "4" * 64
        self.deps = {"ghidra_path": "/engine", "java_home": "/java"}
        data = b"owned test slice"
        digest = hashlib.sha256(data).hexdigest()
        self.image = {"image_id": self.image_id, "sha256": digest, "artifact_sha256": digest,
                      "arch": "arm64", "active_analysis": self.aid}
        (self.workspace.path / "inputs" / (digest + ".artifact")).write_bytes(data)
        (self.workspace.path / "inputs" / (self.image_id + ".macho")).write_bytes(data)
        self.entry = "0x100000000"
        self.function = {
            "function_id": self.function_id, "entry_va": self.entry, "engine_entry": self.entry,
            "names": [{"origin": "ghidra", "name": "owned"}], "is_external": False, "is_thunk": False,
        }
        snapshot = {"analysis_id": self.aid, "image": self.image, "functions": [self.function], "engine": {},
                    "status": "complete", "identity": {"profile": "baseline/1"}}
        path = self.workspace.path / "snapshots" / (self.aid + ".json")
        storage.write_json(path, snapshot)
        source = {"snapshot_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                  "analysis_program_sha256": "5" * 64}
        with self.workspace.db(False) as db:
            db.execute("INSERT INTO images VALUES(?,?,?,1,?)",
                       (self.image_id, "arm64", json.dumps(self.image), self.latest))
            db.execute("INSERT INTO analyses VALUES(?,?,?)", (self.aid, self.image_id, json.dumps(source)))
        self.annotation("name", "previous-label")
        hint = self.annotation("return_type", "uint64_t")
        self.hints = [{"entry_va": self.entry, "return_type": "uint64_t", "revision": hint["revision"]}]
        self.request = jobs.query_request(
            self.workspace, self.image, self.function, source, hint["revision"], self.hints,
        )
        self.annotation("name", "new-label")
        self.annotation("return_type", "int64_t")
        original = self.args("decompile", "--fresh", "--name", "owned", "--timeout", "75")
        self.record = {
            "job_id": self.prior, "mode": "query", "status": "cancelled", "image_id": self.image_id,
            "source_analysis_id": self.aid, "selected_entry": self.entry, "query_request": self.request,
            "type_hints": self.hints, "type_hint_view_id": self.request["type_hint_view_id"],
            "analysis_profile": engine.analysis_profile(), "dependencies": self.deps,
            "limits": engine.worker_limits(original, 1),
            "sandbox_sha256": engine.job_sandbox_sha256(self.workspace, self.deps, self.prior),
        }
        self.prior_path = self.workspace.path / "jobs" / self.prior / "job.json"
        self.prior_path.parent.mkdir()
        storage.write_json(self.prior_path, self.record)

    def annotation(self, kind, value):
        row, _ = annotations.revise(self.workspace, self.image_id, self.aid, self.entry, None,
                                    kind, value, "owner")
        return row

    def args(self, *words):
        return cli.parser().parse_args([*words, "--project", str(self.workspace.path), "--json"])

    def resume(self):
        return cli.execute(self.args("jobs", "resume", self.prior, "--experimental-trusted-input"))

    def worker(self, project, image, mode, replay, deps, **kwargs):
        self.assertEqual((image["active_analysis"], mode), (self.aid, "query"))
        self.assertEqual(engine.worker_limits(replay, replay.max_functions), self.record["limits"])
        self.assertEqual(kwargs, {"entry": self.entry, "hints": self.hints, "query_request": self.request,
                                  "resumed_from": self.prior})
        self.assertEqual(deps, self.deps)
        path = project.path / "jobs" / self.producer / "job.json"
        path.parent.mkdir()
        job = dict(self.record, status="complete", job_id=self.producer, resumed_from=self.prior)
        storage.write_json(path, job)
        function = {"pseudocode": "ulong owned(void) { return 0; }",
                    "decompile_status": "complete", "pseudocode_truncated": False,
                    "coverage": {"pseudocode": {"status": "complete"}}}
        return {"functions": [function], "bridge_version": "test", "applied_type_hints": self.hints}, job

    def test_replay_uses_saved_hints_and_repeats_without_a_new_worker(self):
        with (
            patch.object(engine, "dependencies", return_value=self.deps),
            patch.object(engine, "run", side_effect=self.worker) as run,
        ):
            response = self.resume()
            self.assertEqual(response["analysis_id"], self.aid)
            self.assertEqual(response["data"]["names"][-1]["name"], "previous-label")
            self.assertEqual(response["data"]["origin"]["job_id"], self.producer)
            self.assertFalse(response["data"]["reused_restart"])
            self.assertEqual(self.resume(), dict(response, data=dict(response["data"], reused_restart=True)))
            run.assert_called_once()
        self.assertEqual(self.workspace.select()["active_analysis"], self.latest)
        detail = cli.execute(self.args("jobs", "show", self.prior))
        self.assertEqual(detail["data"]["publication"], {"job_id": self.producer, "analysis_id": self.aid})
        self.assertEqual(detail["data"]["publication_status"], "published_by_other_attempt")
        path = self.prior_path.with_name("query-result.json")
        receipt = json.loads(path.read_bytes())
        receipt["result"]["data"]["pseudocode"] = "modified"
        storage.write_json(path, receipt, force=True)
        with patch.object(engine, "run") as run:
            self.error("query_receipt", self.resume)
            run.assert_not_called()

    def test_query_publication_io_failure_keeps_original_retry_id(self):
        with (
            patch.object(engine, "dependencies", return_value=self.deps),
            patch.object(engine, "run", side_effect=self.worker),
            patch.object(jobs, "atomic", side_effect=OSError("simulated receipt write failure")),
        ):
            error = self.error("query_publication", self.resume)
        self.assertEqual(error.partial, {"job_id": self.prior, "attempt_job_id": self.producer})
        detail = cli.execute(self.args("jobs", "show", self.producer))["data"]
        self.assertEqual((detail["status"], detail["publication_status"]), ("complete", "not_published"))
        self.assertEqual(self.workspace.select()["active_analysis"], self.latest)

    def test_unconfirmed_exit_and_changed_hints_refuse_replay(self):
        with patch.object(engine, "run") as run:
            storage.write_json(self.prior_path, dict(self.record, status="running"), force=True)
            self.error("job_resume_ownership", self.resume)
            storage.write_json(self.prior_path, dict(self.record, type_hints=[]), force=True)
            self.error("job_resume_inputs", self.resume)
            run.assert_not_called()

    def test_resume_recomputes_dispatch_proof_before_starting_a_worker(self):
        original = {'policy': dispatch_returns.POLICY, 'entry_va': self.entry, 'requests': [],
                    'skipped_reason': 'unsupported_dispatch_architecture'}
        recovery = dispatch_returns.request_identity(original)
        request = dict(self.request, type_hint_view_id=None, dispatch_return_recovery=recovery)
        record = dict(self.record, query_request=request, type_hints=None, type_hint_view_id=None,
                      dispatch_return_recovery=recovery)
        storage.write_json(self.prior_path, record, force=True)
        with (patch.object(dispatch_returns, 'request', return_value=dict(original, skipped_reason='changed')),
              patch.object(engine, 'run') as run):
            self.error('job_resume_inputs', self.resume)
            run.assert_not_called()

    def test_resume_does_not_replay_a_direct_plan_under_a_different_policy(self):
        plan = {'policy': direct_signatures.POLICY, 'entry_va': self.entry, 'requests': []}
        field, recovery = engine.signature_request(plan)
        request = dict(self.request, type_hint_view_id=None, **{field: recovery})
        record = dict(self.record, query_request=request, type_hints=None, type_hint_view_id=None,
                      **{field: recovery})
        storage.write_json(self.prior_path, record, force=True)
        with (patch.object(direct_signatures, 'request', return_value=dict(plan, policy=dispatch_returns.POLICY)),
              patch.object(engine, 'run') as run):
            self.error('job_resume_inputs', self.resume)
            run.assert_not_called()
