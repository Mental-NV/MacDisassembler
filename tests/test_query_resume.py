"""A recorded query reopens the exact analyzed or imported Program."""
import hashlib
import json
import os
import struct
from unittest.mock import patch

from macscope import annotations, cli, direct_signatures, dispatch_returns, engine, evidence, focused, jobs, macho, storage
from test_core import TemporaryCase
from test_macho import command, image as macho_image


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
            "image_id": self.image_id, "analysis_id": self.aid, "arch": self.image["arch"],
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

    def test_repaired_program_keeps_completed_receipts_bound_to_the_old_digest(self):
        with patch.object(engine, "dependencies", return_value=self.deps), \
             patch.object(engine, "run", side_effect=self.worker):
            prior = self.resume()
        with self.workspace.db(False) as db:
            payload = db.execute("SELECT payload FROM analyses WHERE id=?", (self.aid,)).fetchone()[0]
            record = json.loads(payload)
            digest = record["analysis_program_sha256"]
            record.update(analysis_program_sha256="6" * 64, previous_program_sha256=[digest])
            db.execute("UPDATE analyses SET payload=? WHERE id=?", (json.dumps(record), self.aid))
        with patch.object(engine, "run") as run:
            replay = self.resume()
            self.assertEqual(replay, dict(prior, data=dict(prior["data"], reused_restart=True)))
            self.prior_path.with_name("query-result.json").unlink()
            self.error("analysis_program_integrity", self.resume)
            run.assert_not_called()

    def test_query_writer_rejects_results_its_reader_cannot_reopen(self):
        nested = None
        for _ in range(storage.MAX_JSON_DEPTH):
            nested = [nested]
        for value in (nested, float("inf")):
            with self.subTest(value=type(value)):
                result = cli.envelope("decompile", {"extra": value}, self.aid)
                self.error("query_receipt", jobs.publish_query, self.workspace, self.prior, self.request, result)
                self.assertFalse(self.prior_path.with_name("query-result.json").exists())

    def test_runtime_selection_is_verified_and_replayed_with_the_receipt(self):
        selection = {"runtime_va": "0x100004000", "load_slide": "0x4000", "va": self.entry,
                     "address_space": "ram", "image_id": self.image_id, "arch": "arm64"}
        self.request["address_selection"] = dict(selection, runtime_va="0x100004001")
        storage.write_json(self.prior_path, self.record, force=True)
        with patch.object(engine, "run") as run:
            self.error("job_resume_inputs", self.resume)
            run.assert_not_called()

        self.request["address_selection"] = selection
        storage.write_json(self.prior_path, self.record, force=True)
        with (patch.object(engine, "dependencies", return_value=self.deps),
              patch.object(engine, "run", side_effect=self.worker) as run):
            self.assertEqual(self.resume()["address_selection"], selection)
            repeated = self.resume()
            self.assertEqual(repeated["address_selection"], selection)
            self.assertTrue(repeated["data"]["reused_restart"])
            run.assert_called_once()
        detail = cli.execute(self.args("jobs", "show", self.prior))["data"]
        self.assertEqual(detail["address_selection"], selection)
        path = self.prior_path.with_name("query-result.json")
        receipt = json.loads(path.read_bytes())
        receipt["result"]["address_selection"]["load_slide"] = "0x5000"
        receipt["result_sha256"] = storage.identity(receipt["result"])
        storage.write_json(path, receipt, force=True)
        self.error("query_receipt", self.resume)

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


class FocusedResumeTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.workspace = self.project()
        self.original, self.attempt = 'a'*32, 'b'*32
        base, offset = 0x100000000, 0x100
        self.entry = hex(base+offset)
        self.code = bytes.fromhex('c0035fd6')
        starts = b'\x80\x02\x04\0'
        section = struct.pack('<16s16s2Q8I',b'__text',b'__TEXT',base+offset,8,offset,2,0,0,0x80000400,0,0,0)
        segment = struct.pack('<16s4Q4I',b'__TEXT',base,4096,0,offset+8+len(starts),7,5,1,0)
        header = macho_image(commands=[command(0x19,segment+section),command(0x26,struct.pack('<2I',offset+8,len(starts)))])
        self.raw = header+bytes(offset-len(header))+self.code*2+starts
        digest = hashlib.sha256(self.raw).hexdigest()
        selected, = macho.inspect_bytes(self.raw)['slices']
        self.image = dict(selected, artifact_sha256=digest, engine_baseline_sha256='c'*64)
        self.image_id = self.image['image_id']
        self.artifact = self.workspace.path/'inputs'/(digest+'.artifact')
        self.artifact.write_bytes(self.raw)
        (self.workspace.path/'inputs'/(self.image_id+'.macho')).write_bytes(self.raw)
        with self.workspace.db(False) as db:
            db.execute('INSERT INTO images VALUES(?,?,?,1,NULL)',(self.image_id,'arm64',json.dumps(self.image)))
        proof, _ = focused.select(self.workspace,self.image,self.entry)
        self.proof = dict(proof,program_sha256=self.image['engine_baseline_sha256'])
        self.request = jobs.focused_request(self.workspace,self.image,self.proof)
        self.deps = {'ghidra_path':'/engine','java_home':'/java','ghidra_version':'12.2',
                     'ghidra_tree_sha256':'d'*64,'bridge_sha256':'e'*64}
        options = cli.parser().parse_args(['decompile','--from-import','--address',self.entry,
                                         '--project',str(self.workspace.path),'--timeout','45'])
        self.record = {'job_id':self.original,'mode':'query','status':'cancelled','image_id':self.image_id,
                       'source_analysis_id':None,'selected_entry':self.entry,'focused_import':self.proof,
                       'focused_request':self.request,'analysis_profile':None,'dependencies':self.deps,
                       'limits':engine.worker_limits(options,1),'restart_protocol':jobs.RESTART_PROTOCOL,
                       'sandbox_sha256':engine.job_sandbox_sha256(self.workspace,self.deps,self.original)}
        self.path = self.write_job(self.original,self.record)

    def write_job(self, job_id, record):
        path = self.workspace.path/'jobs'/job_id/'job.json'
        path.parent.mkdir(exist_ok=True)
        storage.write_json(path,record,force=True)
        return path

    def run_cli(self, *args):
        return cli.execute(cli.parser().parse_args([*args,'--project',str(self.workspace.path),'--json']))

    def resume(self):
        return self.run_cli('jobs','resume',self.original,'--experimental-trusted-input')

    def worker(self, project, image, mode, replay, deps, **kwargs):
        self.assertEqual((image['active_analysis'], mode, deps),(None,'query',self.deps))
        self.assertEqual(engine.worker_limits(replay,1),self.record['limits'])
        self.assertEqual(kwargs,{'entry':self.entry,'from_import':True,'resumed_from':self.original})
        job = dict(self.record,job_id=self.attempt,resumed_from=self.original,status='complete')
        self.write_job(self.attempt,job)
        function = {'entry_va':self.entry,'name':'owned','signature':None,'pseudocode':'return;',
                    'decompile_status':'complete','body_ranges':[[self.entry,hex(int(self.entry,16)+3)]],
                    'is_external':False,'is_thunk':False,
                    'instructions':[{'addr':self.entry,'bytes':self.code.hex(),'flow':'TERMINATOR'}], 'blocks':[],
                    'xrefs_to_entry':[],'xrefs_from_sample':[],
                    'coverage':{key:{'status':'complete'} for key in ('pseudocode','instructions','body_ranges',
                                                                    'xrefs_from','xrefs_to_entry')}}
        return {'functions':[function],'bridge_version':'test'},job

    def test_retry_publishes_under_original_id_and_handoff_accepts_the_producer(self):
        with (patch.object(engine,'dependencies',return_value=self.deps),
              patch.object(engine,'run',side_effect=self.worker) as worker):
            response = self.resume()
            self.assertFalse(response['data']['reused_restart'])
            self.assertEqual(response['data']['origin']['job_id'],self.attempt)
            self.assertTrue(self.resume()['data']['reused_restart'])
            worker.assert_called_once()
        self.assertEqual(self.run_cli('jobs','show',self.original)['data']['publication_status'],'published_by_other_attempt')
        for job_id in (self.original,self.attempt):
            report = evidence.focused_query(self.workspace,self.image,self.raw,self.entry,job_id)
            self.assertEqual(report['data']['function_id'],self.request['function_id'])
        failed = '9'*32
        self.write_job(failed,dict(self.record,job_id=failed,resumed_from=self.original,status='failed'))
        self.error('evidence_query_mismatch',evidence.focused_query,self.workspace,self.image,self.raw,self.entry,failed)

    def test_unverified_retry_and_mutated_artifact_never_start_a_worker(self):
        attempt = self.write_job(self.attempt,dict(self.record,job_id=self.attempt,resumed_from=self.original))
        jobs.record_restart_attempt(attempt,jobs.load(attempt))
        with (patch.object(engine,'dependencies',return_value=self.deps),patch.object(engine,'run') as worker):
            owner = jobs.claim(attempt)
            try:
                self.error('job_resume_ownership',self.resume)
            finally:
                os.close(owner)
            self.write_job(self.original,dict(self.record,focused_import=dict(self.proof,extent_sha256='f'*64)))
            self.error('job_resume_inputs',self.resume)
            self.write_job(self.original,self.record)
            self.artifact.write_bytes(b'changed')
            self.error('input_integrity',self.resume)
            worker.assert_not_called()
