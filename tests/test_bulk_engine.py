"""Mocked worker boundary tests; no claim of native decompiler validation."""
import copy
import json
from unittest import mock
from test_profiles import ProfileRunnerTests, raw_result
from test_core import synthetic_program
from macscope import engine, storage
from macscope.errors import Error


class BulkEngineTests(ProfileRunnerTests):
    def test_bulk_selection_contract(self):
        for entries in ([], ['0x1']*2, ['0x2','0x1'], ['0x01'], ['0xA'], ['1'], [1], tuple(['0x1']), ['0x'+format(n,'x') for n in range(129)]):
            with self.subTest(entries=entries), self.assertRaises(Error) as caught:
                engine.validate_bulk_entries(entries)
            self.assertEqual(caught.exception.code, 'bulk_selection')
        engine.validate_bulk_entries(['0x0','0xf','0x10','0xffffffffffffffff'])

    def test_bulk_scope_rejects_mutations(self):
        for extras in ({'entry':'0x1'}, {'from_import':True}, {'hints':[]}, {'query_request':{}},
                       {'signature_plan':{}}, {'boundary_request':{}}, {'manual_request':{}},
                       {'resumed_from':'abc'}, {'analysis_request':{}}, {'import_request':{}}):
            with self.subTest(extras=extras), self.assertRaises(Error) as caught:
                engine.run(self.project,self.image,'query',self.args(),self.deps,
                           bulk_entries=['0x1'],**extras)
            self.assertEqual(caught.exception.code,'bulk_scope')
        self.assertFalse(list((self.project.path/'jobs').iterdir()))

    def test_bulk_exact_selection_runtime_and_minimal_output(self):
        old='c'*32
        source=self.project.path/'jobs'/old/'program'
        synthetic_program(source,b'analyzed program')
        digest=engine.tree_digest(source)
        snapshot={'identity':{'profile':'baseline/1','engine':{'ghidra_tree_sha256':'pinned'}}}
        record={'job_id':old,'analysis_program_sha256':digest}
        self.image['active_analysis']='saved'
        entries=['0x100000000','0x100000004']
        changed={}
        def reply(argv,*,cwd,**kwargs):
            self.seen=argv
            index=argv.index('--bulk-entries')
            request=json.loads(__import__('pathlib').Path(argv[index+1]).read_text())
            self.assertEqual(request,{'schema':'macscope-bulk-selection/1','entries':entries})
            raw=raw_result(mode='query')
            base=raw['functions'][0]
            raw['functions']=[{k:v for k,v in dict(base,entry_va=e).items()
                               if k in ('entry_va','coverage','decompile_status','pseudocode','pseudocode_truncated')} for e in entries]
            raw.update(bulk_entries=entries,bulk_semantics=engine.BULK_SEMANTICS,function_count_enumerated=2,
                       decompile_summary={'attempted':2},java_runtime={'home':self.deps['java_home'],'version':'25.0.5.0.3','arch':'aarch64'})
            raw['decompiler_timing']['calls']=[{'entry':e,'elapsed_ns':10} for e in entries]
            raw.update(changed)
            (cwd/'launcher.log').write_bytes(b'')
            (cwd/'bridge.json').write_text(json.dumps(raw))
        with mock.patch.object(storage.Project,'snapshot',return_value=(snapshot,record)), mock.patch.object(engine,'run_process',side_effect=reply) as worker:
            self.deps['ghidra_tree_sha256']='wrong'
            with self.assertRaises(Error) as caught:
                engine.run(self.project,self.image,'query',self.args(),self.deps,bulk_entries=entries)
            self.assertEqual(caught.exception.code,'query_engine_mismatch'); worker.assert_not_called()
            self.deps['ghidra_tree_sha256']='pinned'
            result,job=engine.run(self.project,self.image,'query',self.args(),self.deps,bulk_entries=entries)
            self.assertEqual(job['bulk_entries'],entries)
            self.assertEqual(job['limits']['max_functions'],2)
            self.assertEqual(job['source_program_sha256'],digest)
            self.assertIn('-readOnly',self.seen);self.assertIn('-noanalysis',self.seen)
            self.assertNotIn('-preScript',self.seen)
            for mutation in ({'bulk_semantics':'isolated'}, {'bulk_entries':entries[::-1]}):
                changed.update(mutation)
                with self.assertRaises(Error) as caught:
                    engine.run(self.project,self.image,'query',self.args(),self.deps,bulk_entries=entries)
                self.assertEqual(caught.exception.code,'bulk_result_mismatch')
                changed.clear()
        self.assertEqual(engine.tree_digest(source),digest)
