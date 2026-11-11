"""The native gate must not pass vacuously or accept mismatched receipt pins."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import integration_native_callback_counterexamples as gate


def entry(index):
    start=0x1000+index*0x100
    s={'arch':'arm64','container_file_offset':hex(start),'end_va':hex(start+32),
       'image_id':'a'*64,'policy':'macscope-import-disasm/1','program_sha256':'b'*64,
       'project_id':'c'*32,'range_sha256':'d'*64,'requested_bytes':32,
       'slice_file_offset':hex(start),'slice_sha256':'e'*64,'start_va':hex(start)}
    return {'job_id':f'{index:032x}','range':f'{hex(start)}:{hex(start+32)}','receipt_sha256':'f'*64,'selection':s}


def manifest():
    return {'schema':gate.SCHEMA,'positive':{r:entry(i+1) for i,r in enumerate(gate.ROLES)},
            'negative':{r:entry(i+5) for i,r in enumerate(gate.CASES)}}


def output(m,name):
    chosen=m['positive']['assignment'] if name=='positive' else m['negative'][name]
    pins=dict(m['positive'],assignment=chosen)
    hashes={r:hashlib.sha256(json.dumps({'data':{'selection':e['selection']}},sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest() for r,e in pins.items()}
    report={'selection':chosen['selection'],'gaps':[],'stop_reason':'selected_prefix_end','sites':[
        {'kind':'memory_store','instruction_va':chosen['selection']['start_va'],'lane':0,'value':({'kind':'address','value':'0x9990'} if name=='overwritten_target' else {'kind':'range_input_register','register':'x21','selection_start_va':chosen['selection']['start_va'],'source_envelope_sha256':hashes['assignment']})},
        {'kind':'memory_store','instruction_va':chosen['selection']['start_va'],'lane':1,'value':{'kind':'range_input_register','register':'x19'}}]}
    c={'status':'inconclusive','candidate_status':'conditional_candidate' if name=='positive' else 'gap',
       'destination_effects':{k:'unknown' for k in ('application_writer_attribution','runtime_execution','persistence')},
       'unknowns':sorted(gate.REQUIRED_UNKNOWNS),
       'role_identities':{r:{'selection':e['selection'],'source_envelope_sha256':hashes[r]} for r,e in pins.items()},
       'writer_call_evidence':{'status':'conditional_obligations','application_writer_attribution':'unknown','runtime_execution':'unknown','persistence':'unknown',
                               'post_call_stores':[{'status':'conditional_operands'}]},
       'path_obligations':[{'role':'invocation','source_envelope_sha256':hashes['invocation'],
                           'evidence':{'kind':'conditional_branch','instruction_va':pins['invocation']['selection']['start_va'],
                                       'fallthrough_predicate':'nonzero','taken_path':'not_analyzed'}}],
       'call_obligations':[{'role':r,'source_envelope_sha256':hashes[r],
                           'evidence':{'kind':'direct_call','instruction_va':pins[r]['selection']['start_va']},
                           'memory_effects':'unknown','requires':['normal_return','AAPCS64_callee_preservation']} for r in ('invocation','writer')],
       'gaps':[] if name=='positive' else [{'reason':'unique_paired_assignment_not_proven'}],
       'independent_evidence':{'assignment':report}}
    return {'data':{'callback_evidence':{'composition':c}}}


class NativeGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.m=manifest()
        for e in (*self.m['positive'].values(),*self.m['negative'].values()):
            p=self.root/'jobs'/e['job_id'];p.mkdir(parents=True)
            raw=json.dumps({'data':{'selection':e['selection']}}).encode()
            (p/'disasm-result.json').write_bytes(raw)
            e['receipt_sha256']=hashlib.sha256(raw).hexdigest()
        self.expected=gate.verify_receipts(self.root,self.m)

    def test_valid_manifest_and_pinned_receipts(self):
        self.assertEqual(gate.validate_manifest(self.m),self.m)
        gate.verify_receipts(self.root,self.m)
        for name in ('positive',*gate.CASES):gate.check_result(self.m,name,output(self.m,name),self.expected)

    def test_required_controls_and_exact_schema(self):
        for mutate in (lambda m:m['negative'].pop('unknown_target'),lambda m:m.update(extra=True),
                       lambda m:m['negative']['unknown_target'].update(job_id=m['negative']['overwritten_target']['job_id']),
                       lambda m:m['negative']['unknown_target'].update(job_id='../outside'),
                       lambda m:m['negative']['unknown_target']['selection'].update(image_id='1'*64),
                       lambda m:m['negative']['unknown_target']['selection'].update(requested_bytes=True),
                       lambda m:m['positive']['thunk'].update(range='0x0:0xffff')):
            m=copy.deepcopy(self.m);mutate(m)
            with self.assertRaises(ValueError):gate.validate_manifest(m)

    def test_stale_receipts_and_selection_mismatch_fail(self):
        e=self.m['positive']['assignment'];p=self.root/'jobs'/e['job_id']/'disasm-result.json'
        p.write_text('{}')
        with self.assertRaisesRegex(ValueError,'digest'):gate.verify_receipts(self.root,self.m)
        e['receipt_sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError,'selection'):gate.verify_receipts(self.root,self.m)

    def test_vacuous_decoder_failure_cannot_pass_negative(self):
        o=output(self.m,'overwritten_target');c=o['data']['callback_evidence']['composition']
        c['independent_evidence']['assignment']['gaps']=[{'reason':'unsupported_instruction_boundary'}]
        with self.assertRaisesRegex(ValueError,'vacuous'):gate.check_result(self.m,'overwritten_target',o,self.expected)

    def test_positive_must_pass_and_negative_target_kinds_must_match(self):
        o=output(self.m,'positive');o['data']['callback_evidence']['composition']['candidate_status']='gap'
        with self.assertRaisesRegex(ValueError,'Positive'):gate.check_result(self.m,'positive',o,self.expected)
        o=output(self.m,'overwritten_target');c=o['data']['callback_evidence']['composition']
        c['independent_evidence']['assignment']['sites'][0]['value']['value']=self.m['positive']['thunk']['selection']['start_va']
        with self.assertRaisesRegex(ValueError,'mismatch'):gate.check_result(self.m,'overwritten_target',o,self.expected)
        o=output(self.m,'unknown_target');o['data']['callback_evidence']['composition']['independent_evidence']['assignment']['sites'][0]['value']={'kind':'address','value':'0x9990'}
        with self.assertRaisesRegex(ValueError,'selected-input'):gate.check_result(self.m,'unknown_target',o,self.expected)

    def test_unknowns_and_output_identity_cannot_be_promoted(self):
        for mutation in (lambda c:c['unknowns'].remove('persistence'),
                         lambda c:c['destination_effects'].update(runtime_execution='verified'),
                         lambda c:c['role_identities']['thunk'].update(selection={})):
            o=copy.deepcopy(output(self.m,'positive'));mutation(o['data']['callback_evidence']['composition'])
            with self.assertRaises(ValueError):gate.check_result(self.m,'positive',o,self.expected)

    def fake_run(self,args,**kwargs):
        self.assertEqual(kwargs['timeout'],60)
        self.assertTrue(kwargs['check'])
        self.assertNotIn('shell',kwargs)
        self.assertIn('/nonexistent/ghidra',args)
        job=args[-1]
        name=next((n for n,e in self.m['negative'].items() if e['job_id']==job),'positive')
        return SimpleNamespace(stdout=json.dumps(output(self.m,name)))

    def test_six_replays_are_required_and_immutable(self):
        before=gate.job_snapshot(self.root)
        with patch.object(gate.subprocess,'run',side_effect=self.fake_run) as runner, patch('builtins.print'):
            gate.run(self.root,self.m)
        self.assertEqual(runner.call_count,6)
        self.assertEqual(before,gate.job_snapshot(self.root))

    def test_added_job_is_detected(self):
        def changed(args,**kwargs):
            result=self.fake_run(args,**kwargs)
            (self.root/'jobs'/'unexpected').write_text('new')
            return result
        with patch.object(gate.subprocess,'run',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'changed job'):gate.run(self.root,self.m)

    def test_budgets_and_symlinks_fail_closed(self):
        p=self.root/'large';p.write_bytes(b' '*20)
        with self.assertRaisesRegex(ValueError,'budget'):gate.bounded_json(p,10)
        with patch.object(gate,'MAX_JOB_FILES',0):
            with self.assertRaisesRegex(ValueError,'budget'):gate.job_snapshot(self.root)
        with patch.object(gate,'MAX_JOB_BYTES',1):
            with self.assertRaisesRegex(ValueError,'budget'):gate.job_snapshot(self.root)
        (self.root/'jobs'/'linked').symlink_to(p)
        with self.assertRaisesRegex(ValueError,'Symlink'):gate.job_snapshot(self.root)

    def test_all_relevant_unknowns_and_obligation_scopes_are_required(self):
        for unknown in gate.REQUIRED_UNKNOWNS:
            o=output(self.m,'positive');o['data']['callback_evidence']['composition']['unknowns'].remove(unknown)
            with self.assertRaises(ValueError):gate.check_result(self.m,'positive',o,self.expected)
        for mutate in (lambda c:c.update(path_obligations=[{}]),
                       lambda c:c.update(call_obligations=[{}]),
                       lambda c:c['call_obligations'][0].update(source_envelope_sha256='0'*64),
                       lambda c:c['writer_call_evidence'].update(runtime_execution='verified')):
            o=output(self.m,'positive');mutate(o['data']['callback_evidence']['composition'])
            with self.assertRaises(ValueError):gate.check_result(self.m,'positive',o,self.expected)
        o=output(self.m,'unknown_target')
        o['data']['callback_evidence']['composition']['independent_evidence']['assignment']['sites'][1]['instruction_va']='0x9990'
        with self.assertRaisesRegex(ValueError,'pair instruction'):gate.check_result(self.m,'unknown_target',o,self.expected)

    def test_growing_files_cannot_bypass_streamed_byte_caps(self):
        root=self.root/'growing';(root/'jobs').mkdir(parents=True)
        target=root/'jobs'/'file';target.write_bytes(b'x')
        original=Path.open
        def growing(path,*args,**kwargs):
            return io.BytesIO(b'x'*20) if path==target else original(path,*args,**kwargs)
        with patch.object(Path,'open',growing),patch.object(gate,'MAX_JOB_FILE',10):
            with self.assertRaisesRegex(ValueError,'Streamed'):gate.job_snapshot(root)
        with patch.object(Path,'open',growing),patch.object(gate,'MAX_JOB_BYTES',10):
            with self.assertRaisesRegex(ValueError,'Streamed'):gate.job_snapshot(root)
        with patch.object(Path,'open',growing):
            with self.assertRaisesRegex(ValueError,'changed during snapshot'):gate.job_snapshot(root)

    def test_internally_consistent_wrong_envelope_hash_is_rejected(self):
        o=output(self.m,'positive');c=o['data']['callback_evidence']['composition']
        c['role_identities']['invocation']['source_envelope_sha256']='0'*64
        c['path_obligations'][0]['source_envelope_sha256']='0'*64
        c['call_obligations'][0]['source_envelope_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'pinned receipt'):
            gate.check_result(self.m,'positive',o,self.expected)
