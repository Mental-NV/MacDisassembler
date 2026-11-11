"""Host contract tests only; no native control has run in these tests."""
import copy
import json
from hashlib import sha256
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('owned_controls',Path(__file__).parents[1]/'controls.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

class ControlReports(unittest.TestCase):
    def fixture(self,kind):
        raw='c0035fd6';extent=sha256(bytes.fromhex(raw)).hexdigest()
        request={'image_sha256':c.POSITIVE,'caller':{'entry_va':'0xc2c','end_va_exclusive':'0xc30','length':4,'extent_sha256':extent},
                 'callee':{'entry_va':'0xbec','end_va_exclusive':'0xbf0','length':4,'extent_sha256':extent}}
        ast=kind=='ast_scope'
        block=dict(name='text',space='ram',start=0xbec,end=0xc2f,initialized=True,mapped=False)
        functions=['function:0xbec:callee:proto:DEFAULT:cc:false:return:range',
                   'function:0xc2c:caller:proto:DEFAULT:cc:false:return:range'] if ast else []
        inventory=dict(schema='macscope-owned-control-inventory/2',blocks=[block],kinds=['InstructionDB'],
            units=[['ram',0xbec,4,0,0,raw,'RETURN']],functions=functions,
            memory={name:dict(entry_va=request[name]['entry_va'],bytes=raw) for name in ('caller','callee')})
        serialized=json.dumps(inventory)
        snapshots=dict(before=serialized,after=serialized)
        digest=sha256(snapshots['before'].encode()).hexdigest()
        evidence=[dict(entry_va='0xbec',extent_sha256=extent,operations_scanned=10,phase='before_commit',status='complete')] if ast else []
        report=dict(schema=c.SCHEMA,control=kind,image_sha256=c.POSITIVE,request_sha256='b'*64,
            caller=request['caller'],callee=request['callee'],refusal=c.REFUSALS[kind],status='expected_refusal',
            before_sha256=digest,after_sha256=digest,commit_calls=0,inference_attempted=False,
            preparation_report_absent=not ast,positive_scope_checks=int(ast),positive_scope_evidence=evidence,
            rejected_scope_check_appended=False,injected_operation_present=ast,injected_address='0xbf0' if ast else None,
            native_graph_exported=False,stage_sha256='d'*64,ghidra_version='12.2',headless_analysis_enabled=False,java_runtime={})
        return request,report,snapshots

    def test_exact_controls(self):
        for kind in c.REFUSALS:
            request,report,snapshot=self.fixture(kind)
            self.assertEqual(c.validate(report,kind,request,'b'*64,snapshot),report)

    def test_negative_reports(self):
        for kind in c.REFUSALS:
            for key,value in [('control','other'),('refusal','generic failure'),('status','complete'),
                ('commit_calls',1),('commit_calls',False),('inference_attempted',True),('native_graph_exported',True),
                ('request_sha256','x'*64),('caller',{}),('callee',{}),('image_sha256','c'*64),
                ('headless_analysis_enabled',True),('ghidra_version','12.1'),('after_sha256','c'*64),
                ('positive_scope_evidence',None),('rejected_scope_check_appended',True)]:
                with self.subTest(kind=kind,key=key):
                    request,report,snapshot=self.fixture(kind);report[key]=value
                    with self.assertRaises(ValueError):c.validate(report,kind,request,'b'*64,snapshot)

    def test_missing_mismatched_snapshots_and_positive_proof(self):
        request,report,snapshot=self.fixture('ast_scope')
        for changed in ({},{'before':'[]','after':'different'},dict(before='[]',after='[]')):
            with self.assertRaises(ValueError):c.validate(report,'ast_scope',request,'b'*64,changed)
        for field in ('callee','refusal','positive_scope_evidence'):
            bad=copy.deepcopy(report);bad.pop(field)
            with self.assertRaises(ValueError):c.validate(bad,'ast_scope',request,'b'*64,snapshot)
        bad=copy.deepcopy(report);bad['positive_scope_evidence'][0]['entry_va']='0xc2c'
        with self.assertRaises(ValueError):c.validate(bad,'ast_scope',request,'b'*64,snapshot)

    def test_snapshot_payload_negatives_even_when_self_hashed(self):
        request,report,snapshot=self.fixture('prep_digest')
        for value in ('','not json','{}','[]','["malformed"]'):
            bad=copy.deepcopy(report);bad['before_sha256']=bad['after_sha256']=sha256(value.encode()).hexdigest()
            with self.assertRaises(ValueError):c.validate(bad,'prep_digest',request,'b'*64,dict(before=value,after=value))

    def test_pending_stage_contract(self):
        request,report,snapshots=self.fixture('prep_rollback')
        observation=copy.deepcopy(report);observation.pop('stage_sha256');observation.pop('after_sha256');observation['status']='refusal_observed'
        stage=dict(schema='macscope-owned-native-control-stage/1',status='refusal_observed',control_request_sha256='e'*64,
                   before=snapshots['before'],observation=observation)
        c.validate_stage(stage,report,snapshots,'d'*64,'e'*64)
        for field,value in [('schema','other'),('status','expected_refusal'),('before','[]'),('control_request_sha256','x')]:
            bad=copy.deepcopy(stage);bad[field]=value
            with self.assertRaises(ValueError):c.validate_stage(bad,report,snapshots,'d'*64,'e'*64)
        for field,value in [('inference_attempted',True),('commit_calls',1),('control','other'),('request_sha256','wrong')]:
            bad=copy.deepcopy(stage);bad['observation'][field]=value
            with self.assertRaises(ValueError):c.validate_stage(bad,report,snapshots,'d'*64,'e'*64)
        with self.assertRaises(ValueError):c.validate_stage({},report,snapshots,'d'*64,'e'*64)

    def check_inventory(self,inventory,kind='prep_digest'):
        request,report,_=self.fixture(kind)
        text=json.dumps(inventory);report['before_sha256']=report['after_sha256']=sha256(text.encode()).hexdigest()
        return c.validate(report,kind,request,'b'*64,dict(before=text,after=text))

    def test_explicit_uninitialized_tuple(self):
        _,_,snapshot=self.fixture('prep_digest');inventory=json.loads(snapshot['before'])
        inventory['blocks'][0]['initialized']=False;inventory['units'][0][5]=None
        self.check_inventory(inventory)
        inventory['units'][0][5]='00000000'
        with self.assertRaises(ValueError):self.check_inventory(inventory)

    def test_compact_inventory_negative_mutations(self):
        _,_,snapshot=self.fixture('ast_scope')
        mutations={
          'missing_memory':lambda v:v['memory'].pop('caller'),
          'memory_entry':lambda v:v['memory']['caller'].update(entry_va='0xc30'),
          'memory_hash':lambda v:v['memory']['caller'].update(bytes='00000000'),
          'empty_units':lambda v:v.update(units=[]),
          'empty_blocks':lambda v:v.update(blocks=[]),
          'empty_kinds':lambda v:v.update(kinds=[]),
          'missing_functions':lambda v:v.update(functions=[]),
          'bad_ref':lambda v:v['units'][0].__setitem__(4,1),
          'bad_kind':lambda v:v['units'][0].__setitem__(3,1),
          'space':lambda v:v['units'][0].__setitem__(0,'other'),
          'mapped':lambda v:v['blocks'][0].update(mapped=True),
          'null_read':lambda v:v['units'][0].__setitem__(5,None),
          'short_read':lambda v:v['units'][0].__setitem__(5,'00'),
          'wrong_end':lambda v:v['blocks'][0].update(end=0xbec),
          'length':lambda v:v['units'][0].__setitem__(2,3),
          'overflow':lambda v:v['units'][0].__setitem__(1,2**63-1),
          'negative':lambda v:v['units'][0].__setitem__(1,-1),
          'boolstart':lambda v:v['units'][0].__setitem__(1,True),
          'boollength':lambda v:v['units'][0].__setitem__(2,True),
          'boolref':lambda v:v['units'][0].__setitem__(4,False),
          'boolblock':lambda v:v['blocks'][0].update(start=False),
          'overlap':lambda v:v['units'].append(copy.deepcopy(v['units'][0])),
          'order':lambda v:v['units'].insert(0,['ram',0xbf0,4,0,0,'c0035fd6','']),
          'duplicate_block':lambda v:v['blocks'].append(copy.deepcopy(v['blocks'][0])),
          'unused_block':lambda v:v['blocks'].append(dict(v['blocks'][0],start=0xd000,end=0xdfff)),
          'duplicate_kind':lambda v:v['kinds'].append(v['kinds'][0]),
          'unused_kind':lambda v:v['kinds'].append('UnusedKind'),
        }
        for label,mutate in mutations.items():
            with self.subTest(label=label):
                inventory=json.loads(snapshot['before']);mutate(inventory)
                with self.assertRaises(ValueError):self.check_inventory(inventory,'ast_scope')

    def test_multiple_spaces_ordered_and_bound(self):
        _,_,snapshot=self.fixture('prep_digest');inventory=json.loads(snapshot['before'])
        inventory['blocks'].append(dict(inventory['blocks'][0],name='other',space='zzz'))
        inventory['units'].append(['zzz',0xbec,4,0,1,'c0035fd6','RETURN'])
        self.check_inventory(inventory)
        inventory['units'].reverse()
        with self.assertRaises(ValueError):self.check_inventory(inventory)

    def test_control_serialization_explicitly_preserves_nulls(self):
        # Source/API contract check only: no Gson jar is available on this host.
        root=Path(__file__).parents[1]
        source=(root/'OwnedNativeControls.java').read_text()
        self.assertIn('static final Gson JSON=new GsonBuilder().serializeNulls().create();',source)
        for name in ('OwnedNativeControls.java','VerifyOwnedNativeControl.java'):
            text=(root/name).read_text()
            self.assertNotIn('new Gson()',text)
            self.assertIn('JSON.toJson(',text)

    def test_prepared_arm_and_no_export_contract(self):
        source=(Path(__file__).parents[1]/'OwnedNativeControls.java').read_text()
        self.assertLess(source.index('!"prepared".equals'),source.index('super.run();'))
        self.assertIn('Control forbids parameter commit',source)
        self.assertIn('Control forbids decompilation after injection',source)
        self.assertNotIn('MacscopeBridge',source)
        self.assertNotIn('after=snapshot()',source)
        self.assertIn('control-stage.json',source)
        verification=(Path(__file__).parents[1]/'VerifyOwnedNativeControl.java').read_text()
        self.assertIn('after=snapshot()',verification)
        self.assertNotIn('highFunction(',verification)
        self.assertNotIn('endTransaction(',verification)

if __name__=='__main__':unittest.main()
