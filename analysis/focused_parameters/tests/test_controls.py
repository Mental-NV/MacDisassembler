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
        block=dict(name='text',start='0xbec',end='0xc2f',initialized=True,mapped=False)
        unit=dict(start='0xbec',end='0xbef',length=4,kind='InstructionDB',block=block,byte_state='read',bytes=raw,flow='RETURN')
        records=['memory:callee:0xbec:'+raw,'memory:caller:0xc2c:'+raw,
                 'block:'+json.dumps(block),'unit:'+json.dumps(unit)]
        if ast: records+=['function:0xbec:callee:proto:DEFAULT:cc:false:return:range',
                          'function:0xc2c:caller:proto:DEFAULT:cc:false:return:range']
        serialized=json.dumps(sorted(records))
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
        rows=[row for row in json.loads(snapshot['before']) if row.startswith('memory:')]
        cases=['', 'not json', '{}', '[]', json.dumps(['malformed']), json.dumps([rows[0]]),
               json.dumps(rows+[rows[0]]),json.dumps(list(reversed(rows))),
               json.dumps([rows[0],rows[1].replace('0xc2c','0xc30')]),
               json.dumps([rows[0],rows[1].replace('c0035fd6','00000000')]),
               json.dumps(rows+['unit:bad']),json.dumps(rows+['function:bad'])]
        for value in cases:
            with self.subTest(value=value):
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

    def test_memory_block_markers(self):
        request,report,snapshots=self.fixture('prep_digest')
        base=json.loads(snapshots['before'])
        block=dict(name='bss',start='0xd000',end='0xdfff',initialized=False,mapped=False)
        unit=dict(start='0xd978',end='0xd97b',length=4,kind='DataDB',block=block,
                  byte_state='uninitialized',bytes=None,flow='')
        def check(b,u,extra=()):
            rows=sorted(base+['block:'+json.dumps(b),'unit:'+json.dumps(u)]+list(extra))
            text=json.dumps(rows);r=copy.deepcopy(report);r['before_sha256']=r['after_sha256']=sha256(text.encode()).hexdigest()
            return c.validate(r,'prep_digest',request,'b'*64,dict(before=text,after=text))
        check(block,unit)
        initialized=dict(block,initialized=True);read=dict(unit,block=initialized,byte_state='read',bytes='00010203')
        check(initialized,read)
        for mutate in ('mapped','wrongblock','range','length','fakebytes','read','initialized_nobytes','shortread'):
            b=copy.deepcopy(block);u=copy.deepcopy(unit)
            if mutate=='mapped':b['mapped']=True;u['block']=b
            if mutate=='wrongblock':u['block']['name']='other'
            if mutate=='range':u['end']='0xe000'
            if mutate=='length':u['length']=5
            if mutate=='fakebytes':u['bytes']='00000000'
            if mutate=='read':u['byte_state']='read'
            if mutate=='initialized_nobytes':b['initialized']=True;u['block']=b
            if mutate=='shortread':b=initialized;u=dict(read,bytes='00')
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):check(b,u)

    def test_rejects_truncated_inventory_even_when_self_hashed(self):
        for kind in ('prep_digest','ast_scope'):
            request,report,snapshot=self.fixture(kind)
            for removed in ('unit:','block:','function:'):
                if removed=='function:' and kind!='ast_scope': continue
                rows=[row for row in json.loads(snapshot['before']) if not row.startswith(removed)]
                text=json.dumps(rows);bad=copy.deepcopy(report)
                bad['before_sha256']=bad['after_sha256']=sha256(text.encode()).hexdigest()
                with self.subTest(kind=kind,removed=removed),self.assertRaises(ValueError):
                    c.validate(bad,kind,request,'b'*64,dict(before=text,after=text))

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
