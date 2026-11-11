"""Structural controls only. These do not claim native Ghidra validation."""
import copy
from contextlib import ExitStack
from types import SimpleNamespace
from hashlib import sha256
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from macscope import focused_tailcalls

spec=importlib.util.spec_from_file_location('owned_harness',Path(__file__).parents[1]/'harness.py')
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)


def proof(start,data):
    return dict(policy=h.focused.POLICY,entry_va=hex(start),end_va_exclusive=hex(start+len(data)),
                length=len(data),extent_sha256=sha256(data).hexdigest())


def fixture(arm='inferred'):
    # Synthetic byte contract, not a claimed native fixture.
    cp=bytes.fromhex('04000094c0035fd6'); dp=bytes.fromhex('c0035fd6')
    c,d=proof(0x100,cp),proof(0x110,dp)
    image=dict(arch='arm64',sha256='a'*64)
    return h.selection(image,c,cp,d,dp,'0x100',arm),cp,dp


class Guards(unittest.TestCase):
    def test_written_tail_request_matches_shared_digest(self):
        # Exact file bytes, not object equality: the native report hashes this file.
        for candidates in ([],[dict(source_va='0x100',source_bytes='04000014',
                target_va='0x110',target_kind='linker_function_start',target_bytes='c0035fd6')]):
            with self.subTest(candidates=candidates),tempfile.TemporaryDirectory() as tmp:
                plan=dict(policy=focused_tailcalls.POLICY,candidates=candidates)
                path=Path(tmp)/'tail.json';h.write(path,plan)
                self.assertEqual(path.read_bytes(),h.storage.canonical(plan)+b'\n')
                self.assertEqual(h.digest(path),focused_tailcalls.request_digest(plan))

    def test_positive_selection(self):
        req,_,_=fixture(); self.assertEqual(req['requests'][0]['path'][0]['bytes'],'04000094')

    def test_wrong_edge_and_stale_bytes(self):
        req,cp,dp=fixture()
        for change in ('wrongedge','stale','entry','overlap','budget','mode','arch','alignment'):
            with self.subTest(change=change):
                c,d=copy.deepcopy(req['caller']),copy.deepcopy(req['callee'])
                data=cp; arm='caller'; image=dict(arch='arm64',sha256='a'*64)
                if change=='wrongedge': d['entry_va']='0x114';d['end_va_exclusive']='0x118'
                if change=='stale': data=b'\0'*len(cp)
                if change=='entry': c['entry_va']='0x104'
                if change=='overlap': d['entry_va']='0x104';d['end_va_exclusive']='0x108'
                if change=='budget': c['length']=8196;c['end_va_exclusive']='0x2104'
                if change=='mode': arm='auto'
                if change=='arch': image['arch']='x86_64'
                if change=='alignment': c['entry_va']='0x101'
                with self.assertRaises(ValueError):h.selection(image,c,data,d,dp,'0x100',arm)

    def test_outside_call(self):
        req,cp,dp=fixture()
        with self.assertRaises(ValueError):h.selection(dict(arch='arm64',sha256='a'*64),req['caller'],cp,req['callee'],dp,'0x108','caller')

    def guards(self,req):
        return dict(schema=h.SCHEMA,arm=req['arm'],body_checks=[
            dict(entry_va=req[k]['entry_va'],extent_sha256=req[k]['extent_sha256'],leaf=k=='callee')
            for k in ('caller','callee')],native_checks=[
            dict(entry_va=req['callee']['entry_va'],extent_sha256=req['callee']['extent_sha256'],operations_scanned=4,phase=p,status='complete')
            for p in ('before_commit','after_commit')])

    def recovery(self,req):
        return dict(policy=h.callee_parameters.POLICY,entry_va=req['entry_va'],results=[dict(
            target_va=req['callee']['entry_va'],status='applied',return_unchanged=True,parameters=[dict(register='x0',size=8)])])

    def test_guard_positive(self):
        req,_,_=fixture(); self.assertEqual(h.validate_guards(req,self.guards(req),self.recovery(req))['status'],'applied')

    def test_scope_report_rejections(self):
        req,_,_=fixture()
        for mutation in ('missing','outside','truncated','unavailable','empty','wrong_hash','wrong_arm','return','hidden'):
            with self.subTest(mutation=mutation):
                guards=self.guards(req); recovery=self.recovery(req)
                if mutation=='missing': guards['native_checks'].pop()
                if mutation=='outside': guards['native_checks'][0]['entry_va']='0x200'
                if mutation=='truncated': guards['native_checks'][0]['operations_scanned']=100001
                if mutation=='unavailable': guards['native_checks'][0]['status']='unavailable'
                if mutation=='empty': guards['native_checks'][0]['operations_scanned']=0
                if mutation=='wrong_hash': guards['body_checks'][0]['extent_sha256']='b'*64
                if mutation=='wrong_arm': guards['arm']='auto'
                if mutation=='return': recovery['results'][0]['return_unchanged']=False
                if mutation=='hidden': recovery['results'][0]['parameters'][0]['register']='x20'
                with self.assertRaises((ValueError,h.engine.Error)):h.validate_guards(req,guards,recovery)

    def test_noninference_must_not_report_inference(self):
        req,_,_=fixture('prepared')
        with self.assertRaises(ValueError): h.validate_guards(req,self.guards(req),None)

    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=Path(tmp)/'a';a.mkdir(); b=Path(tmp)/'b';b.symlink_to(a)
            with self.assertRaises(ValueError):h.safe_path(b)

    def test_host_gate_before_work(self):
        with patch.object(h.engine,'require_worker_host',side_effect=ValueError('host')),patch.object(h.engine,'run_process') as execute:
            with self.assertRaises(ValueError):h.run(None)
            execute.assert_not_called()

    def test_owned_allowlist_is_not_arbitrary(self):
        self.assertEqual(len(h.OWNED),2)
        self.assertNotIn('a'*64,h.OWNED)

    def raw(self):
        return dict(schema='macscope-bridge/1',mode='query',ghidra_version=h.engine.engine_checks.GHIDRA_VERSION,
                    bridge_version=h.engine.BRIDGE_VERSION,status='partial',coverage={},analysis_profile={},
                    effective_analysis_options={},validation={'headless_analysis_enabled':False},selected_entry='0x100',
                    function_count_enumerated=1,functions=[dict(entry_va='0x100',name='owned',coverage={'pseudocode':{'status':'complete'}},
                    decompile_status='complete',pseudocode_truncated=False,pseudocode='owned',instructions=[],blocks=[],body_ranges=[])],
                    decompile_summary={'attempted':1},decompiler_timing={'open_program':{'elapsed_ns':1,'opened':True},
                    'calls':[{'entry':'0x100','elapsed_ns':2}]})

    def test_raw_contract_preserves_partial_diagnostics(self):
        raw=self.raw(); before=copy.deepcopy(raw)
        with patch.object(h.engine,'verify_macho_loader'),patch.object(h.engine.engine_checks,'verify_runtime'):
            result=h.validate_raw(raw,{},dict(java_home='/fake'),'0x100')
        self.assertEqual(result['raw_status'],'partial')
        self.assertEqual(raw,before)

    def test_raw_contract_negatives(self):
        cases=[('schema','unknown'),('bridge_version','unknown'),('ghidra_version','unknown'),('mode','analyze'),
               ('status','failed'),('selected_entry','0x110'),('functions',[]),('validation',{}),
               ('validation',{'headless_analysis_enabled':True}),('validation',{'headless_analysis_enabled':0}),
               ('decompiler_timing',{}),('decompile_summary',{'attempted':2}),
               ('applied_type_hints',[{}]),('applied_type_hints',{}),('applied_type_hints',None),
               ('aggregate_type_layouts',[{'definition':'unexpected'}]),
               ('aggregate_type_layouts',{}),('aggregate_type_layouts',None)]
        with patch.object(h.engine,'verify_macho_loader'),patch.object(h.engine.engine_checks,'verify_runtime'):
            for key,value in cases:
                with self.subTest(key=key,value=value):
                    raw=self.raw();raw[key]=value
                    with self.assertRaises((ValueError,h.engine.Error)):h.validate_raw(raw,{},dict(java_home='/fake'),'0x100')
            raw=self.raw();raw['functions'][0]['entry_va']='0x110'
            with self.assertRaises(ValueError):h.validate_raw(raw,{},dict(java_home='/fake'),'0x100')
            with self.assertRaises(ValueError):h.validate_raw([],{},dict(java_home='/fake'),'0x100')

    def test_launch_is_experimental_and_preserves_failure(self):
        # Mocked supervisor boundary, NOT a native capture or validation receipt.
        req,cp,dp=fixture('caller')
        for p in (req['caller'],req['callee']):p['tail_calls']={}
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp); (root/'project.json').write_text('{}'); (root/'index.sqlite').write_bytes(b'index')
            source=root/'import'; source.mkdir()
            owned=next(iter(h.OWNED)); entries=h.OWNED[owned]
            image=dict(sha256=owned,arch='arm64',active_analysis=None,imported=True,image_id='b'*64,
                       engine_baseline_sha256='baseline',import_dependencies={'ghidra_tree_sha256':'runtime'})
            deps=dict(ghidra_tree_sha256='runtime',ghidra_path='/fake/ghidra',java_home='/fake/java')
            project=SimpleNamespace(path=root,select=lambda **kw:image)
            args=SimpleNamespace(arm='caller',ghidra='/fake/ghidra',java_home='/fake/java')
            # The actual proof addresses are irrelevant to this mocked launch test;
            # selection validation is exercised independently, not bypassed in the harness.
            stack.enter_context(patch.object(h,'selection',return_value=req))
            stack.enter_context(patch.object(h.focused,'select',side_effect=lambda p,i,e:
                (req['caller'],cp) if e==entries[0] else (req['callee'],dp)))
            for method,value in [('dependencies',deps),('matches_auxiliary_jdk',True),('verify_auxiliary_jdk',None),
                                 ('import_program_path',source),('saved_program_digest','baseline'),
                                 ('tree_digest','normalized'),('profile','sandbox')]:
                stack.enter_context(patch.object(h.engine,method,return_value=value))
            stack.enter_context(patch.object(h.engine,'copy_program',side_effect=lambda s,d,*a:d.mkdir()))
            observed=[]
            def stop(argv,**kw):
                observed.append(kw)
                self.assertEqual(kw['manifest']['schema'],h.SCHEMA)
                self.assertEqual(kw['manifest']['kind'],'owned_feasibility_operation')
                self.assertEqual(kw['manifest']['mode'],'query')
                self.assertNotIn('query_request',kw['manifest'])
                self.assertNotIn('focused_request',kw['manifest'])
                self.assertEqual(kw['manifest_path'].parent,kw['cwd'].parent)
                self.assertNotEqual(kw['manifest_path'].parent,kw['cwd'])
                self.assertIn('-readOnly',argv); self.assertIn('-noanalysis',argv)
                raise RuntimeError('intentional mocked stop')
            stack.enter_context(patch.object(h.engine,'run_process',side_effect=stop))
            with self.assertRaisesRegex(RuntimeError,'intentional mocked stop'):h.run_locked(project,args)
            self.assertEqual(len(observed),1)
            attempt=observed[0]['manifest_path'].parent
            self.assertTrue((attempt/'failure.json').exists())
            self.assertFalse((attempt/'assessment.json').exists())
            self.assertFalse(list(root.rglob('query-result.json')))

    def test_no_product_module_changes_in_contract(self):
        text=Path(h.__file__).read_text()
        self.assertNotIn('engine.run(',text)
        self.assertNotIn('query-result.json',text)
        self.assertIn("manifest_path=attempt/'operation.json'",text)
        self.assertIn('write_root=worker,read_only_program=True',text)

if __name__=='__main__':unittest.main()
