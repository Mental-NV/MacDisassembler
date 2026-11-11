"""Conditional ABI projections and sidecars leave saved code evidence alone."""
import copy
import hashlib
import json
import struct
import unittest
from unittest.mock import patch

from macscope import cli, engine, evidence, handoff_diff, objc, objc_types, objc_type_evidence as sidecars, storage
from test_core import TemporaryCase, synthetic_snapshot
from test_objc import BASE, fixture
import test_binary_diff


class AbiProjectionTests(unittest.TestCase):
    def project(self, encoding, selector='take:', arch='arm64', kind='instance'):
        return sidecars.project_abi(objc_types.decode_method(encoding,selector,kind),arch)

    def test_word_and_pointer_roles_on_both_compiler_checked_targets(self):
        for arch, registers in sidecars.GP.items():
            for code, representation in (('q','integer'),('Q','integer'),('@','pointer'),('#','pointer'),
                                          (':','pointer'),('*','pointer'),('^v','pointer')):
                row = self.project(code+'24@0:8'+code+'16',arch=arch)
                self.assertEqual(row['status'],'projected',row)
                self.assertEqual([a['register'] for a in row['arguments']],registers[:3])
                self.assertEqual([a['role'] for a in row['arguments']],['receiver','selector','explicit'])
                self.assertEqual(row['return_value']['representation'],representation)
                self.assertEqual(row['return_value']['register'],'x0' if arch=='arm64' else 'rax')
                self.assertFalse(row['implementation_signature_verified'])
            self.assertEqual(self.project('v24@0:8@16',arch=arch,kind='class')['return_value'],
                             {'kind':'void','register':None})

    def test_register_limits_and_offsets_do_not_change_roles(self):
        for arch, registers in sidecars.GP.items():
            count = len(registers)-2
            row = self.project('v@:'+'q'*count,'take:'*count,arch)
            self.assertEqual([a['register'] for a in row['arguments']],registers)
            over = self.project('v@:'+'q'*(count+1),'take:'*(count+1),arch)
            self.assertEqual(over['status'],'unsupported')
            self.assertIn('stack_arguments_unsupported',over['reasons'])
            self.assertNotIn('arguments',over)
        ordinary = self.project('q24@0:8q16')
        strange = self.project('q999@-7:123q+9999')
        self.assertEqual(ordinary,strange)

    def test_types_and_qualifiers_outside_initial_subset_are_explicit(self):
        for code in ('l','L','i','B','c','f','d','D','@?','{Owned=qq}','[2q]','b5','nq','O@'):
            row = self.project('v24@0:8'+code+'16')
            self.assertEqual(row['status'],'unsupported',code)
            self.assertNotIn('arguments',row)
        self.assertEqual(self.project('d24@0:8@16')['reasons'],['return_type_unsupported'])
        self.assertEqual(self.project('v24@0:8?16')['reasons'],['type_encoding_incomplete'])
        self.assertEqual(self.project('v24@0:8@16',arch='arm64e')['reasons'],['unsupported_architecture'])
        self.assertEqual(self.project('v24@0:8^{Owned=qq}16')['status'],'projected')
        self.assertEqual(self.project('v24@0:8r^q16')['status'],'projected')


class SidecarDiffTests(TemporaryCase):
    fixture = test_binary_diff.HandoffDiffTests.fixture
    save = test_binary_diff.HandoffDiffTests.save
    compare = test_binary_diff.HandoffDiffTests.compare

    def typed(self,label='typed'):
        path, report = self.fixture(label)
        row = report['leads'][0]
        row.update(match_references=[],candidates=[])
        row['query']={'status':'partial','origin':{'job_id':row['lead']['query_job']}}
        row['matches'] = [{'name':row['lead']['value'],'class_name':'Owned','class_slot':row['lead']['class_slot'],
                           'category':None,'method_kind':'instance',
                           'type_encoding':'q24@0:8q16','record_va':'0x5000','selector_va':'0x5100',
                           'selector_reference_va':None,'implementation_va':row['function']['entry_va'],
                           'origin':'objc_method_list','encoding':'absolute'}]
        report[sidecars.FIELD] = sidecars.build(report,{})
        self.save(path,report)
        return path,report

    def test_sidecar_digest_binding_html_and_changed_meaning(self):
        left,a = self.typed('left')
        right,b = self.typed('right')
        record, = a[sidecars.FIELD]['records']
        self.assertEqual(record['status'],'associated')
        self.assertEqual(record['binding']['function_id'],a['leads'][0]['function']['function_id'])
        self.assertEqual(record['sha256'],storage.identity({k:v for k,v in record.items() if k!='sha256'}))
        result = self.compare(left,right)['data']['records'][0]
        self.assertNotIn('objc_types',result['changed_observations'])
        self.assertIn('objc_type_binding',result['changed_provenance'])
        b['leads'][0]['matches'][0]['type_encoding'] = 'Q24@0:8Q16'
        b[sidecars.FIELD] = sidecars.build(b,{})
        self.save(right,b)
        result = self.compare(left,right)['data']['records'][0]
        self.assertEqual(result['changed_observations'],['objc_types'])
        html = cli.render(json.loads(left.read_bytes()),'html')
        self.assertIn(b'conditional ABI roles',html)
        self.assertIn(b'implementation_signature_verified',html)

    def test_owned_consumer_context_and_unsupported_types_preserve_code(self):
        path, report = self.typed('consumer')
        before = copy.deepcopy(report['leads'][0]['function'])
        record = report[sidecars.FIELD]['records'][0]
        self.assertEqual(record['binding']['entry_va'], before['entry_va'])
        self.assertEqual(record['declaration']['name'], report['leads'][0]['lead']['value'])
        roles = record['abi_projection']['arguments']
        self.assertEqual([r['role'] for r in roles], ['receiver', 'selector', 'explicit'])
        self.assertEqual(roles[2]['label'], 'arg1')
        self.assertEqual(record['abi_projection']['claim'], 'conditional_register_roles')
        self.assertFalse(record['abi_projection']['implementation_signature_verified'])
        envelope = json.loads(path.read_bytes())
        for fmt in ('text', 'html'):
            rendered = cli.render(envelope, fmt)
            for fragment in (b'conditional_register_roles', b'arg1', before['entry_va'].encode(), before['pseudocode'].encode(), b'pseudocode'):
                self.assertIn(fragment, rendered)
        compact = cli.render(envelope, 'compact')
        self.assertIn(b'Optional Objective-C type details omitted', compact)
        self.assertLessEqual(len(compact), 32768)
        self.assertLessEqual(compact.count(b'\n'), 200)
        report['leads'][0]['matches'][0]['type_encoding'] = 'v24@0:8B16'
        report[sidecars.FIELD] = sidecars.build(report, {})
        unsupported = report[sidecars.FIELD]['records'][0]
        self.assertEqual(unsupported['status'], 'associated')
        self.assertEqual(unsupported['declaration']['type_encoding'], 'v24@0:8B16')
        self.assertEqual(unsupported['abi_projection']['status'], 'unsupported')
        self.assertNotIn('arguments', unsupported['abi_projection'])
        self.assertEqual(report['leads'][0]['function'], before)
        sidecars.validate(report)

    def test_opt_in_added_removed_and_unknown_policy_not_silent(self):
        left,a = self.typed('left')
        right = self.root/'raw.json'
        raw = copy.deepcopy(a)
        del raw[sidecars.FIELD]
        self.save(right,raw)
        for x,y in ((left,right),(right,left)):
            self.assertIn('objc_types',self.compare(x,y)['data']['records'][0]['changed_coverage'])
        for policy in ('policy','decoder_policy','abi_policy'):
            bad = copy.deepcopy(a)
            bad[sidecars.FIELD][policy] = 'unknown'
            self.save(right,bad)
            self.error('diff_evidence',self.compare,left,right)

    def test_tampering_is_recomputed_not_accepted_on_self_digest(self):
        left,original = self.typed('left')
        right = self.root/'bad.json'
        for key in ('register','binding','raw','decoded','extra','missing','gaps','budget'):
            bad = copy.deepcopy(original)
            record = bad[sidecars.FIELD]['records'][0]
            if key=='register': record['abi_projection']['arguments'][2]['register']='x31'
            elif key=='binding': record['binding']['entry_va']='0x2000'
            elif key=='raw': record['declaration']['type_encoding']='v@:'
            elif key=='decoded': record['decoded_types']['declaration']='invented'
            elif key=='extra': record['invented']=True
            elif key=='missing': bad[sidecars.FIELD]['records']=[]
            elif key=='gaps': record['metadata_gaps']=['invented_gap']
            elif key=='budget': record['declaration']['type_encoding']='q'*100000
            record['sha256']=storage.identity({k:v for k,v in record.items() if k!='sha256'})
            self.save(right,bad)
            self.error('diff_evidence',self.compare,left,right)

    def test_unavailable_states_preserve_original_function(self):
        _,original = self.typed()
        for scenario,reason in (('ambiguous','method_declaration_ambiguous'),('entry','method_entry_mismatch'),
                ('metadata','method_selection_incomplete'),('slot','exact_class_slot_required'),
                ('wrong_slot','method_class_slot_mismatch'),
                ('function','selected_function_unavailable'),('image','image_unavailable'),
                ('query','selected_query_unavailable')):
            report = copy.deepcopy(original)
            row = report['leads'][0]
            gaps = {}
            if scenario=='ambiguous': row['matches']*=2
            elif scenario=='entry': row['matches'][0]['implementation_va']='0x2000'
            elif scenario=='metadata':
                gaps[row['lead']['id']]=['method_limit'];row['gaps'].append('method_limit')
            elif scenario=='slot': del row['lead']['class_slot']
            elif scenario=='wrong_slot': row['matches'][0]['class_slot']='0xbad0'
            elif scenario=='function': row['function']=None
            elif scenario=='image': report['images'][0]['status']='unavailable'
            elif scenario=='query': row['query']={'status':'unavailable','reason':'evidence_query_mismatch'}
            before=copy.deepcopy(row)
            report[sidecars.FIELD]=sidecars.build(report,gaps)
            self.assertEqual(row,before)
            record=report[sidecars.FIELD]['records'][0]
            self.assertEqual((record['status'],record['reason']),('unavailable',reason))
            sidecars.validate(report)

    def test_redaction_and_deep_types_do_not_invalidate_report_or_invent_raw_types(self):
        _,report=self.typed()
        report['leads'][0]['matches'][0]['type_encoding']='@"/Users/owner/Name"24@0:8@16'
        report[sidecars.FIELD]=sidecars.build(report,{})
        clean=sidecars.redact_report(report,cli.redact)
        self.assertNotIn(b'/Users/owner',storage.canonical(clean))
        self.assertEqual(clean[sidecars.FIELD]['records'][0]['reason'],'declaration_redacted')
        sidecars.validate(clean)
        self.assertEqual({k:v for k,v in clean.items() if k!=sidecars.FIELD},
                         cli.redact({k:v for k,v in report.items() if k!=sidecars.FIELD}))
        report['leads'][0]['matches'][0]['type_encoding']='v24@0:8^'+'{N='*25+'q'+'}'*25+'16'
        report[sidecars.FIELD]=sidecars.build(report,{})
        self.assertEqual(report[sidecars.FIELD]['records'][0]['reason'],'sidecar_nesting_limit')
        storage.strict_json(storage.canonical(report))
        with patch.object(sidecars,'MAX_SIDECAR_BYTES',400):
            report[sidecars.FIELD]=sidecars.build(report,{})
            self.assertEqual(report[sidecars.FIELD]['records'][0]['status'],'unavailable')


class SidecarExportTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.workspace=self.project()
        data=bytearray(fixture())
        data[0x600:0x604]=bytes.fromhex('c0035fd6')
        snapshot,record=synthetic_snapshot(self.workspace,slice_bytes=bytes(data))
        self.entry=hex(BASE+0x600)
        f=snapshot['functions'][0]
        f.update(function_id='a'*64,entry_va=self.entry,engine_entry=self.entry,
                 body_ranges=[[self.entry,hex(BASE+0x603)]],origin={'mode':'saved'},
                 instructions=[dict(addr=self.entry,bytes='c0035fd6',mnemonic='ret')],
                 blocks=[dict(min=self.entry,max=self.entry,dsts=[])])
        snapshot['functions']=[f]
        path=self.workspace.path/'snapshots'/(snapshot['analysis_id']+'.json')
        storage.write_json(path,snapshot,force=True)
        record['snapshot_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.workspace.db(False) as db:
            db.execute('UPDATE analyses SET payload=? WHERE id=?',(json.dumps(record),snapshot['analysis_id']))
        self.snapshot=snapshot
        image=snapshot['image']
        self.pin=dict(image_id=image['image_id'],arch=image['arch'],artifact_sha256=image['artifact_sha256'],
                      slice_sha256=image['sha256'],analysis_id=snapshot['analysis_id'])
        self.lead=dict(id='method',image_id=image['image_id'],kind='objc_selector',value='probe',class_slot=hex(BASE+0x300))
        self.manifest=dict(schema=evidence.LEADS_SCHEMA,images=[self.pin],leads=[self.lead])

    def query(self,*extra):
        path=self.root/'leads.json'
        storage.write_json(path,self.manifest,force=True)
        with patch.object(engine,'run',side_effect=AssertionError('engine forbidden')), \
             patch.object(engine,'dependencies',side_effect=AssertionError('engine forbidden')):
            return cli.execute(cli.parser().parse_args(['evidence','--project',str(self.workspace.path),'--leads',str(path),*extra]))

    def test_real_metadata_saved_snapshot_offline_and_raw_compatibility(self):
        raw=self.query()
        enriched=self.query('--objc-types')
        sidecars.validate(enriched['data'])
        self.assertEqual(raw['data'],{k:v for k,v in enriched['data'].items() if k!=sidecars.FIELD})
        self.assertEqual(enriched['data'][sidecars.FIELD]['records'][0]['status'],'associated')
        self.assertEqual(enriched['data'][sidecars.FIELD]['records'][0]['decoded_types']['declaration'],'- (void)probe')
        self.assertEqual(enriched,self.query('--objc-types'))
        # Pin selection survives a different active analysis without source mutation.
        with self.workspace.db(False) as db:
            db.execute('UPDATE images SET active_analysis=?',('f'*64,))
        self.assertEqual(enriched,self.query('--objc-types'))
        self.assertEqual(cli.render(enriched,'html'),cli.render(self.query('--objc-types'),'html'))

    def test_cli_output_exit_and_receipt_immutability(self):
        raw = self.query()
        enriched = self.query('--objc-types')
        self.assertEqual(raw['status'], enriched['status'])
        snapshot_before = {p.name: p.read_bytes() for p in (self.workspace.path/'snapshots').iterdir() if p.is_file()}
        job_names = sorted(p.name for p in (self.workspace.path/'jobs').iterdir())
        for fmt in ('json', 'text', 'html', 'compact'):
            target = self.root / ('output.' + fmt)
            with patch.object(engine, 'run', side_effect=AssertionError('engine forbidden')):
                code = cli.main(['evidence', '--project', str(self.workspace.path), '--leads', str(self.root/'leads.json'),
                                 '--objc-types', '--format', fmt, '--output', str(target)])
            self.assertEqual(code, 6 if enriched['status']=='partial' else 0)
            self.assertTrue(target.read_bytes())
        self.assertEqual(snapshot_before, {p.name: p.read_bytes() for p in (self.workspace.path/'snapshots').iterdir() if p.is_file()})
        self.assertEqual(job_names, sorted(p.name for p in (self.workspace.path/'jobs').iterdir()))

    def test_partial_metadata_missing_slice_and_invalid_pin_fail_only_sidecar(self):
        with patch.object(objc,'MAX_METHODS',0):
            result=self.query('--objc-types')
        self.assertEqual(result['data'][sidecars.FIELD]['records'][0]['reason'],'method_selection_incomplete')
        sidecars.validate(result['data'])
        with patch.object(objc,'MAX_METHODS',0),patch.object(evidence,'MAX_LEAD_BYTES',1):
            limited=self.query('--objc-types')
        self.assertEqual(limited['data'][sidecars.FIELD]['records'][0]['reason'],'lead_output_limit')
        sidecars.validate(limited['data'])
        self.pin['slice_sha256']='f'*64
        result=self.query('--objc-types')
        self.assertEqual(result['data'][sidecars.FIELD]['records'][0]['reason'],'image_unavailable')
        self.pin['slice_sha256']=self.snapshot['image']['sha256']
        source=self.workspace.path/'inputs'/(self.pin['image_id']+'.macho')
        source.rename(source.with_suffix('.held'))
        result=self.query('--objc-types')
        self.assertEqual(result['data'][sidecars.FIELD]['records'][0]['status'],'unavailable')
        sidecars.validate(result['data'])

    def test_focused_result_reader_path_retains_conditional_sidecar(self):
        # Exercise import-pinned integration using a synthetic focused reader
        # result. Existing receipt tests cover receipt publication and tampering.
        image=dict(self.snapshot['image'],engine_baseline_sha256='b'*64)
        with self.workspace.db(False) as db:
            db.execute('UPDATE images SET metadata=?',(json.dumps(image),))
        del self.pin['analysis_id']
        self.pin['import_program_sha256']='b'*64
        self.lead['query_job']='c'*32
        function=copy.deepcopy(self.snapshot['functions'][0])
        focused=cli.envelope('decompile',function,cov=cli.coverage('owned synthetic',1,1))
        with patch.object(evidence,'focused_query',return_value=focused) as read:
            result=self.query('--objc-types')
        self.assertEqual(read.call_count,1)
        record=result['data'][sidecars.FIELD]['records'][0]
        self.assertEqual(record['status'],'associated')
        self.assertEqual(record['binding']['query_job'],'c'*32)
        self.assertNotIn('analysis_id',record['binding'])
        sidecars.validate(result['data'])


if __name__=='__main__':
    unittest.main()
