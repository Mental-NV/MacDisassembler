"""Owned Mach-O receipts exercise links without native code execution."""
import copy
import hashlib
import struct
from unittest.mock import patch
from macscope import callback_evidence, callback_links, cli, focused, import_disasm, storage
from test_core import TemporaryCase
from test_macho import command, image as macho_image


class CallbackLinkTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.project_ = self.project()
        section=struct.pack('<16s16s2Q8I',b'__text',b'__TEXT',0x1200,0x80,0x200,2,0,0,0x80000400,0,0,0)
        segment=struct.pack('<16s4Q4I',b'__TEXT',0x1000,0x300,0,0x300,7,5,1,0)
        raw=bytearray(macho_image(commands=[command(0x19,segment+section),command(0x26,struct.pack('<II',0x280,5))]))
        raw.extend(bytes(0x300-len(raw)))
        raw[0x200:0x204]=bytes.fromhex('04000014')  # B 0x1210
        raw[0x210:0x218]=bytes.fromhex('800a00f9c0035fd6')  # STR x0,[x20,#16]; RET
        raw[0x280:0x285]=bytes.fromhex('8004100800')
        self.raw=bytes(raw)
        self.image={'image_id':'owned','arch':'arm64','sha256':hashlib.sha256(raw).hexdigest(),
                    'offset':'0x0','engine_baseline_sha256':'a'*64}
        self.source=self.save('b'*32,0x1200,0x1204)
        self.target=self.save('c'*32,0x1210,0x1218)

    def save(self, job,start,end):
        proof,payload=import_disasm.selection(self.raw,self.image,start,end)
        rows=[{'addr':hex(start+i),'bytes':payload[i:i+4].hex(),'mnemonic':'owned','text':'owned'} for i in range(0,len(payload),4)]
        request=import_disasm.binding(self.project_,self.image,proof)
        manifest={'job_id':job,'status':'complete','mode':'query','disasm_request':request}
        (self.project_.path/'jobs'/job).mkdir()
        response=cli.envelope('disasm',{'selection':request,'instructions':rows,'gaps':[],
                                      'covered_bytes':len(payload),'origin':{'job_id':job}})
        import_disasm.publish(self.project_,manifest,response)
        return response

    def attach(self,source=None,job='c'*32,image=None):
        return callback_links.attach(self.project_,image or self.image,self.raw,
                callback_evidence.project(source or self.source),job)['data']['callback_evidence']

    def test_real_linker_entry_and_writer_observation_stay_separate(self):
        saved=copy.deepcopy(self.source)
        path=self.project_.path/'jobs'/('c'*32)/'disasm-result.json';before=path.read_bytes()
        with patch.object(import_disasm.engine,'dependencies',side_effect=AssertionError('native')):
            r=self.attach()
        link=r['destination_link']
        self.assertEqual(link['status'],'verified_direct_entry_link')
        self.assertEqual(link['destination_extent']['entry_va'],'0x1210')
        self.assertEqual(link['destination_evidence']['sites'][0]['kind'],'memory_store')
        self.assertEqual(link['writer_attribution'],'unknown')
        self.assertEqual(r['status'],'inconclusive')
        self.assertEqual(path.read_bytes(),before)
        self.assertEqual(self.source,saved)

    def test_mismatched_direct_target_is_gap(self):
        s=copy.deepcopy(self.source);s['data']['instructions'][0]['bytes']='05000014'
        self.assertEqual(self.attach(source=s)['destination_link']['reason'],'selected_direct_destination_not_proven')

    def test_interior_destination_cannot_become_function_entry(self):
        self.save('d'*32,0x1214,0x1218)
        s=copy.deepcopy(self.source);s['data']['instructions'][0]['bytes']='05000014'
        link=self.attach(source=s,job='d'*32)['destination_link']
        self.assertEqual(link['reason'],'destination_linker_extent_unavailable')
        self.assertEqual(link['extent_error'],'focused_entry_missing')

    def test_extent_crossing_cannot_become_link(self):
        self.save('e'*32,0x1210,0x121c)
        self.assertEqual(self.attach(job='e'*32)['destination_link']['reason'],'destination_selection_exceeds_linker_extent')

    def test_stale_receipt_and_wrong_image_fail_closed(self):
        self.error('disasm_receipt_identity',self.attach,image=dict(self.image,engine_baseline_sha256='e'*64))
        path=self.project_.path/'jobs'/('c'*32)/'disasm-result.json';path.write_text('{}')
        self.error('disasm_receipt_identity',self.attach)

    def test_malformed_request_fails_with_receipt_error(self):
        path=self.project_.path/'jobs'/('c'*32)/'job.json'
        import json
        manifest=json.loads(path.read_text());manifest['disasm_request']=[]
        storage.write_json(path,manifest,force=True)
        self.error('callback_target_receipt',self.attach)

    def test_wrong_image_identity_is_rejected(self):
        self.error('disasm_receipt_identity',self.attach,image=dict(self.image,image_id='other'))

    def test_unsupported_writer_prefix_retains_link_not_a_writer(self):
        # New owned image begins destination with SUB SP,SP,#16; the receipt
        # remains valid but no later store can be claimed by this projection.
        raw=bytearray(self.raw);raw[0x210:0x214]=bytes.fromhex('ff4300d1')
        self.raw=bytes(raw);self.image=dict(self.image,sha256=hashlib.sha256(raw).hexdigest())
        self.source=self.save('f'*32,0x1200,0x1204)
        self.save('1'*32,0x1210,0x1218)
        link=self.attach(job='1'*32)['destination_link']
        self.assertEqual(link['status'],'verified_direct_entry_link')
        self.assertEqual(link['destination_evidence']['sites'],[])
        self.assertEqual(link['destination_evidence']['stop_reason'],'unsupported_instruction_boundary')
        self.assertEqual(link['writer_attribution'],'unknown')

    def test_partial_destination_keeps_gap_with_verified_entry_link(self):
        import json
        response=copy.deepcopy(self.target)
        response['status']='partial'
        response['data']['instructions']=response['data']['instructions'][:1]
        response['data']['gaps']=[{'start_va':'0x1214','end_va':'0x1218','reason':'undecodable_or_unavailable'}]
        response['data']['covered_bytes']=4
        path=self.project_.path/'jobs'/('c'*32)/'disasm-result.json'
        storage.write_json(path,response,force=True)
        manifest_path=path.parent/'job.json'
        manifest=json.loads(manifest_path.read_text());manifest['disasm_result_sha256']=import_disasm.digest(path)
        storage.write_json(manifest_path,manifest,force=True)
        link=self.attach()['destination_link']
        self.assertEqual(link['status'],'verified_direct_entry_link')
        self.assertIn({'reason':'disassembly_incomplete'},link['destination_evidence']['gaps'])
        self.assertEqual(link['writer_attribution'],'unknown')

    def test_cli_offline_two_receipt_projection_is_deterministic(self):
        from types import SimpleNamespace
        args=SimpleNamespace(receipt='b'*32,callback_evidence=True,callback_target_receipt='c'*32)
        with patch.object(cli.metadata,'verified_slice',return_value=self.raw), \
             patch.object(import_disasm.engine,'dependencies',side_effect=AssertionError('native')), \
             patch.object(import_disasm,'run',side_effect=AssertionError('native')):
            first=cli.imported_disassembly(args,self.project_,self.image,0x1200,0x1204)
            second=cli.imported_disassembly(args,self.project_,self.image,0x1200,0x1204)
        self.assertEqual(first,second)
        self.assertEqual(first['data']['callback_evidence']['destination_link']['status'],'verified_direct_entry_link')

    def test_cli_requires_evidence_option(self):
        args=cli.parser().parse_args(['disasm','--project','owned','--from-import','--range','0x1200:0x1204',
                                     '--callback-target-receipt','c'*32])
        self.error('callback_scope',cli.execute,args)
