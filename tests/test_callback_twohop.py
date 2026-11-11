"""Owned exact three-receipt route, with independent negative selections."""
import copy
import hashlib
import shutil
import struct
from unittest.mock import patch
from macscope import callback_evidence, callback_twohop, cli, import_disasm
import test_callback_links as fixtures
from test_core import TemporaryCase
from test_macho import command,image as macho_image


class TwoHopTests(TemporaryCase):
    save=fixtures.CallbackLinkTests.save
    def setUp(self):
        super().setUp();self.project_=self.project()
        section=struct.pack('<16s16s2Q8I',b'__text',b'__TEXT',0x1200,0x80,0x200,2,0,0,0x80000400,0,0,0)
        segment=struct.pack('<16s4Q4I',b'__TEXT',0x1000,0x300,0,0x300,7,5,1,0)
        raw=bytearray(macho_image(commands=[command(0x19,segment+section),command(0x26,struct.pack('<II',0x280,6))]))
        raw.extend(bytes(0x300-len(raw)))
        raw[0x200:0x204]=bytes.fromhex('04000014')
        raw[0x210:0x214]=bytes.fromhex('04000014')
        raw[0x220:0x228]=bytes.fromhex('800a00f9c0035fd6')
        raw[0x280:0x286]=bytes.fromhex('800410101000')
        self.raw=bytes(raw);self.source_end=0x1204;self.inner_end=0x1214;self.writer_end=0x1228
        self.image={'image_id':'owned','arch':'arm64','offset':'0x0','engine_baseline_sha256':'a'*64}
        self.resave()

    def resave(self):
        self.image['sha256']=hashlib.sha256(self.raw).hexdigest()
        for id_,start,end in (('a'*32,0x1200,self.source_end),('b'*32,0x1210,self.inner_end),('c'*32,0x1220,self.writer_end)):
            path=self.project_.path/'jobs'/id_
            if path.exists():shutil.rmtree(path)
            response=self.save(id_,start,end)
            if id_=='a'*32:self.source=response

    def change(self,offset,code):
        raw=bytearray(self.raw);raw[offset:offset+len(bytes.fromhex(code))]=bytes.fromhex(code);self.raw=bytes(raw);self.resave()

    def chain(self,via='b'*32,target='c'*32,checked_add=False):
        response=callback_evidence.project(self.source,abi='aapcs64')
        with patch.object(import_disasm.engine,'dependencies',side_effect=AssertionError('native')):
            r=callback_twohop.attach(self.project_,self.image,self.raw,response,via,target,abi='aapcs64',checked_add=checked_add)
        self.assertNotIn('two_hop_chain',response['data']['callback_evidence'])
        self.assertNotIn('destination_link',r['data']['callback_evidence'])
        return r['data']['callback_evidence']['two_hop_chain']

    def test_independent_edges_and_unknowns(self):
        r=self.chain();self.assertEqual(r['link_status'],'verified_two_hop_entry_links')
        self.assertEqual(r['status'],'inconclusive');self.assertEqual(r['source_extent'],'not_proven_selected_bytes_only')
        self.assertEqual([e['transfer']['target_va'] for e in r['edges']],['0x1210','0x1220'])
        self.assertEqual(r['destination_effects']['application_writer_attribution'],'unknown')
        self.assertIn('transitive_register_correspondence_not_applied',r['unknowns'])
        self.assertEqual(set(r['role_identities']),{'outer','inner','destination'})

    def test_immutable_deterministic_replay(self):
        def snapshot():return {str(p):p.read_bytes() for p in (self.project_.path/'jobs').rglob('*') if p.is_file()}
        before=snapshot();self.assertEqual(self.chain(),self.chain());self.assertEqual(before,snapshot())

    def test_wrong_direct_target_and_nonentry_destination(self):
        self.change(0x200,'05000014');r=self.chain()
        self.assertEqual(r['link_status'],'gap')
        self.assertIn('selected_direct_destination_not_proven',[g['reason'] for g in r['gaps']])
        self.change(0x200,'04000014');self.change(0x210,'05000014')
        self.save('d'*32,0x1224,0x1228)
        r=self.chain(target='d'*32)
        self.assertIn('destination_linker_extent_unavailable',[g['reason'] for g in r['gaps']])

    def test_bl_and_extended_prefix_rejected(self):
        self.change(0x200,'04000094')
        self.assertIn({'reason':'single_instruction_thunk_not_proven','role':'outer'},self.chain()['gaps'])
        self.change(0x200,'04000014');self.inner_end=0x1218;self.resave()
        self.assertIn({'reason':'single_instruction_thunk_not_proven','role':'inner'},self.chain()['gaps'])

    def test_final_reentry_and_overlap(self):
        self.change(0x220,'f8ffff17')
        self.assertIn({'reason':'destination_cycle_or_reentry'},self.chain()['gaps'])
        self.save('d'*32,0x1200,0x1204)
        self.assertTrue(any(g['reason']=='overlapping_role_selections' for g in self.chain(via='d'*32)['gaps']))

    def test_guard_is_preserved_in_each_derived_store_view(self):
        self.writer_end=0x1230
        self.change(0x220,'130400b166000054930a00f9c0035fd6')
        default=self.chain();self.assertEqual(default['destination_stop_reason'],'unsupported_instruction_boundary')
        c=self.chain(checked_add=True);edge=c['edges'][1]
        raw=next(s for s in edge['destination_evidence']['sites'] if s['kind']=='memory_store')
        self.assertEqual(raw['conditional_on_branches'],['0x1224'])
        for s in (edge['store_relations'][0],c['destination_effects']['observed_stores'][0]):
            self.assertEqual(s['destination_branch_conditions'],['0x1224'])
            self.assertEqual(s['source_branch_conditions'],[])
        for view in (edge,c['destination_effects']):
            path,=view['destination_path_obligations']
            self.assertEqual(path['source_envelope_sha256'],c['role_identities']['destination']['source_envelope_sha256'])
            self.assertEqual(path['evidence']['fallthrough_predicate'],'no_signed_overflow')

    def test_stale_receipt_fails_closed(self):
        path=self.project_.path/'jobs'/('b'*32)/'disasm-result.json';path.write_text('{}')
        from macscope.errors import Error
        with self.assertRaises(Error):self.chain()

    def test_cli_requires_distinct_selected_only_receipts(self):
        base=['disasm','--project','absent','--from-import','--range','0x1200:0x1204',
              '--callback-evidence','--receipt','a'*32,'--callback-via-receipt','b'*32]
        for extra in ([],['--callback-target-receipt','a'*32],
            ['--callback-target-receipt','c'*32,'--callback-assignment-receipt','d'*32],
            ['--callback-target-receipt','c'*32,'--callback-checked-add-fallthrough'],
            ['--callback-target-receipt','c'*32,'--callback-destination-checked-add-fallthrough']):
            self.error('callback_scope',cli.execute,cli.parser().parse_args(base+extra))
