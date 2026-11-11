"""Owned five-role saved evidence; no runtime dispatch or native engine."""
import hashlib
import shutil
import struct
from types import SimpleNamespace
from unittest.mock import patch
from macscope import cli,import_disasm
from test_core import TemporaryCase
from test_macho import command,image as macho_image
import test_callback_links


class FiveRoleTests(TemporaryCase):
    save=test_callback_links.CallbackLinkTests.save
    def setUp(self):
        super().setUp();self.project_=self.project()
        section=struct.pack('<16s16s2Q8I',b'__text',b'__TEXT',0x1200,0x80,0x200,2,0,0,0x80000400,0,0,0)
        segment=struct.pack('<16s4Q4I',b'__TEXT',0x1000,0x300,0,0x300,7,5,1,0)
        stream=bytes.fromhex('8004040c040c08180c140800')
        raw=bytearray(macho_image(commands=[command(0x19,segment+section),command(0x26,struct.pack('<II',0x280,len(stream)))]))
        raw.extend(bytes(0x300-len(raw)));raw[0x280:0x280+len(stream)]=stream
        for offset,code in ((0x200,'04000014'),(0x210,'04000014'),(0x220,'800a00f9c0035fd6'),
                            (0x240,'08feff10085001a9c0035fd6'),(0x260,'085041a900013fd6')):
            raw[offset:offset+len(bytes.fromhex(code))]=bytes.fromhex(code)
        self.raw=bytes(raw);self.save_all()

    def save_all(self):
        self.image={'image_id':'owned','arch':'arm64','offset':'0x0','engine_baseline_sha256':'a'*64,'sha256':hashlib.sha256(self.raw).hexdigest()}
        for job,start,end in (('1'*32,0x1200,0x1204),('2'*32,0x1210,0x1214),('3'*32,0x1220,0x1228),('4'*32,0x1240,0x124c),('5'*32,0x1260,0x1268)):
            path=self.project_.path/'jobs'/job
            if path.exists():shutil.rmtree(path)
            self.save(job,start,end)

    def compose(self, invocation='5'*32):
        args=SimpleNamespace(receipt='1'*32,callback_evidence=True,callback_provenance=True,callback_abi=None,
                             callback_via_receipt='2'*32,callback_target_receipt='3'*32,
                             callback_assignment_receipt='4'*32,callback_invocation_receipt=invocation)
        with patch.object(cli.metadata,'verified_slice',return_value=self.raw),patch.object(import_disasm.engine,'dependencies',side_effect=AssertionError('native')):
            return cli.imported_disassembly(args,self.project_,self.image,0x1200,0x1204)['data']['callback_evidence']['composition']

    def test_five_roles_are_explicit_conditional_and_immutable(self):
        before={str(p):p.read_bytes() for p in (self.project_.path/'jobs').rglob('*') if p.is_file()}
        c=self.compose();self.assertEqual(c,self.compose())
        self.assertEqual(c['candidate_status'],'conditional_candidate',c['gaps'])
        self.assertEqual(c['policy'],'macscope-callback-composition/4');self.assertEqual(c['status'],'inconclusive')
        self.assertEqual(len(c['role_identities']),5);self.assertEqual(len(c['conditional_writer_entry_bindings']),19)
        self.assertNotIn('direct_destination',c['facts']);self.assertIn('inner_direct_destination',c['facts'])
        self.assertEqual(c['facts']['forwarding_route']['destination_entry_va'],'0x1220')
        self.assertEqual(before,{str(p):p.read_bytes() for p in (self.project_.path/'jobs').rglob('*') if p.is_file()})

    def test_wrong_assignment_and_inner_prefix_block_candidate(self):
        raw=bytearray(self.raw);raw[0x240:0x244]=bytes.fromhex('88feff10');self.raw=bytes(raw);self.save_all()
        self.assertEqual(self.compose()['candidate_status'],'gap')
        raw[0x240:0x244]=bytes.fromhex('08feff10');raw[0x284]=8;raw[0x285]=8;self.raw=bytes(raw);self.save_all()
        c=self.compose();self.assertIn({'reason':'verified_two_thunk_forwarding_missing'},c['gaps']);self.assertFalse(c['conditional_writer_entry_bindings'])

    def test_stale_inner_receipt_fails(self):
        (self.project_.path/'jobs'/('2'*32)/'disasm-result.json').write_text('{}')
        from macscope.errors import Error
        with self.assertRaises(Error):self.compose()

    def test_duplicate_receipts_rejected_before_project_or_engine(self):
        args=['disasm','--project',str(self.project_.path),'--from-import','--range','0x1200:0x1204','--receipt','1'*32,'--callback-evidence','--callback-provenance',
              '--callback-via-receipt','2'*32,'--callback-target-receipt','3'*32,'--callback-assignment-receipt','1'*32,'--callback-invocation-receipt','5'*32]
        self.error('callback_scope',cli.execute,cli.parser().parse_args(args))

    def test_overlapping_roles_and_writer_backedge_block_bindings(self):
        self.save('6'*32,0x1220,0x1228)
        c=self.compose(invocation='6'*32)
        self.assertIn({'reason':'overlapping_composition_roles'},c['gaps'])
        self.assertFalse(c['conditional_writer_entry_bindings'])
        for backedge in ('f8ffff17','fcffff17'):
            raw=bytearray(self.raw);raw[0x220:0x224]=bytes.fromhex(backedge);self.raw=bytes(raw);self.save_all()
            c=self.compose();self.assertIn({'reason':'writer_direct_link_cycle'},c['gaps'])
            self.assertFalse(c['conditional_writer_entry_bindings'])
