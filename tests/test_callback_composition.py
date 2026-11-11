"""Owned instruction/receipt fixture: no proprietary inputs or binary execution."""
import copy
import hashlib
import struct
from test_macho import command, image as macho_image
from types import SimpleNamespace
from unittest.mock import patch
from macscope import callback_composition, callback_evidence, cli, import_disasm
import test_callback_links
from test_core import TemporaryCase


class CompositionTests(TemporaryCase):
    save = test_callback_links.CallbackLinkTests.save
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
        raw = bytearray(self.raw)
        # ADR x8,0x1200; STP x8,x20,[x0,#16]; RET
        raw[0x220:0x22c] = bytes.fromhex('08ffff10085001a9c0035fd6')
        # LDP x8,x20,[x0,#16]; BLR x8
        raw[0x240:0x248] = bytes.fromhex('085041a900013fd6')
        self.raw = bytes(raw)
        self.image = dict(self.image,sha256=hashlib.sha256(raw).hexdigest())
        self.source = self.save('8'*32,0x1200,0x1204)
        self.save('9'*32,0x1210,0x1218)
        self.save('a'*32,0x1220,0x122c)
        self.save('0'*32,0x1240,0x1248)

    def composed(self, target_receipt=None, abi=None, context_register=None, fallthrough=False, writer_calls=False):
        args = SimpleNamespace(receipt='8'*32,callback_evidence=True,callback_provenance=True,
                               callback_target_receipt=target_receipt or '9'*32,callback_assignment_receipt='a'*32,
                               callback_invocation_receipt='0'*32,callback_abi=abi,callback_context_register=context_register,
                               callback_invocation_fallthrough=fallthrough,callback_writer_call_obligations=writer_calls)
        with patch.object(cli.metadata,'verified_slice',return_value=self.raw), \
             patch.object(import_disasm.engine,'dependencies',side_effect=AssertionError('native')):
            return cli.imported_disassembly(args,self.project_,self.image,0x1200,0x1204)['data']['callback_evidence']['composition']

    def test_positive_independent_facts_stay_conditional(self):
        r=self.composed()
        self.assertEqual(r['candidate_status'],'conditional_candidate',r['gaps'])
        self.assertEqual(r['status'],'inconclusive')
        self.assertEqual(r['assumptions'],[])
        self.assertIn('runtime_context_identity_and_abi',r['unknowns'])
        self.assertIn('writer_stores',r['facts'])
        self.assertEqual(len(r['facts']),7)
        binding=next(b for b in r['conditional_register_bindings'] if b['destination']['register']=='x20')
        self.assertEqual(binding['source']['value']['kind'],'memory_read')
        self.assertEqual(binding['status'],'conditional_not_applied_to_facts')
        self.assertIn('runtime_invoked_code_identity',binding['requires_unverified'])

    def test_replay_is_immutable_deterministic_without_engine(self):
        paths=list((self.project_.path/'jobs').glob('*/*'))
        before={str(p):p.read_bytes() for p in paths if p.is_file()}
        self.assertEqual(self.composed(),self.composed())
        after_paths=list((self.project_.path/'jobs').glob('*/*'))
        self.assertEqual(set(paths),set(after_paths))
        self.assertEqual(before,{str(p):p.read_bytes() for p in after_paths if p.is_file()})

    def change(self, offset, code, assignment_end=0x122c, invocation_end=0x1248):
        raw=bytearray(self.raw);raw[offset:offset+len(bytes.fromhex(code))]=bytes.fromhex(code)
        self.raw=bytes(raw);self.image=dict(self.image,sha256=hashlib.sha256(raw).hexdigest())
        # Replace fixture receipts intentionally; publication validates new identities.
        import shutil
        for receipt,start,end in [('8'*32,0x1200,0x1204),('9'*32,0x1210,0x1218),
                                  ('a'*32,0x1220,assignment_end),('0'*32,0x1240,invocation_end)]:
            shutil.rmtree(self.project_.path/'jobs'/receipt)
            self.save(receipt,start,end)

    def assertGap(self, reason):
        r=self.composed();self.assertEqual(r['candidate_status'],'gap')
        self.assertIn({'reason':reason},r['gaps'])

    def test_overwritten_callback(self):
        self.change(0x228,'090800f9c0035fd6',assignment_end=0x1230)
        self.assertGap('later_assignment_store_possible_overwrite')

    def test_context_layout_mismatch(self):
        self.change(0x240,'085042a9')
        self.assertGap('assignment_invocation_layout_mismatch')

    def test_clobbered_target(self):
        self.change(0x244,'e80309aa00013fd6',invocation_end=0x124c)
        self.assertGap('unique_paired_invocation_load_not_proven')

    def test_clobbered_context(self):
        self.change(0x244,'f40309aa00013fd6',invocation_end=0x124c)
        self.assertGap('invocation_context_clobbered_or_untracked')

    def test_uncertain_single_load(self):
        self.change(0x240,'080840f9')
        self.assertGap('unique_paired_invocation_load_not_proven')

    def test_unsupported_boundary(self):
        self.change(0x228,'00000000')
        self.assertGap('assignment_unsupported_boundary')

    def test_missing_receipt_fails_closed(self):
        import shutil
        shutil.rmtree(self.project_.path/'jobs'/('a'*32))
        from macscope.errors import Error
        with self.assertRaises(Error):self.composed()

    def test_cli_incomplete_roles_rejected(self):
        args=cli.parser().parse_args(['disasm','--project','owned','--from-import','--range','0x1200:0x1204',
                                     '--callback-assignment-receipt','a'*32])
        self.error('callback_scope',cli.execute,args)

    def test_self_writer_cycle(self):
        self.change(0x200,'00000014')
        r=self.composed(target_receipt='8'*32)
        self.assertEqual(r['candidate_status'],'gap')
        self.assertIn({'reason':'direct_link_cycle'},r['gaps'])

    def test_intervening_invocation_store(self):
        self.change(0x244,'090800f900013fd6',invocation_end=0x124c)
        self.assertGap('intervening_invocation_store')

    def test_context_loaded_from_unknown_memory_remains_unresolved(self):
        self.change(0x220,'140040f9e8feff10085001a9c0035fd6',assignment_end=0x1230)
        self.assertGap('assignment_context_value_unresolved')

    def test_writer_backedge_cycle(self):
        self.change(0x214,'fbffff17')
        self.assertGap('writer_direct_link_cycle')

    def test_known_slot_addresses_mismatch_without_alias_assumption(self):
        def adr(reg, pc, target):
            delta=(target-pc) & ((1<<21)-1)
            word=0x10000000|((delta&3)<<29)|((delta>>2)<<5)|reg
            return word.to_bytes(4,'little').hex()
        self.change(0x220,adr(0,0x1220,0x1300)+adr(8,0x1224,0x1200)+'085001a9c0035fd6',assignment_end=0x1230)
        self.change(0x240,adr(0,0x1240,0x1400)+'085041a900013fd6',assignment_end=0x1230,invocation_end=0x124c)
        self.assertGap('known_slot_address_mismatch')

    def test_known_movz_slot_addresses_mismatch(self):
        self.change(0x220,'006082d2e8feff10085001a9c0035fd6',assignment_end=0x1230)
        self.change(0x240,'008082d2085041a900013fd6',assignment_end=0x1230,invocation_end=0x124c)
        r=self.composed(abi='aapcs64')
        self.assertEqual(r['candidate_status'],'gap')
        self.assertIn({'reason':'known_slot_address_mismatch'},r['gaps'])
        self.assertTrue(r['assumptions'])

    def test_native_swift_oracle_preserves_unsupported_invocation(self):
        # Reverified Apple Swift6.4 -O OwnedCallbacks compiler output. These
        # contiguous slices do NOT establish a full composed compiler chain.
        from test_callback_provenance import project, encoded
        full=project(encoded('950e40f9550100b4941240f9e00315aae10314aa49ffff97e00313aaa0023fd6'),start=0xc80)
        self.assertEqual(full['stop_reason'],'unsupported_instruction_boundary')
        self.assertEqual(full['interpreted_end_va'],'0xc84')
        self.assertFalse(any(s['kind']=='indirect_invocation' for s in full['sites']))
        suffix=project(encoded('e00313aaa0023fd6'),start=0xc98)
        call=suffix['sites'][-1]
        self.assertEqual(call['kind'],'indirect_invocation')
        self.assertEqual(call['operand']['kind'],'range_input_register')
        self.assertEqual(call['operand']['register'],'x21')
        self.assertFalse(any(s['kind']=='memory_load' for s in suffix['sites']))
