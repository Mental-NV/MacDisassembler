"""Owned conditional stores do not prove callee purity or application writes."""
import hashlib
import struct
from types import SimpleNamespace
from unittest.mock import patch
from macscope import cli, import_disasm, writer_call_obligations
from test_core import TemporaryCase
from test_macho import command, image as macho_image
import test_callback_links


def bl(pc,target=0x1300):
    return (0x94000000|(((target-pc)//4)&0x3ffffff)).to_bytes(4,'little').hex()


class WriterCallTests(TemporaryCase):
    save=test_callback_links.CallbackLinkTests.save

    def prepare(self, writer=None):
        self.count=getattr(self,'count',0)+1
        self.project_=self.project('project'+str(self.count))
        section=struct.pack('<16s16s2Q8I',b'__text',b'__TEXT',0x1200,0x200,0x200,2,0,0,0x80000400,0,0,0)
        segment=struct.pack('<16s4Q4I',b'__TEXT',0x1000,0x500,0,0x500,7,5,1,0)
        raw=bytearray(macho_image(commands=[command(0x19,segment+section),command(0x26,struct.pack('<II',0x480,5))]))
        raw.extend(bytes(0x500-len(raw)))
        writer=writer or 'f30300aa'+bl(0x1214)+'930a00f9c0035fd6'
        raw[0x200:0x204]=bytes.fromhex('04000014')
        raw[0x210:0x210+len(bytes.fromhex(writer))]=bytes.fromhex(writer)
        # ADR x8,0x1200; STP x8,x20,[x0,#16]; RET.
        raw[0x280:0x28c]=bytes.fromhex('08fcff10085001a9c0035fd6')
        raw[0x2a0:0x2a8]=bytes.fromhex('085041a900013fd6')
        raw[0x480:0x485]=bytes.fromhex('8004107000')
        self.raw=bytes(raw)
        self.image={'image_id':'owned','arch':'arm64','sha256':hashlib.sha256(raw).hexdigest(),
                    'offset':'0x0','engine_baseline_sha256':'a'*64}
        self.save('b'*32,0x1200,0x1204)
        self.save('c'*32,0x1210,0x1210+len(bytes.fromhex(writer)))
        self.save('d'*32,0x1280,0x128c)
        self.save('e'*32,0x12a0,0x12a8)

    def composed(self, *, abi='aapcs64', enabled=True):
        args=SimpleNamespace(receipt='b'*32,callback_evidence=True,callback_provenance=True,
            callback_target_receipt='c'*32,callback_assignment_receipt='d'*32,
            callback_invocation_receipt='e'*32,callback_abi=abi,callback_writer_call_obligations=enabled)
        with patch.object(cli.metadata,'verified_slice',return_value=self.raw), \
             patch.object(import_disasm.engine,'dependencies',side_effect=AssertionError('native')):
            return cli.imported_disassembly(args,self.project_,self.image,0x1200,0x1204)['data']['callback_evidence']['composition']

    def test_callee_saved_relation_is_conditional_not_application_attribution(self):
        self.prepare();r=self.composed()
        self.assertEqual(r['candidate_status'],'conditional_candidate',r['gaps'])
        proof=r['writer_call_evidence']
        self.assertEqual(proof['status'],'conditional_obligations')
        self.assertEqual(proof['calls'][0]['memory_effects'],'unknown')
        store,=proof['post_call_stores']
        self.assertEqual(store['base_basis'],'matched_input_register')
        self.assertEqual(store['value_basis'],'matched_input_register')
        self.assertEqual(store['evidence']['conditional_on_calls'],['0x1214'])
        self.assertEqual(r['destination_effects']['application_writer_attribution'],'unknown')
        self.assertIn('receiver_lifetime_after_writer_calls',r['unknowns'])
        # Invocation-to-thunk bindings do not inherit future writer call sites.
        self.assertEqual(r['conditional_register_bindings'][0]['requires_call_conditions'],[])
        self.assertEqual(self.composed(enabled=False)['candidate_status'],'gap')
        self.error('callback_scope',self.composed,abi=None)

    def test_caller_clobbered_and_load_operands_do_not_compose(self):
        for suffix,reason in [('800a00f9','writer_post_call_value_unresolved'),
                              ('130000f9','writer_post_call_base_unresolved'),
                              ('810a40f9330000f9','writer_post_call_base_unresolved'),
                              ('6002148b800a00f9','writer_post_call_value_unresolved')]:
            self.prepare('f30300aa'+bl(0x1214)+suffix+'c0035fd6')
            r=self.composed()
            self.assertEqual(r['candidate_status'],'gap')
            self.assertIn(reason,[g['reason'] for g in r['writer_call_evidence']['gaps']])

    def test_byte_constant_and_stack_effects_stay_distinct(self):
        self.prepare('f30300aa'+bl(0x1214)+'e00080d2800a00f9c0035fd6')
        r=self.composed()
        self.assertEqual(r['candidate_status'],'conditional_candidate',r['gaps'])
        self.assertEqual(r['writer_call_evidence']['post_call_stores'][0]['value_basis'],'byte_defined')
        self.prepare('f30300aa'+bl(0x1214)+'f30300f9c0035fd6')
        r=self.composed()
        self.assertEqual(r['candidate_status'],'conditional_candidate',r['gaps'])
        self.assertEqual(r['destination_effects']['summary'],'only_stack_or_frame_stores')
        self.assertEqual(r['destination_effects']['application_writer_attribution'],'unknown')

    def test_calls_back_into_extent_or_other_role_are_gaps(self):
        for target in (0x1214,0x1250,0x1280,0x12a0,0x1200):
            self.prepare('f30300aa'+bl(0x1214,target)+'930a00f9c0035fd6')
            r=self.composed()
            self.assertEqual(r['candidate_status'],'gap')
            self.assertIn('writer_call_cycle_or_reentry',[g['reason'] for g in r['writer_call_evidence']['gaps']])

    def test_call_and_store_budget_omissions_are_explicit(self):
        self.prepare('f30300aa'+''.join(bl(0x1214+4*i) for i in range(9))+'930a00f9c0035fd6')
        r=self.composed();p=r['writer_call_evidence']
        self.assertEqual(r['candidate_status'],'gap')
        self.assertEqual(p['omitted_calls'],1)
        self.assertEqual(len(p['calls']),8)
        self.prepare('f30300aa'+bl(0x1214)+'935201a9c0035fd6') # STP x19,x20,[x20,#16]
        with patch.object(writer_call_obligations,'MAX_POST_CALL_STORES',1):r=self.composed()
        self.assertEqual(r['candidate_status'],'gap')
        self.assertEqual(r['writer_call_evidence']['omitted_post_call_stores'],1)
        self.assertEqual(len(r['facts']['writer_stores']),2)

    def test_unsupported_writer_branch_stays_a_gap(self):
        self.prepare('f30300aa'+bl(0x1214)+'730000b4930a00f9c0035fd6')
        r=self.composed()
        self.assertEqual(r['candidate_status'],'gap')
        self.assertIn({'reason':'writer_unsupported_boundary'},r['gaps'])

    def test_offline_replay_preserves_job_set_and_bytes(self):
        self.prepare()
        def saved():return {str(p):p.read_bytes() for p in (self.project_.path/'jobs').rglob('*') if p.is_file()}
        before=saved()
        self.assertEqual(self.composed(),self.composed())
        self.assertEqual(saved(),before)

    def test_cli_requires_explicit_abi_and_composition(self):
        args=cli.parser().parse_args(['disasm','--project','owned','--from-import','--range','0x1200:0x1204','--callback-writer-call-obligations'])
        self.error('callback_scope',cli.execute,args)

    def test_indirect_boundary_retains_store_but_does_not_compose(self):
        self.prepare('f30300aa'+bl(0x1214)+'930a00f960023fd6')
        r=self.composed()
        self.assertEqual(r['candidate_status'],'gap')
        self.assertIn({'reason':'writer_indirect_invocation_boundary'},r['writer_call_evidence']['gaps'])
        self.assertEqual(len(r['writer_call_evidence']['post_call_stores']),1)
        self.assertIn('writer_stores',r['facts'])
        self.assertEqual(self.composed(enabled=False)['candidate_status'],'gap')
