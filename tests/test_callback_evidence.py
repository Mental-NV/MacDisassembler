"""Independently authored A64 words; no recovered application content."""
import copy
import json
import unittest
from macscope import callback_evidence as subject, cli


def receipt(words, arch='arm64'):
    rows = [{'addr':hex(0x1000+4*i),'bytes':w.to_bytes(4,'little').hex(),
             'mnemonic':'deliberately misleading','text':'not evidence'} for i,w in enumerate(words)]
    return {'status':'complete','data':{'selection':{'arch':arch,'start_va':'0x1000',
            'end_va':hex(0x1000+4*len(words)),'image_id':'owned'},'instructions':rows,'gaps':[]}}


def report(words):
    return subject.project(receipt(words))['data']['callback_evidence']


class CallbackTests(unittest.TestCase):
    def test_address_store_and_load_call_stay_separate(self):
        # adr x1,.; str x1,[x0,#8]; ldr x2,[x0,#8]; blr x2
        r = report([0x10000001,0xf9000401,0xf9400402,0xd63f0040])
        store,load,call = r['sites']
        self.assertEqual(store['value']['value'],'0x1000')
        self.assertEqual(load['location']['offset'],8)
        self.assertEqual(call['operand'],{'kind':'memory_read','origin_va':'0x1008'})
        self.assertNotIn('value',call['operand'])
        self.assertEqual(r['status'],'inconclusive')
        self.assertIn('eventual_state_writer',r['missing_evidence'])

    def test_overwrite_and_copy_do_not_retain_old_target(self):
        r = report([0x10000001,0xf9000001,0x10000001,0xaa0103e2,0xf9000002])
        self.assertEqual([s['value']['value'] for s in r['sites']],['0x1000','0x1008'])

    def test_unknown_target(self):
        r = report([0xd63f0060])
        self.assertEqual(r['sites'][0]['operand']['kind'],'unknown')

    def test_barriers_never_join_or_cross_calls(self):
        for word in (0x54000040,0xd61f0000,0x52800001,0xffffffff):
            r = report([0x10000001,word,0xf9000001])
            self.assertEqual(r['sites'],[])
            self.assertEqual(r['gaps'][0]['reason'],'unsupported_instruction_boundary')
        self.assertEqual(len(report([0xd63f0000,0xf9000001])['sites']),1)
        self.assertEqual(report([0xd65f03c0,0xf9000001])['sites'],[])

    def test_sp_zr_and_shifted_mov_are_not_pointer_proofs(self):
        for word in (0xf900001f,0x910003e1,0xaa0107e2):
            self.assertEqual(report([word,0xd63f0040])['sites'],[])

    def test_signed_adr_and_adrp_add(self):
        self.assertEqual(report([0x10ffffe1,0xf9000001])['sites'][0]['value']['value'],'0xffc')
        self.assertEqual(report([0xb0000001,0x91002021,0xf9000001])['sites'][0]['value']['value'],'0x2008')

    def test_immutable_deterministic_and_unsupported(self):
        original = receipt([0xf9400001,0xd63f0020]); saved=copy.deepcopy(original)
        a = subject.project(original)
        self.assertEqual(original,saved)
        self.assertEqual(json.dumps(a,sort_keys=True),json.dumps(subject.project(original),sort_keys=True))
        self.assertEqual(subject.project(receipt([], 'x86_64'))['data']['callback_evidence']['gaps'],
                         [{'reason':'unsupported_architecture'}])

    def test_malformed_and_budget_fail_before_edges(self):
        for key,value in [('bytes','000000'),('addr','0x1008')]:
            r = receipt([0xf9000001]);r['data']['instructions'][0][key]=value
            e=subject.project(r)['data']['callback_evidence']
            self.assertEqual(e['sites'],[])
            self.assertEqual(e['gaps'][0]['reason'],'invalid_instruction_evidence')
        self.assertEqual(report([0xd503201f]*1025)['gaps'][0]['reason'],'instruction_budget')

    def test_stop_coverage_and_source_identity_are_explicit(self):
        r=report([0xd503201f,0xd65f03c0,0xf9000001])
        self.assertEqual(r['interpreted_end_va'],'0x1008')
        self.assertEqual(r['stop_reason'],'return_boundary')
        r=report([0xd503201f,0x54000000,0xf9000001])
        self.assertEqual(r['interpreted_end_va'],'0x1004')
        self.assertEqual(r['stop_reason'],'unsupported_instruction_boundary')
        self.assertNotEqual(r['source_envelope_sha256'],report([0xd503201f])['source_envelope_sha256'])

    def test_owned_swift64_arm64_oracle_fragments(self):
        # Apple llvm-objdump independently verified these owned Swift -Onone
        # fragments. Stack slots are not closure fields or known contents.
        for start,encoded,target in [(0xc80,'0800009008013591e80700f9','0xd40'),
                                     (0x128c,'0800009008a10991e80700f9','0x1268')]:
            raw=bytes.fromhex(encoded)
            r=receipt([int.from_bytes(raw[i:i+4],'little') for i in range(0,len(raw),4)])
            r['data']['selection'].update(start_va=hex(start),end_va=hex(start+len(raw)))
            for i,row in enumerate(r['data']['instructions']):row['addr']=hex(start+4*i)
            e=subject.project(r)['data']['callback_evidence']
            self.assertEqual(e['sites'][0]['value']['value'],target)
            self.assertEqual(e['sites'][0]['location']['base'],{'kind':'unknown_stack_pointer'})
            self.assertEqual(e['status'],'inconclusive')
        e=report([0xf9400fe0,0xf94007e8,0xd63f0100])
        self.assertEqual(e['sites'][-1]['operand'],{'kind':'memory_read','origin_va':'0x1004'})
        self.assertNotIn('value',e['sites'][-1]['operand'])

    def test_pair_storage_lanes_and_original_load_base(self):
        # STP x1,x2,[x0,#-16]; LDP x0,x1,[x0,#16]; BLR x1
        r=report([0xa93f0801,0xa9410400,0xd63f0020])
        self.assertEqual([s['location']['offset'] for s in r['sites'][:4]],[-16,-8,16,24])
        self.assertEqual(r['sites'][2]['location']['base'],r['sites'][3]['location']['base'])
        self.assertEqual(r['sites'][-1]['operand'],{'kind':'memory_read','origin_va':'0x1004','lane':1})
        for word in (0xa9007c01,0xa9800801,0xa8800801,0x29000801,0xad000801,0xa9400000):
            self.assertEqual(report([word])['sites'],[])

    def test_direct_transfer_is_a_byte_fact_not_followed(self):
        for word,kind in ((0x17ffffff,'direct_branch'),(0x97ffffff,'direct_call')):
            r=report([word,0xf9000001])
            self.assertEqual(len(r['sites']),1)
            self.assertEqual((r['sites'][0]['kind'],r['sites'][0]['target_va']),(kind,'0xffc'))
            self.assertEqual(r['status'],'inconclusive')
            self.assertEqual(r['stop_reason'],'direct_transfer_boundary')

    def test_owned_swift64_optimized_pair_thunk_and_writer_oracle(self):
        def at(start,encoded):
            raw=bytes.fromhex(encoded)
            r=receipt([int.from_bytes(raw[i:i+4],'little') for i in range(0,len(raw),4)])
            r['data']['selection'].update(start_va=hex(start),end_va=hex(start+len(raw)))
            for i,row in enumerate(r['data']['instructions']):row['addr']=hex(start+4*i)
            return subject.project(r)['data']['callback_evidence']
        # llvm-objdump independently verifies STP x8,x20,[x20,#24].
        r=at(0xb00,'0800009008d12c9188d201a9')
        self.assertEqual(len(r['sites']),2)
        self.assertEqual(r['sites'][0]['value']['value'],'0xb34')
        self.assertEqual([s['location']['offset'] for s in r['sites']],[24,32])
        self.assertEqual(r['sites'][1]['value'],{'kind':'unknown','register':'x20'})
        thunk=at(0xb34,'6fffff17')
        self.assertEqual(thunk['sites'][0]['target_va'],'0x8f0')
        # Linker starts: writer0x8f0, next0x92c. Its initial prologue means
        # the later STR at0x918 must not be claimed as reached by our decoder.
        writer=at(0x8f0,'ff0301d1f44f02a9fd7b03a9fdc30091f30300aa80420091e123009122008052030080d220010094930a00f9fd7b43a9f44f42a9ff030191c0035fd6')
        self.assertEqual(writer['sites'],[])
        self.assertEqual(writer['stop_reason'],'unsupported_instruction_boundary')
        self.assertEqual(writer['interpreted_end_va'],'0x8f0')

    def test_parser_option(self):
        p=cli.parser().parse_args(['disasm','--project','owned','--from-import','--range','0x1000:0x1004','--callback-evidence'])
        self.assertTrue(p.callback_evidence)
