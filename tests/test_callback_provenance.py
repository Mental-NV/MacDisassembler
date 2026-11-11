"""ABI is an explicit hypothesis, never byte-proven callee behavior."""
import copy
import unittest
from macscope import callback_evidence, cli
from test_callback_evidence import receipt


def project(words, start=0x1000, abi='aapcs64'):
    r=receipt(words)
    r['data']['selection'].update(start_va=hex(start),end_va=hex(start+4*len(words)))
    for i,row in enumerate(r['data']['instructions']):row['addr']=hex(start+4*i)
    return callback_evidence.project(r,abi=abi)['data']['callback_evidence']


def encoded(text):
    raw=bytes.fromhex(text)
    return [int.from_bytes(raw[i:i+4],'little') for i in range(0,len(raw),4)]


class ProvenanceTests(unittest.TestCase):
    def test_owned_setter_provenance_is_abi_conditional(self):
        words=encoded('ff0301d1f44f02a9fd7b03a9fdc30091f30300aa80420091e123009122008052030080d220010094930a00f9fd7b43a9f44f42a9ff030191c0035fd6')
        r=project(words,start=0x8f0)
        store=next(s for s in r['sites'] if s['instruction_va']=='0x918')
        self.assertEqual(store['value']['register'],'x0')
        self.assertEqual(store['value']['kind'],'range_input_register')
        self.assertEqual(store['location']['base']['register'],'x20')
        self.assertEqual(store['location']['offset'],16)
        self.assertEqual(store['conditional_on_calls'],['0x914'])
        self.assertEqual(r['provenance_mode'],'aapcs64_conditional')
        self.assertEqual(r['status'],'inconclusive')
        self.assertEqual(r['stop_reason'],'return_boundary')
        self.assertIn('eventual_state_writer',r['missing_evidence'])
        self.assertEqual(project(words,start=0x8f0,abi=None)['sites'],[])

    def test_caller_saved_values_and_memory_not_preserved(self):
        # MOV x19,x0; BL; STR x0,[x20]; STR x19,[x20,#8]; LDR x1,[x20,#8]
        r=project([0xaa0003f3,0x94000008,0xf9000280,0xf9000693,0xf9400681])
        stores=[s for s in r['sites'] if s['kind']=='memory_store']
        self.assertEqual(stores[0]['value']['kind'],'call_clobbered')
        self.assertEqual(stores[1]['value']['register'],'x0')
        self.assertEqual(r['sites'][-1]['kind'],'memory_load')
        self.assertEqual(r['sites'][-1]['location']['base']['register'],'x20')
        # Same-looking store then load never forwards contents.
        called=project([0xf9000680,0xf9400681,0xd63f0020])['sites'][-1]
        self.assertEqual(called['operand']['kind'],'memory_read')

    def test_movz_zero_extends_overwritten_register_and_reserved_form_stops(self):
        r=project([0x10000001,0x52800021,0xf9000001])
        self.assertEqual(r['sites'][0]['value']['kind'],'integer_constant')
        self.assertEqual(r['sites'][0]['value']['value'],'0x1')
        self.assertEqual(project([0x52c00021,0xf9000001])['sites'],[])

    def test_frame_delta_and_stack_bounds(self):
        r=project([0xd10103ff,0x910083fd,0xf90003e0])  # SUB SP64; ADD FP32; STR
        store=r['sites'][-1]
        self.assertEqual(store['location']['base']['offset'],-64)
        self.assertEqual(store['location']['base']['kind'],'stack_pointer_relative')
        self.assertEqual(project([0xd14007ff,0xd10007ff])['stop_reason'],'stack_delta_budget')
        self.assertEqual(project([0x9100001f])['stop_reason'],'unknown_stack_assignment')

    def test_input_scope_and_call_budget(self):
        a=project([0xf9000001]);b=project([0xf9000001],start=0x2000)
        self.assertNotEqual(a['sites'][0]['value'],b['sites'][0]['value'])
        r=project([0x94000000]*33+[0xf9000001])
        self.assertEqual(r['stop_reason'],'call_condition_budget')
        self.assertFalse(any(s['kind']=='memory_store' for s in r['sites']))

    def test_unsupported_branch_and_indirect_call_still_stop(self):
        for word in (0x54000000,0xb4000000,0xab000000,0xdac10000):
            r=project([word,0xf9000001])
            self.assertEqual(r['sites'],[])
        self.assertEqual(len(project([0xd63f0020,0xf9000001])['sites']),1)

    def test_original_response_immutable(self):
        r=receipt([0xd10043ff,0x94000001,0xf9000001]);before=copy.deepcopy(r)
        a=callback_evidence.project(r,abi='aapcs64')
        self.assertEqual(r,before)
        self.assertEqual(a,callback_evidence.project(r,abi='aapcs64'))
        with self.assertRaises(ValueError):callback_evidence.project(r,abi='invented')

    def test_register_only_mode_does_not_acquire_call_preservation(self):
        r=callback_evidence.project(receipt([0xaa0003f3,0x94000008,0xf9000293]),provenance=True)['data']['callback_evidence']
        self.assertEqual(r['provenance_mode'],'register_inputs')
        self.assertEqual(r['assumptions'],[])
        self.assertEqual(len(r['sites']),1)
        self.assertEqual(r['stop_reason'],'direct_transfer_boundary')

    def test_parser_opt_in(self):
        args=cli.parser().parse_args(['disasm','--project','owned','--from-import','--range','0x1000:0x1004','--callback-abi','aapcs64'])
        self.assertEqual(args.callback_abi,'aapcs64')
