"""Owned compiler words and independent A64 encoding/semantic negatives."""
import copy
import unittest
from macscope import callback_evidence
from test_callback_evidence import receipt
from test_callback_provenance import encoded, project


def add(rd=0,rn=1,rm=2,width=64,shift=0,amount=0):
    return 0x0b000000|((width==64)<<31)|(shift<<22)|(rm<<16)|(amount<<10)|(rn<<5)|rd


def movz(reg,value,width=64,shift=0):
    return 0x52800000|((width==64)<<31)|((shift//16)<<21)|(value<<5)|reg


class RegisterAddTests(unittest.TestCase):
    def test_owned_native_swift_entry_prefixes(self):
        for start,code,width,shift,amount in [
            (0x398,'2000008bc0035fd6',64,'lsl',0),
            (0x3a0,'000c018bc0035fd6',64,'lsl',3),
            (0x3a8,'000c418bc0035fd6',64,'lsr',3),
            (0x3b0,'000c818bc0035fd6',64,'asr',3),
            (0x3b8,'2000000bc0035fd6',32,'lsl',0),
            (0x3c0,'000c010bc0035fd6',32,'lsl',3),
            (0x390,'000c410bc0035fd6',32,'lsr',3),
            (0x398,'000c810bc0035fd6',32,'asr',3)]:
            with self.subTest(start=start):
                r=project(encoded(code),start=start,abi=None)
                self.assertEqual(r['stop_reason'],'unsupported_instruction_boundary')
                original=receipt(encoded(code))
                original['data']['selection'].update(start_va=hex(start),end_va=hex(start+8))
                for i,row in enumerate(original['data']['instructions']):row['addr']=hex(start+4*i)
                r=callback_evidence.project(original,provenance=True)['data']['callback_evidence']
                site,=r['sites']
                self.assertEqual((site['width'],site['shift'],site['shift_amount']),(width,shift,amount))
                self.assertEqual(site['result']['kind'],'register_add_result')
                self.assertEqual(r['stop_reason'],'return_boundary')
                self.assertEqual(r['status'],'inconclusive')
        for code in ('0040218bc0035fd6','000001ab42000054c0035fd6200020d4'):
            r=project(encoded(code))
            self.assertEqual(r['sites'],[])
            self.assertEqual(r['stop_reason'],'unsupported_instruction_boundary')

    def test_numeric_shift_semantics(self):
        for width in (32,64):
            for shift in range(3):
                for amount in (0,1,width-1):
                    value=0x8001 << (width-16)
                    mask=(1<<width)-1
                    rhs=value if shift!=2 else value-(1<<width)
                    shifted=(rhs << amount if shift==0 else rhs >> amount)&mask
                    r=project([movz(1,7),movz(2,0x8001,shift=width-16),add(width=width,shift=shift,amount=amount)])
                    self.assertEqual(int(r['sites'][-1]['result']['value'],16),(7+shifted)&mask)

    def test_width_zero_extension_and_overlap(self):
        r=project([movz(0,0xffff,shift=48),movz(1,2),add(rd=0,rn=0,rm=1,width=32),0xf90003e0])
        self.assertEqual(r['sites'][-1]['value']['value'],'0x2')
        self.assertEqual(r['sites'][-2]['left']['value'],'0xffff000000000000')

    def test_zr_is_never_sp(self):
        r=project([add(rd=31,rn=31,rm=31),add(rd=0,rn=31,rm=31),0xf90003e0])
        self.assertTrue(r['sites'][0]['discarded_write'])
        self.assertEqual(r['sites'][0]['result']['value'],'0x0')
        self.assertEqual(r['sites'][-1]['location']['base']['offset'],0)
        self.assertEqual(r['sites'][-1]['value']['value'],'0x0')

    def test_wrapping_and_address_provenance(self):
        r=project([0x10000001,movz(2,1),add(rd=0,rn=1,rm=2),0xf90003e0])
        self.assertEqual(r['sites'][-1]['value']['kind'],'address')
        self.assertEqual(r['sites'][-1]['value']['value'],'0x1001')
        r=project([movz(1,0x8000,shift=48),movz(2,0x8000,shift=48),add(),0xf90003e0])
        self.assertEqual(r['sites'][-1]['value']['value'],'0x0')
        r=project([0x10000001,add(rn=31,rm=1),0xf90003e0])
        self.assertEqual(r['sites'][-1]['value']['kind'],'integer_constant')

    def test_w_address_truncation_and_unknown_overwrite(self):
        r=project([0x10000001,add(rd=0,rn=1,rm=31,width=32),0xf90003e0])
        self.assertEqual(r['sites'][-1]['value']['kind'],'integer_constant')
        r=project([0x10000000,add(rd=0,rn=0,rm=1),0xf90003e0])
        self.assertEqual(r['sites'][-1]['value']['kind'],'register_add_result')

    def test_invalid_forms_keep_barriers(self):
        words=[add(shift=3),add(width=32,amount=32),add(width=32,amount=63),
               add()|(1<<21),add()|(1<<29),add()|(1<<30)]
        for word in words:
            r=project([word,0xf90003e0])
            self.assertEqual(r['sites'],[])
            self.assertEqual(r['interpreted_end_va'],'0x1000')
            self.assertEqual(r['stop_reason'],'unsupported_instruction_boundary')

    def test_unknown_chain_is_bounded_and_not_alias(self):
        source=receipt([add(rd=0,rn=0,rm=1)]*1024);before=copy.deepcopy(source)
        a=callback_evidence.project(source,provenance=True)
        self.assertEqual(a,callback_evidence.project(source,provenance=True))
        self.assertEqual(source,before)
        sites=a['data']['callback_evidence']['sites']
        self.assertEqual(len(sites),1024)
        self.assertEqual(sites[-1]['left']['kind'],'register_add_result')
        self.assertNotIn('left',sites[-1]['left'])
        r=project([0x94000008,add(),0xf90003e0])
        self.assertEqual(r['sites'][1]['left']['kind'],'call_clobbered')
        self.assertEqual(r['sites'][-1]['value']['kind'],'register_add_result')
        self.assertEqual(r['sites'][1]['conditional_on_calls'],['0x1000'])
