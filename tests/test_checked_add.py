"""Owned adjacent guard semantics, independent words and conservative negatives."""
import copy
import unittest
from macscope import callback_evidence as c, cli
from test_callback_evidence import receipt
from test_callback_provenance import encoded
from test_core import TemporaryCase


def adds(rd=19,rn=0,imm=1,shift=False):
    return 0xb1000000 | (int(shift)<<22) | (imm<<10) | (rn<<5) | rd


def branch(cond=6,delta=16):
    return 0x54000000 | (((delta//4)&0x7ffff)<<5) | cond


def project(words,**kw):
    return c.project(receipt(words),abi='aapcs64',checked_add=True,**kw)['data']['callback_evidence']



class CheckedAddTests(unittest.TestCase):
    def test_owned_native_writer_prefix(self):
        words=encoded('ff0301d1f44f02a9fd7b03a9fdc30091130400b16601005480420091e123009122008052030080d2b7000094930a00f9fd7b43a9f44f42a9ff030191c0035fd6200020d4')
        r=receipt(words);r['data']['selection'].update(start_va='0xa90',end_va='0xad4')
        for i,row in enumerate(r['data']['instructions']):row['addr']=hex(0xa90+i*4)
        before=copy.deepcopy(r);p=c.project(r,abi='aapcs64',checked_add=True)['data']['callback_evidence']
        self.assertEqual(r,before);self.assertEqual(p['stop_reason'],'return_boundary')
        guard,=p['path_obligations'];self.assertEqual(guard['target_va'],'0xad0')
        self.assertEqual(guard['fallthrough_predicate'],'no_signed_overflow')
        self.assertEqual(guard['predicate_status'],'unverified')
        store=next(s for s in p['sites'] if s['instruction_va']=='0xabc')
        self.assertEqual(store['value']['kind'],'checked_add_result')
        self.assertEqual(store['conditional_on_branches'],['0xaa4'])
        self.assertEqual(store['conditional_on_calls'],['0xab8'])
        self.assertEqual(p['status'],'inconclusive')
        old=c.project(r,abi='aapcs64')['data']['callback_evidence']
        self.assertEqual(old['interpreted_end_va'],'0xaa0')
        self.assertFalse(any(s['instruction_va']=='0xabc' for s in old['sites']))

    def test_concrete_signed_boundaries_and_conditions(self):
        # MOVZ x0,0x7fff,LSL48; MOVZ x1,0xffff,LSL32; ADD;
        # MOVZ x1,0xffff,LSL16; ADD; MOVZ x1,0xffff; ADD -> INT64_MAX.
        maxwords=[0xd2efffe0,0xd2dfffe1,0x8b010000,0xd2bfffe1,0x8b010000,0xd29fffe1,0x8b010000]
        for prefix,imm,overflow,expected in ((maxwords,1,True,'0x8000000000000000'),
            (maxwords,0,False,'0x7fffffffffffffff'),([0xd2f00000],1,False,'0x8000000000000001'),
            ([0xd2800000],1,False,'0x1')):
            for cond in (6,7):
                p=project(prefix+[adds(),branch(cond),0xf9000293]) if imm else project(prefix+[adds(imm=0),branch(cond),0xf9000293])
                arithmetic=next(s for s in p['sites'] if s['kind']=='checked_add')
                self.assertEqual(arithmetic['result']['value'],expected)
                self.assertEqual(arithmetic['overflow_flag']['value'],overflow)
                allowed=overflow==(cond==7)
                self.assertEqual(any(s['kind']=='memory_store' for s in p['sites']),allowed)
                self.assertEqual(p['stop_reason'],'selected_prefix_end' if allowed else 'impossible_fallthrough_predicate')

    def test_shift_overlap_discard_and_unknown(self):
        p=project([0xd2800020,adds(rd=0,imm=2,shift=True),branch(),0xf9000280])
        self.assertEqual(p['sites'][0]['result']['value'],'0x2001')
        p=project([adds(rd=31),branch(7),0xf9000293])
        self.assertTrue(p['sites'][0]['discarded_write'])
        self.assertEqual(p['path_obligations'][0]['fallthrough_predicate'],'signed_overflow')
        self.assertEqual(p['path_obligations'][0]['predicate_status'],'unverified')
        self.assertEqual(p['sites'][-1]['value']['kind'],'range_input_register')

    def test_unsupported_near_misses_and_missing_adjacency(self):
        for words in ([adds()], [adds(),0xd503201f,branch()], [adds(),branch(0)],
                      [adds(),branch()|16],[adds(rn=31),branch()],
                      [adds()&~(1<<31),branch()],[adds()|(1<<23),branch()],
                      [0xab000013,branch()]):
            p=project(words);self.assertEqual(p['stop_reason'],'unsupported_instruction_boundary')
            self.assertEqual(p['sites'],[])
        for d in (-4,0):
            p=project([adds(),branch(delta=d),0xf9000293])
            self.assertEqual(p['stop_reason'],'conditional_backedge_or_cycle')
            self.assertFalse(any(s['kind']=='memory_store' for s in p['sites']))

    def test_symbolic_zero_and_zero_extended_operands_cannot_overflow(self):
        for rd in (0,31):
            for shift in (False,True):
                for cond in (6,7):
                    p=project([adds(rd=rd,imm=0,shift=shift),branch(cond),0xf9000280])
                    self.assertEqual(p['sites'][0]['overflow_flag']['value'],False)
                    self.assertEqual(p['stop_reason'],'selected_prefix_end' if cond==6 else 'impossible_fallthrough_predicate')
        for cond in (6,7):
            p=project([0x0b010000,adds(rd=0,imm=4095,shift=True),branch(cond),0xf9000280])
            guard=next(s for s in p['sites'] if s['kind']=='conditional_branch')
            self.assertEqual(guard['tested_value']['value'],False)
            self.assertEqual(p['stop_reason'],'selected_prefix_end' if cond==6 else 'impossible_fallthrough_predicate')

    def test_same_scoped_operand_overflow_contradictions(self):
        p=project([adds(rd=19),branch(6,24),adds(rd=20),branch(7,16),0xf9000293])
        self.assertEqual(p['stop_reason'],'contradictory_fallthrough_predicates')
        self.assertEqual(p['sites'][-1]['contradictory_with'],['0x1004'])
        self.assertFalse(any(s['kind']=='memory_store' for s in p['sites']))
        # Rewritten left input, different immediate, and fresh load stay distinct.
        for words in ([adds(rd=0),branch(6,24),adds(rd=20),branch(7,16)],
                      [adds(rd=19),branch(6,24),adds(rd=20,imm=2),branch(7,16)],
                      [0xf9400280,adds(rd=19),branch(6,32),0xf9400280,adds(rd=20),branch(7,16)]):
            p=project(words+[0xf9000293])
            self.assertEqual(p['stop_reason'],'selected_prefix_end')
            self.assertEqual(len(p['path_obligations']),2)

    def test_budget_and_strict_defaults(self):
        p=project([v for i in range(17) for v in (adds(),branch())]+[0xf9000293])
        self.assertEqual(len(p['path_obligations']),16)
        self.assertEqual(p['stop_reason'],'branch_condition_budget')
        old=c.project(receipt([adds(),branch()]),provenance=True)['data']['callback_evidence']
        self.assertEqual(old['sites'],[])
        with self.assertRaises(ValueError):c.project(receipt([adds(),branch()]),checked_add=True)


class GuardCLITests(TemporaryCase):
    def test_guard_scope_rejected_before_project_access(self):
        base=['disasm','--project','not-present','--from-import','--range','0x1000:0x1010','--callback-checked-add-fallthrough']
        for extra in ([],['--callback-evidence'],['--callback-evidence','--callback-provenance','--callback-target-receipt','a'*32]):
            self.error('callback_scope',cli.execute,cli.parser().parse_args(base+extra))
