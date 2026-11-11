"""Owned final-thunk proof; old policy and malformed mapping regressions."""
import copy
import struct
import unittest
from unittest.mock import patch
from macscope import focused,flow_gap_evidence
from macscope.errors import Error
from test_macho import command,image as macho_image


def fixture(word=0x17fffffc,section_size=0x14,stream=bytes.fromhex('80041000')):
    section=struct.pack('<16s16s2Q8I',b'__text',b'__TEXT',0x1200,section_size,0x200,2,0,0,0x80000400,0,0,0)
    segment=struct.pack('<16s4Q4I',b'__TEXT',0x1000,0x300,0,0x300,7,5,1,0)
    raw=bytearray(macho_image(commands=[command(0x19,segment+section),command(0x26,struct.pack('<II',0x280,len(stream)))]))
    raw.extend(bytes(0x300-len(raw)))
    raw[0x200:0x204]=bytes.fromhex('c0035fd6')
    raw[0x210:0x214]=word.to_bytes(4,'little');raw[0x280:0x280+len(stream)]=stream
    return bytes(raw)


class TerminalLinkerTests(unittest.TestCase):
    image={'arch':'arm64','offset':'0x0'}
    def extent(self,data=None,policy=focused.POLICY):
        return focused.extent(data or fixture(),self.image,'0x1210',policy=policy)

    def test_exact_last_thunk_new_policy_only(self):
        p,raw=self.extent();self.assertEqual(raw.hex(),'fcffff17')
        self.assertEqual(p['policy'],'macscope-focused-import/4')
        self.assertEqual(p['end_va_exclusive'],'0x1214');self.assertEqual(p['length'],4)
        self.assertEqual(p['boundary']['target_extent']['entry_va'],'0x1200')
        self.assertEqual(p['boundary']['target_extent']['policy'],'macscope-focused-import/1')
        self.assertIn('tail_calls',p);self.assertIn('flow_gap_classification',p)
        for policy in ('macscope-focused-import/1','macscope-focused-import/2','macscope-focused-import/3'):
            with self.assertRaises(Error) as e:self.extent(policy=policy)
            self.assertEqual(e.exception.code,'focused_boundary_missing')

    def test_old_nonterminal_policy_proofs_remain_unchanged(self):
        raw=fixture()
        proofs={n:focused.extent(raw,self.image,'0x1200',policy=f'macscope-focused-import/{n}')[0] for n in (1,2,3,4)}
        self.assertNotIn('tail_calls',proofs[1]);self.assertIn('tail_calls',proofs[2])
        self.assertNotIn('flow_gap_classification',proofs[2]);self.assertIn('flow_gap_classification',proofs[3])
        old=copy.deepcopy(proofs[3]);old['policy']='macscope-focused-import/4'
        self.assertEqual(old,proofs[4]);self.assertNotIn('boundary',proofs[4])

    def test_nonbranch_longer_or_padded_last_entry_fails(self):
        for word in (0xd65f03c0,0x97fffffc,0x54ffff80,0xd61f0000,0x14000000,0x17fffffd):
            with self.subTest(word=word),self.assertRaises(Error):self.extent(fixture(word=word))
        with self.assertRaises(Error):self.extent(fixture(section_size=0x18))
        with self.assertRaises(Error):self.extent(fixture(stream=bytes.fromhex('80040c00')))

    def test_incomplete_ambiguous_linker_streams_fail(self):
        for stream in (bytes.fromhex('800410'),bytes.fromhex('8004100001'),b''):
            with self.assertRaises(Error):self.extent(fixture(stream=stream))
        parsed=focused.thin(fixture(),include_section_linkage=True)
        parsed['loader']['linkedit'].append(copy.deepcopy(parsed['loader']['linkedit'][0]))
        with patch.object(focused,'thin',return_value=parsed),self.assertRaises(Error):self.extent()

    def test_mapping_encryption_and_data_uncertainty_fail(self):
        original=focused.thin(fixture(),include_section_linkage=True)
        variants=[]
        p=copy.deepcopy(original);p['sections'].append(copy.deepcopy(p['sections'][0]));variants.append(p)
        p=copy.deepcopy(original);p['segments'].append(copy.deepcopy(p['segments'][0]));variants.append(p)
        p=copy.deepcopy(original);p['segments'][0]['file_offset']='0x4';variants.append(p)
        p=copy.deepcopy(original);p['sections'][0]['protections']=1;variants.append(p)
        p=copy.deepcopy(original);p['sections'][0]['file_offset']='0x1ff';variants.append(p)
        p=copy.deepcopy(original);p['loader']['data_in_code']={'status':'partial','records':[]};variants.append(p)
        p=copy.deepcopy(original);p['loader']['data_in_code']={'status':'complete','records':[{'slice_file_offset':'0x210','length':4}]};variants.append(p)
        p=copy.deepcopy(original);p['loader']['encryption']={'cryptid':1,'slice_file_offset':'0x210','size':'0x4'};variants.append(p)
        p=copy.deepcopy(original);p['arch']='x86_64';variants.append(p)
        for p in variants:
            with self.subTest(parsed=p),patch.object(focused,'thin',return_value=p),self.assertRaises(Error):self.extent()

    def test_target_extent_checks_remain_strict(self):
        # Source itself is clean, but branch target is marked embedded data.
        p=focused.thin(fixture(),include_section_linkage=True)
        p['loader']['data_in_code']={'status':'complete','records':[{'slice_file_offset':'0x200','length':4}]}
        with patch.object(focused,'thin',return_value=p),self.assertRaises(Error) as e:self.extent()
        self.assertEqual(e.exception.code,'focused_terminal_target')
