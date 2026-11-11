"""Owned presentation fixtures; no private application text or addresses."""
import copy
import unittest
from macscope import pseudocode_window as window


def fixture(tokens):
    code='';spans=[]
    for token in tokens:
        start=len(code.encode('utf-16-le'))//2
        code+=token
        spans.append(dict(text_start=start,text_end=len(code.encode('utf-16-le'))//2,
                          ranges=[['0x1000','0x1000']]))
        code+=' '
    return {'status':'partial','data':{'pseudocode':code,'address_spans':spans,
            'coverage':{'address_spans':{'status':'partial','emitted':len(spans)}}}}


class CandidateTests(unittest.TestCase):
    def test_exact_tokens_non_bmp_and_explicit_selection(self):
        row=fixture(['😀','owned_call','(',')']);before=copy.deepcopy(row)
        out=window.render(row,address='0x1000')
        self.assertIn('Candidate UTF-16 [0, 2): 😀'.encode(),out)
        self.assertIn(b'Candidate UTF-16 [3, 13): owned_call',out)
        self.assertIn(b'Window ambiguous: 4',out)
        self.assertNotIn(b'Anchor UTF-16',out)
        self.assertEqual(row,before);self.assertEqual(out,window.render(row,address='0x1000'))
        selected=window.render(row,token_start=3)
        self.assertIn(b'Recorded token text (possibly clipped): owned_call',selected)
        self.assertNotIn(b'Candidate UTF-16',selected)

    def test_cap_escaping_clipping_and_byte_budget(self):
        row=fixture(['\x1b\n\r\t'+('\U000e0001'*100)]*10)
        out=window.render(row,address='0x1000')
        candidates=[line for line in out.splitlines() if line.startswith(b'Candidate UTF-16')]
        self.assertEqual(len(candidates),8)
        self.assertTrue(all(b'[clipped]' in line for line in candidates))
        self.assertIn(b'token starts omitted: 2',out)
        self.assertNotIn(b'\x1b',out);self.assertNotIn(b'\r',out);self.assertNotIn(b'\t',out)
        self.assertIn(b'\\n\\r\\t',out);self.assertLessEqual(len(out),window.MAX_BYTES)

    def test_full_validation_before_any_preview(self):
        row=fixture(['😀','name'])
        row['data']['address_spans'][1]['text_end']=1000
        out=window.render(row,address='0x1000')
        self.assertIn(b'invalid recorded mapping',out);self.assertNotIn(b'Candidate UTF-16',out)
        row=fixture(['😀','name']);row['data']['address_spans'][0]['text_end']=1
        self.assertIn(b'invalid recorded mapping',window.render(row,address='0x1000'))
        row=fixture(['a','b']);row['data']['address_spans'][1]=copy.deepcopy(row['data']['address_spans'][0])
        self.assertIn(b'invalid recorded mapping',window.render(row,token_start=0))

    def test_combined_adversarial_metadata_and_tokens_fit(self):
        row=fixture(['\U0010ffff'*81]*8);data=row['data'];bad='\U0010ffff'*161
        row['status']=bad
        for name in ('entry_va','function_id','decompile_status','pseudocode_truncated'):
            data[name]=bad
        data['origin']={'mode':bad,'job_id':bad}
        before=copy.deepcopy(row);out=window.render(row,address='0x1000')
        shown=sum(line.startswith(b'Candidate UTF-16') for line in out.splitlines())
        self.assertGreater(shown,0);self.assertLess(shown,8)
        self.assertIn(f'previews omitted: {8-shown}'.encode(),out)
        self.assertIn(b'token starts omitted: 0',out)
        self.assertLessEqual(len(out),window.MAX_BYTES);self.assertEqual(row,before)
