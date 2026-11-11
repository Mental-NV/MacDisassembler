"""UTF-16 recorded token positions are not fabricated line-address ownership."""
import copy
import unittest
from macscope import addressed_pseudocode as view, cli


def result(code='  call();\n  return;\n',spans=None):
    spans=spans if spans is not None else [{'text_start':2,'text_end':8,'ranges':[['0x100','0x103']]}]
    return {'command':'decompile','status':'partial','coverage':{},'data':{'entry_va':'0x100','decompile_status':'partial',
           'pseudocode':code,'pseudocode_truncated':False,'address_spans':spans,
           'coverage':{'address_spans':{'status':'partial','emitted':len(spans)}}}}


class AddressedTests(unittest.TestCase):
    def test_recorded_mapping_and_absence_are_distinct(self):
        r=result();before=copy.deepcopy(r);out=view.render(r).decode()
        self.assertIn('1 | 0x100..0x103 |   call();',out)
        self.assertIn('2 | — (no recorded token mapping) |   return;',out)
        self.assertIn('Token mapping coverage: partial',out);self.assertIn('not whole-line',out)
        self.assertEqual(r,before);self.assertEqual(view.render(r),view.render(r))

    def test_utf16_and_leading_newlines_multiline_token(self):
        code='\n😀x\ny\n';spans=[{'text_start':3,'text_end':6,'ranges':[['0x110','0x110']]}]
        out=view.render(result(code,spans)).decode()
        self.assertIn('1 | — (no recorded token mapping) | ',out)
        self.assertIn('2 | 0x110 | 😀x',out);self.assertIn('3 | 0x110 | y',out)
        # Offset 2 splits the supplementary character; no plausible mapping.
        spans[0]['text_start']=2;out=view.render(result(code,spans)).decode()
        self.assertIn('invalid recorded spans',out);self.assertNotIn('| 0x110 |',out)

    def test_invalid_offsets_range_metadata_and_coverage(self):
        variants=[]
        r=result();r['data']['address_spans'][0]['text_end']=999;variants.append(r)
        r=result();r['data']['address_spans'][0]['ranges']=[['0x104','0x100']];variants.append(r)
        r=result();r['data']['coverage']['address_spans']['emitted']=2;variants.append(r)
        r=result();r['data']['address_spans']=None;variants.append(r)
        for r in variants:
            out=view.render(r).decode();self.assertIn('invalid recorded spans',out);self.assertNotIn('| 0x100..0x103 |',out)

    def test_limits_controls_and_omission_accounting(self):
        r=result('\x1b[31m'+('a'*600)+'\n'*1000,[]);out=view.render(r).decode()
        self.assertNotIn('\x1b',out);self.assertIn('\\u{1b}',out)
        self.assertIn('code lines in shown functions: 745',out)
        self.assertIn('Clipped fields: 1',out)
        self.assertLessEqual(len(out.encode()),view.MAX_BYTES);self.assertLessEqual(len(out.splitlines()),view.MAX_LINES)
        rows=[copy.deepcopy(r['data']) for _ in range(20)];r['data']={'functions':rows}
        out=view.render(r).decode();self.assertLessEqual(len(out.splitlines()),view.MAX_LINES);self.assertIn('Omitted functions:',out)

    def test_range_caps_budget_and_unavailable_code(self):
        spans=[{'text_start':0,'text_end':1,'ranges':[[hex(n),hex(n)] for n in range(10)]}]
        out=view.render(result('x',spans)).decode();self.assertIn('(+2 ranges omitted)',out);self.assertIn('ranges on shown lines: 2',out)
        r=result('x'*(view.MAX_TEXT+1),[]);self.assertIn('mapping budget exceeded',view.render(r).decode())
        self.assertIn('Pseudocode unavailable',view.render(result('',[])).decode())
        self.assertIn('unavailable for this result',view.render({'status':'complete','data':{'job_id':'owned'}}).decode())

    def test_parser_and_format_are_opt_in(self):
        for argv in (['decompile','--project','p','--address','0x100'],['jobs','resume','job','--project','p']):
            self.assertEqual(cli.parser().parse_args(argv+['--format','addressed']).format,'addressed')
        r=result();self.assertEqual(cli.render(r,'addressed'),view.render(r))
        self.assertNotIn(b'Address-linked pseudocode',cli.render(cli.envelope('decompile',r['data']),'text'))

    def test_mapping_can_refer_to_token_after_visible_snippet(self):
        r=result(' '*300+'call()', [{'text_start':300,'text_end':306,'ranges':[['0x200','0x200']]}])
        out=view.render(r).decode()
        self.assertIn('1 | 0x200 | ',out);self.assertNotIn('call()',out)
        self.assertIn('ranges (entire line)',out);self.assertIn('pseudocode (may be clipped)',out)
        self.assertIn('Clipped fields: 1',out)
