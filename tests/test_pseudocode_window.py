import copy
import unittest
from unittest.mock import patch
from macscope import cli, pseudocode_window as window
from macscope.errors import Error


def fixture():
    lines=[f'context_{i};' for i in range(1,81)]
    lines[55]='😀 owned_increment = input + 1;'
    code='\n'.join(lines)
    start=len('\n'.join(lines[:55]).encode('utf-16-le'))//2+1+3
    span=dict(text_start=start,text_end=start+15,ranges=[['0x1000','0x1003']])
    return dict(status='partial',data=dict(entry_va='0x900',function_id='a'*64,
        origin={'mode':'focused_readonly_import','job_id':'owned'},pseudocode=code,
        decompile_status='complete',pseudocode_truncated=False,address_spans=[span],
        coverage={'address_spans':{'status':'partial','emitted':1}}))


class WindowTests(unittest.TestCase):
    def test_beyond_preview_and_non_bmp_exact_offsets(self):
        row=fixture();before=copy.deepcopy(row)
        output=window.render(row,address='0x1001')
        self.assertIn(b'Recorded token text (possibly clipped): owned_increment',output)
        self.assertIn(b'56 | ',output);self.assertIn(b'owned_increment = input + 1;',output)
        self.assertIn(b'token presentation lines 56..56',output)
        self.assertIn(b'coverage: partial',output);self.assertIn(b'job: owned',output)
        self.assertIn(b'Omitted code lines: 40',output)
        self.assertEqual(row,before)
        self.assertEqual(output,window.render(row,token_start=row['data']['address_spans'][0]['text_start']))

    def test_repeated_address_ambiguous_no_first_match(self):
        row=fixture();data=row['data'];start=data['address_spans'][0]['text_start']
        data['address_spans'].append(dict(text_start=start+16,text_end=start+17,ranges=[['0x1000','0x1003']]))
        data['coverage']['address_spans']['emitted']=2
        text=window.render(row,address='0x1001')
        self.assertIn(b'ambiguous: 2',text);self.assertNotIn(b'56 |',text)
        self.assertIn(b'56 |',window.render(row,token_start=start+16))

    def test_invalid_tail_surrogate_boundary_empty_missing_and_unmatched(self):
        row=fixture();start=row['data']['address_spans'][0]['text_start']
        row['data']['address_spans'][0]['text_start']=start-2 # second surrogate unit
        self.assertIn(b'invalid recorded mapping',window.render(row,address='0x1000'))
        for code,spans in [('',[]),('hello',[]),('hello',[dict(text_start=0,text_end=99,ranges=[['0x1','0x2']])])]:
            row=fixture();row['data'].update(pseudocode=code,address_spans=spans)
            self.assertIn(b'unavailable',window.render(row,address='0x1000'))
        self.assertIn(b'no exact',window.render(fixture(),token_start=1))
        row=fixture();row['data']['address_spans'].append({'text_start':99999,'text_end':100000,'ranges':[['0x2','0x1']]})
        row['data']['coverage']['address_spans']['emitted']=2
        self.assertIn(b'invalid recorded mapping',window.render(row,address='0x1001'))

    def test_multiline_newline_and_end_context(self):
        row=fixture();data=row['data'];data['pseudocode']='a\nb\nc\n'
        data['address_spans']=[dict(text_start=1,text_end=5,ranges=[['0x1','0x1']])]
        text=window.render(row,token_start=1)
        self.assertIn(b'token presentation lines 1..3',text)
        self.assertIn(b'anchor lines omitted: 0',text)
        self.assertIn(b'   4 | ',text)

    def test_limits_escape_clipping_and_no_raw_changes(self):
        row=fixture();data=row['data'];data['pseudocode']=('\x1b'*1000+'\n')*80
        data['address_spans']=[dict(text_start=55055,text_end=55056,ranges=[['0x1','0x1']])]
        before=copy.deepcopy(row);text=window.render(row,address='0x1')
        self.assertLessEqual(len(text),16384);self.assertLessEqual(sum(b' | ' in l for l in text.splitlines()),40)
        self.assertNotIn(b'\x1b',text);self.assertIn(b'[clipped]',text)
        self.assertIn(b'anchor lines omitted:',text);self.assertEqual(row,before)
        with patch.object(window,'MAX_TEXT',10):self.assertIn(b'oversized',window.render(row,address='0x1'))
        data['pseudocode']='a';data['address_spans']=[dict(text_start=0,text_end=1,ranges=[['0x1','0x1']]*8193)]
        self.assertIn(b'budget exceeded',window.render(row,address='0x1'))

    def test_query_coverage_and_batch_refusal(self):
        row=fixture();data=row['data'];data.pop('coverage')
        data['address_span_coverage']={'available':True,'status':'partial','text_offsets':'utf16'}
        self.assertIn(b'56 |',window.render(row,address='0x1000'))
        data['address_span_coverage']['available']=False
        self.assertIn(b'unavailable',window.render(row,address='0x1000'))
        self.assertIn(b'exactly one function',window.render({'data':{'functions':[{},{}]}},address='0x1'))

    def test_parser_and_early_usage_errors(self):
        for command in (['decompile','--project','/absent','--address','0x1'],['jobs','resume','owned','--project','/absent']):
            for flags in (['--format','window'],['--window-address','0x1'],['--format','window','--window-token-start','-1'],['--format','window','--window-address','bad']):
                args=cli.parser().parse_args(command+flags)
                with patch.object(cli,'execute_command',side_effect=AssertionError('no action')):
                    with self.assertRaises(Error) as caught:cli.execute(args)
                    self.assertEqual(caught.exception.code,'window_anchor')

    def test_batch_rejected_before_work(self):
        args=cli.parser().parse_args(['decompile','--project','/absent','--all','--format','window','--window-address','0x1'])
        with patch.object(cli,'execute_command',side_effect=AssertionError('no batch work')):
            with self.assertRaises(Error) as caught:cli.execute(args)
            self.assertEqual(caught.exception.code,'window_anchor')
