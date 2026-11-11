"""Owned navigation fixtures, not semantic proof."""
import copy
import unittest
from unittest.mock import patch
from macscope import cli, token_preview
import test_method_dossier as dossiers


def source(text='😀return;', spans=None, status='complete'):
    spans=spans if spans is not None else [dict(text_start=2,text_end=9,ranges=[['0x1000','0x1003']])]
    return dict(pseudocode=text,address_spans=spans,coverage=dict(address_spans=dict(status=status,emitted=len(spans))))


class TokenTests(unittest.TestCase):
    def test_non_bmp_and_partial(self):
        original=source(status='partial');before=copy.deepcopy(original)
        result=token_preview.preview(original)
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['records'][0]['token'],'return;')
        self.assertEqual(result['records'][0]['ranges'],[['0x1000','0x1003']])
        self.assertEqual(original,before)
        self.assertEqual(result,token_preview.preview(original))
        emoji=source(spans=[dict(text_start=0,text_end=2,ranges=[['0x1000','0x1000']])])
        self.assertEqual(token_preview.preview(emoji)['records'][0]['token'],'😀')

    def test_invalid_offsets_ranges_and_tail(self):
        for change in (dict(text_start=1),dict(text_end=99),dict(text_start=True),dict(ranges=[['0x2000','0x1000']]),dict(ranges=[['oops','0x1000']])):
            data=source();data['address_spans'][0].update(change)
            self.assertEqual(token_preview.preview(data)['status'],'unavailable')
        data=source('abcdef',[dict(text_start=i,text_end=i+1,ranges=[['0x1000','0x1000']]) for i in range(6)])
        reordered=copy.deepcopy(data);reordered['address_spans'].reverse()
        self.assertEqual(token_preview.preview(reordered)['reason'],'invalid_recorded_spans')
        data['address_spans'][-1]['text_end']=999
        self.assertEqual(token_preview.preview(data)['reason'],'invalid_recorded_spans')

    def test_query_coverage_and_no_silent_fallback(self):
        data=source();data['address_span_coverage']=dict(available=True,status='complete',text_offsets='utf16');data.pop('coverage')
        self.assertEqual(token_preview.preview(data)['records'][0]['token'],'return;')
        for change in (dict(available=False),dict(text_offsets='bytes'),dict(status='unknown')):
            bad=copy.deepcopy(data);bad['address_span_coverage'].update(change)
            self.assertEqual(token_preview.preview(bad)['status'],'unavailable')
        data=source();data['coverage']['address_spans']['emitted']=99
        self.assertEqual(token_preview.preview(data)['status'],'unavailable')

    def test_caps_clipping_omissions(self):
        data=source('abcdef',[dict(text_start=i,text_end=i+1,ranges=[['0x1000','0x1000']]*3) for i in range(6)])
        result=token_preview.preview(data)
        self.assertEqual((len(result['records']),result['omitted_spans']),(4,2))
        self.assertEqual(result['records'][0]['omitted_ranges'],1)
        for name,value,reason in [('MAX_SPANS',5,'preview_span_limit'),('MAX_RANGES_PER_SPAN',2,'preview_range_limit'),('MAX_TEXT_CHARS',5,'preview_text_limit')]:
            with patch.object(token_preview,name,value):self.assertEqual(token_preview.preview(data)['reason'],reason)
        data=source('x'*200,[dict(text_start=0,text_end=200,ranges=[['0x1000','0x1000']])])
        record=token_preview.preview(data)['records'][0]
        self.assertEqual(len(record['token']),160);self.assertTrue(record['token_clipped'])

    def test_absence_and_malformed(self):
        for data in ({},source(spans=[]),dict(pseudocode='x',address_spans='not a list'),dict(pseudocode='x',address_spans=[None]),dict(pseudocode='x',address_span_coverage=None)):
            self.assertEqual(token_preview.preview(data)['status'],'unavailable')


class DossierTokenTests(dossiers.TemporaryCase):
    fixture=dossiers.DossierTests.fixture
    save=dossiers.DossierTests.save
    typed=dossiers.DossierTests.typed
    report=dossiers.DossierTests.report

    def test_reader_navigation_source_and_terminal_safety(self):
        report=self.report();row=report['data']['leads'][0];row['function'].update(source())
        row['query'].update(source('QUERY;',[dict(text_start=0,text_end=6,ranges=[['0x2000','0x2003']])]))
        row['query']['address_span_coverage']=dict(available=True,status='partial',text_offsets='utf16')
        before=copy.deepcopy(report);out=cli.render(report,'dossier')
        self.assertIn(b'0:6 QUERY; => 0x2000..0x2003',out)
        self.assertNotIn(b'2:9 return;',out)
        self.assertIn(b'Recorded token/address coverage: partial',out)
        self.assertIn(b'UTF-16 token offsets are half-open',out)
        self.assertEqual(report,before)
        row['query'].update(source('\x1b[31m',[dict(text_start=0,text_end=5,ranges=[['0x2000','0x2003']])]))
        out=cli.render(report,'dossier');self.assertNotIn(b'\x1b',out)
        self.assertLessEqual(len(out),65536);self.assertLessEqual(out.count(b'\n'),512)

    def test_invalid_preview_keeps_code_and_count(self):
        report=self.report();row=report['data']['leads'][0]
        row['query'].update(source('VISIBLE;',[dict(text_start=0,text_end=99,ranges=[['0x2000','0x2003']])]))
        out=cli.render(report,'dossier')
        self.assertIn(b'invalid_recorded_spans',out);self.assertIn(b'1: VISIBLE;',out)
        self.assertIn(b'Token addresses=1',out)


if __name__=='__main__':unittest.main()
