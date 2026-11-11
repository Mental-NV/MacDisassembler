"""Source labels do not replace receipt validation or change selected code."""
import copy
import unittest
from macscope import cli
import test_method_dossier as fixtures
from test_core import TemporaryCase


class SourceTests(TemporaryCase):
    fixture = fixtures.DossierTests.fixture
    save = fixtures.DossierTests.save
    typed = fixtures.DossierTests.typed
    report = fixtures.DossierTests.report

    def focused(self):
        report = self.report()
        data = report['data'];data.pop('objc_type_evidence',None)
        row = data['leads'][0];pin = data['images'][0]
        pin.pop('analysis_id',None)
        origin = dict(mode='focused_readonly_import',job_id='a'*32,
                      extent={'program_sha256':pin['import_program_sha256']})
        row['function']['origin'] = origin
        row['function']['pseudocode'] = 'FOCUSED_CODE;'
        row['query'] = dict(status='complete',origin=copy.deepcopy(origin))
        return report,row,pin

    def test_focused_complete_partial_and_resumed_job_keep_payload(self):
        for status in ('complete','partial'):
            report,row,_ = self.focused()
            row['query']['status']=status
            # Requested job may differ from a resumed receipt's source job.
            row['lead']['query_job']='b'*32
            before=copy.deepcopy(report)
            text=cli.render(report,'dossier')
            self.assertIn(b'selected import-focused query (function payload)',text)
            self.assertIn(b'Source job: '+b'a'*32,text)
            self.assertIn(b'FOCUSED_CODE;',text)
            self.assertIn(b'samples below come from the selected import-focused function payload',text)
            self.assertNotIn(b'not a successful query',text)
            self.assertEqual(report,before)

    def test_unestablished_provenance_never_implies_success(self):
        for change in ('missing_origin','different_origin','mode','missing_pin','wrong_pin','failed','missing_job'):
            report,row,pin=self.focused()
            if change=='missing_origin':row['query'].pop('origin')
            elif change=='different_origin':row['query']['origin']['job_id']='b'*32
            elif change=='mode':row['function']['origin']['mode']='saved'
            elif change=='missing_pin':pin.pop('import_program_sha256')
            elif change=='wrong_pin':pin['import_program_sha256']='f'*64
            elif change=='failed':row['query']['status']='failed'
            elif change=='missing_job':row['function']['origin'].pop('job_id')
            text=cli.render(report,'dossier')
            self.assertNotIn(b'selected import-focused query (function payload)',text,change)
            self.assertIn(b'query relationship unestablished',text,change)
            self.assertIn(b'FOCUSED_CODE;',text)

    def test_inline_precedence_empty_code_and_analyzed_fallback(self):
        report,row,pin=self.focused()
        row['query']['pseudocode']=''
        self.assertIn(b'Pseudocode source: selected saved query',cli.render(report,'dossier'))
        self.assertNotIn(b'FOCUSED_CODE;',cli.render(report,'dossier'))
        row['query'].pop('pseudocode');row['query']['status']='unavailable'
        pin['analysis_id']='e'*64
        self.assertIn(b'Pseudocode source: saved function',cli.render(report,'dossier'))
        self.assertIn(b'not established as this query output',cli.render(report,'dossier'))

    def test_signature_caution_and_objc_advice_only_for_selectors(self):
        report,row,_=self.focused()
        row['lead']['kind']='address'
        text=cli.render(report,'dossier')
        self.assertIn(b'Signature metadata may differ from pseudocode-inferred arguments',text)
        self.assertNotIn(b'Add --objc-types',text)
        row['lead']['kind']='objc_selector'
        self.assertIn(b'Add --objc-types',cli.render(report,'dossier'))
