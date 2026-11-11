import copy
import unittest
from macscope import terminal, cli
from macscope.cli import envelope
import test_dossier_source as sources
from test_core import TemporaryCase


class StatusWordingTests(unittest.TestCase):
    def result(self):
        return envelope('status',dict(images=[dict(image_id='owned',imported=True,active_analysis=None,
             analysis={'status':'not_analyzed','analysis_id':None})],jobs=[]))

    def test_recorded_import_without_query_not_claimed_verified(self):
        result=self.result();before=copy.deepcopy(result);text=terminal.render(result)
        self.assertIn(b'No whole-image analysis recorded',text)
        self.assertIn(b'recorded, not verified',text)
        self.assertIn(b'query outcomes and graph coverage',text)
        self.assertEqual(result,before)

    def test_analysis_errors_existing_and_import_failures_remain(self):
        for state in ('unavailable','unverified','failed','complete','partial'):
            result=self.result();image=result['data']['images'][0]
            image.update(active_analysis='a'*64,analysis={'status':state,'analysis_id':'a'*64,'error':'owned_snapshot_error'})
            text=terminal.render(result)
            self.assertNotIn(b'No whole-image analysis recorded',text)
            self.assertIn(('Whole-image analysis: '+state).encode(),text)
            self.assertIn(b'owned_snapshot_error',text)
        for state in ('unavailable','unverified','not_imported'):
            result=self.result();result['data']['images'][0]['programs']={'import':{'status':state,'error':'owned_import_error'}}
            text=terminal.render(result)
            self.assertNotIn(b'No whole-image analysis recorded',text)
            self.assertIn(b'owned_import_error',text)

    def test_failed_attempt_remains_visible_and_missing_ids_not_reassuring(self):
        result=self.result();result['data']['jobs']=[{'mode':'analysis','status':'failed','failure':'owned_failure'}]
        text=terminal.render(result)
        self.assertIn(b'No whole-image analysis recorded',text)
        self.assertIn(b'does not mean no analysis was attempted',text)
        self.assertIn(b'owned_failure',text);self.assertIn(b'failed',text)
        del result['data']['images'][0]['active_analysis']
        self.assertNotIn(b'No whole-image analysis recorded',terminal.render(result))

    def test_inconsistent_diagnostic_shapes_do_not_imply_safe_absence(self):
        for target in ('analysis','import','program_analysis'):
            result=self.result();image=result['data']['images'][0]
            image['programs']={'import':{},'analysis':{}}
            record=image['analysis'] if target=='analysis' else image['programs']['import' if target=='import' else 'analysis']
            record['error']='contradictory_failure'
            text=terminal.render(result)
            self.assertNotIn(b'No whole-image analysis recorded',text)
            self.assertIn(b'contradictory_failure',text)
        result=self.result();result['data']['images'][0]['programs']={'analysis':{'status':'unavailable','error':'missing_program'}}
        self.assertIn(b'Analysis Program verification: unavailable; diagnostic: missing_program',terminal.render(result))

    def test_summary_bounded_and_raw_tree_retained(self):
        result=self.result();result['data']['images']*=10
        text=terminal.render(result)
        self.assertEqual(text.count(b'No whole-image analysis recorded'),8)
        self.assertIn(b'Summary images omitted: 2',text)
        self.assertIn(b'[10]',text)


class DossierWordingTests(TemporaryCase):
    fixture=sources.SourceTests.fixture
    save=sources.SourceTests.save
    typed=sources.SourceTests.typed
    report=sources.SourceTests.report
    focused=sources.SourceTests.focused

    def test_available_import_only_scoped_not_global_with_query_outcomes(self):
        for status in ('complete','partial','unavailable'):
            result,row,pin=self.focused();pin['source']='committed_import';pin['status']='available'
            row['query']['status']=status
            text=cli.render(result,'dossier')
            self.assertIn(b'No whole-image analysis recorded in this import-pinned report; other snapshots not checked.',text)
            self.assertIn(('query status: '+status).encode(),text)
            self.assertIn(b'Image evidence: available',text)
            self.assertNotIn(b'Source pin: analysis unavailable',text)

    def test_unavailable_image_and_committed_analysis(self):
        result,row,pin=self.focused();pin.update(source='committed_import',status='unavailable',reason='snapshot_invalid')
        text=cli.render(result,'dossier')
        self.assertNotIn(b'No whole-image analysis recorded',text)
        self.assertIn(b'snapshot_invalid',text)
        self.assertIn(b'no analysis success or absence inferred',text)
        pin['analysis_id']='a'*64
        self.assertIn(b'Whole-image analysis pin: '+b'a'*64,cli.render(result,'dossier'))
