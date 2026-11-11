"""Owned consumer reading tasks; no semantic or human-speed claim."""
import copy
import json
import unittest
from unittest.mock import patch

from macscope import cli, engine, jobs, method_dossier, objc_type_evidence as sidecars, storage
from test_core import TemporaryCase
import test_objc_type_evidence as type_tests


class DossierTests(TemporaryCase):
    fixture = type_tests.SidecarDiffTests.fixture
    save = type_tests.SidecarDiffTests.save
    typed = type_tests.SidecarDiffTests.typed

    def report(self):
        path, data = self.typed('dossier')
        return json.loads(path.read_bytes())

    def test_consumer_finds_identity_argument_code_and_unknowns_together(self):
        report = self.report()
        row = report['data']['leads'][0]
        row['function']['pseudocode'] = 'return arg1 + 42;'
        before = copy.deepcopy(report)
        text = cli.render(report, 'dossier').decode()
        for value in ('calendarDayDuration:', row['function']['entry_va'],
                      'arg1 [explicit] -> rdx', 'conditional on conforming IMP',
                      '1: return arg1 + 42;', 'runtime dispatch, behavior and persistence are not established',
                      'References to recorded coverage: partial', 'not recovered source lines',
                      '--format json or --format text'):
            self.assertIn(value, text)
        self.assertEqual(report, before)
        self.assertNotIn('callback_composition', text)

    def test_query_code_source_not_silently_merged_with_snapshot(self):
        report = self.report()
        row = report['data']['leads'][0]
        row['function']['pseudocode'] = 'OLD_SNAPSHOT;'
        row['query'].update(pseudocode='SELECTED_QUERY;', decompile_status='partial',
                            control_flow_gaps=[dict(reason='query_unknown')])
        text = cli.render(report, 'dossier')
        self.assertIn(b'selected saved query', text)
        self.assertIn(b'SELECTED_QUERY;', text)
        self.assertNotIn(b'OLD_SNAPSHOT', text)
        self.assertIn(b'query_unknown', text)
        self.assertIn(b'saved function, not the query pseudocode', text)

    def test_unsupported_context_preserves_raw_code(self):
        report = self.report()
        data = report['data']
        row = data['leads'][0]
        row['matches'][0]['type_encoding'] = 'v24@0:8d16'
        data[sidecars.FIELD] = sidecars.build(data, {})
        text = cli.render(report, 'dossier')
        self.assertIn(b'ABI roles: unsupported', text)
        self.assertIn(b'argument_2_type_unsupported', text)
        self.assertNotIn(b'-> rdx', text)
        self.assertIn(b'return;', text)
        row['matches'][0]['implementation_va'] = '0x9999'
        data[sidecars.FIELD] = sidecars.build(data, {})
        self.assertIn(b'method_entry_mismatch', cli.render(report, 'dossier'))

    def test_missing_function_and_missing_reasons(self):
        report = self.report()
        data = report['data'];data.pop(sidecars.FIELD)
        row = data['leads'][0]
        row.update(function=None, status='partial', reason=None, gaps=[])
        text = cli.render(report, 'dossier')
        self.assertIn(b'Missing evidence unspecified', text)
        self.assertIn(b'Selected function unavailable', text)

    def test_caps_escaping_and_counts_do_not_modify_full_evidence(self):
        report = self.report()
        data = report['data']; data.pop(sidecars.FIELD)
        row = data['leads'][0]
        row['lead']['value'] = '\x1b\n' * 1000
        row['function']['pseudocode'] = ('\U000e0001' * 500 + '\n') * 100
        row['gaps'] = ['gap'] * 9
        data['leads'] = [copy.deepcopy(row) for _ in range(10)]
        before = storage.canonical(report)
        output = cli.render(report, 'dossier')
        self.assertLessEqual(len(output), 65536)
        self.assertLessEqual(output.count(b'\n'), 512)
        self.assertIn(b'Leads displayed: 4; omitted: 6.', output)
        self.assertIn(b'Blockers=5', output)
        self.assertIn(b'[clipped]', output)
        self.assertIn(b'budget lines omitted:', output)
        self.assertNotIn(b'\x1b', output)
        self.assertEqual(before, storage.canonical(report))
        self.assertEqual(json.loads(cli.render(report, 'json')), report)
        for block in output.split(b'Lead ')[1:]:
            self.assertLess(len(block), 12288 + 512)  # last block also includes global footer

    def test_offline_cli_and_deterministic_replay(self):
        case = type_tests.SidecarExportTests();case.setUp()
        self.addCleanup(case.doCleanups)
        enriched = case.query('--objc-types')
        jobs_before = sorted(p.name for p in (case.workspace.path/'jobs').iterdir())
        with patch.object(engine, 'dependencies', side_effect=AssertionError('offline')), patch.object(jobs, 'claim', side_effect=AssertionError('no jobs')):
            first = cli.render(enriched, 'dossier')
            self.assertEqual(first, cli.render(enriched, 'dossier'))
            target = case.root/'dossier.txt'
            code = cli.main(['evidence','--project',str(case.workspace.path),'--leads',str(case.root/'leads.json'),
                             '--objc-types','--format','dossier','--output',str(target)])
            self.assertEqual(code, 6 if enriched['status']=='partial' else 0)
            self.assertEqual(target.read_bytes(), first)
        self.assertEqual(jobs_before, sorted(p.name for p in (case.workspace.path/'jobs').iterdir()))


if __name__ == '__main__':
    unittest.main()
