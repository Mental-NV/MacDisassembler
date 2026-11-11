"""Owned synthetic evidence, presentation only; no native engine required."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from macscope import cli, engine, evidence_summary, jobs, terminal


def lead(name, status, reason=None, gaps=()):
    return dict(lead=dict(id=name), status=status, reason=reason, gaps=list(gaps))


def result(rows):
    return cli.envelope('evidence', dict(leads=rows), status='partial',
                        cov=cli.coverage('reviewer-selected evidence leads', len(rows), len(rows),
                                         True, reason='lead_evidence_incomplete'))


class SummaryTests(unittest.TestCase):
    def summary(self, rows):
        report = terminal.Report()
        evidence_summary.render(report, dict(leads=rows))
        return report.output.getvalue()

    def test_default_format_unchanged(self):
        args = cli.parser().parse_args(["evidence", "--project", "unused", "--leads", "unused"])
        self.assertIsNone(args.format)
        envelope = result([lead("a", "resolved")])
        self.assertEqual(json.loads(cli.render(envelope, args.format)), envelope)
        self.assertIn("ID unavailable", self.summary([dict(status="partial")]))

    def test_mixed_statuses_and_actions(self):
        text = self.summary([lead('complete', 'resolved'),
                             lead('partial', 'partial', gaps=['instructions_incomplete']),
                             lead('absent', 'unresolved', 'lead_ambiguous'),
                             lead('failed', 'failed', 'evidence_query_unpublished')])
        for value in ['complete [resolved]', 'partial [partial]', 'absent [unresolved]',
                      'failed [failed]', 'Disambiguate', 'saved receipt', 'recorded instructions',
                      'site not specified', 'do not establish complete graph coverage']:
            self.assertIn(value, text)
        self.assertNotIn('macscope ', text)  # actions are not invented executable commands

    def test_missing_reason_does_not_infer_site(self):
        row = lead('missing', 'partial')
        row['lead']['value'] = '0x1234'
        row['function'] = dict(entry_va='0x4321')
        text = self.summary([row])
        self.assertIn('Missing evidence not specified', text)
        self.assertNotIn('0x', text)

    def test_limits_and_terminal_controls(self):
        rows = [lead('bad\x1b[31m\n' + 'x' * 200, 'partial', 'lead_output_limit',
                     ['gap' + str(i) for i in range(10)]) for _ in range(34)]
        text = self.summary(rows)
        self.assertNotIn('\x1b', text)
        self.assertIn(r'\u{1b}', text)
        self.assertIn(r'\n', text)
        self.assertIn('narrow the selected scope', text)
        self.assertIn('Additional reason/gap entries omitted from summary  3', text)
        self.assertIn('Additional leads omitted from summary  2', text)
        self.assertEqual(text.count('  Lead  '), 32)
        self.assertNotIn('x' * 161, text)

    def test_offline_multi_lead_render_preserves_machine_data(self):
        source = result([lead('a', 'resolved'), lead('b', 'partial', gaps=['pseudocode_partial']),
                         lead('c', 'unresolved', 'selected_receipts_unavailable')])
        before = copy.deepcopy(source)
        encoded = cli.render(source, 'json')
        with patch.object(engine, 'dependencies', side_effect=AssertionError('engine unavailable')), \
             patch.object(jobs, 'claim', side_effect=AssertionError('no new jobs')):
            saved = json.loads(encoded)
            first = terminal.render(saved)
            self.assertEqual(first, terminal.render(saved))
            self.assertEqual(encoded, cli.render(saved, 'json'))
        self.assertEqual(source, before)
        self.assertLess(first.index(b'Selected lead summary'), first.index(b'    gaps'))

    def test_cli_partial_text_retains_exit_six(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'report.txt'
            with patch.object(cli, 'execute', return_value=result([lead('a', 'partial')])), \
                 patch.object(cli, 'protect_output'):
                code = cli.main(['evidence', '--project', directory, '--leads', 'unused.json',
                                 '--format', 'text', '--output', str(output)])
            self.assertEqual(code, 6)
            text = output.read_text()
            self.assertIn('Partial result (exit 6)', text)
            self.assertIn('a [partial]', text)


if __name__ == '__main__':
    unittest.main()
