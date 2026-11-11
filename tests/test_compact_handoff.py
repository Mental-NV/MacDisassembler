"""Owned large handoff fixture; offline presentation benchmark, not native analysis."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from macscope import cli, engine, jobs


def fixture(count=12):
    rows = [dict(lead=dict(id=f'owned-lead-{i}'), status='partial', reason='lead_evidence_incomplete',
                 gaps=['instructions_incomplete', 'selected_receipts_unavailable', 'candidate_limit'],
                 function=dict(pseudocode='OWNED_NESTED_DETAIL\n' * 1000,
                               instructions=[dict(addr=hex(j), text='owned instruction') for j in range(500)]))
            for i in range(count)]
    return cli.envelope('evidence', dict(leads=rows), status='partial',
                        cov=cli.coverage('owned selected leads', count, count, True, reason='lead_evidence_incomplete'))


def measurements():
    return {fmt: dict(bytes=len(out), lines=out.count(b'\n'))
            for fmt in ('compact', 'text', 'json') for out in (cli.render(fixture(), fmt),)}


class CompactTests(unittest.TestCase):
    def test_twelve_lead_benchmark(self):
        data = fixture()
        before = copy.deepcopy(data)
        out = cli.render(data, 'compact')
        self.assertLessEqual(len(out), 32768)
        self.assertLessEqual(out.count(b'\n'), 200)
        for text in (b'[partial]', b'Partial evidence exits 6', b'Leads displayed: 12; omitted: 0.', b'Nested evidence details omitted'):
            self.assertIn(text, out)
        self.assertNotIn(b'OWNED_NESTED_DETAIL', out)
        detailed = cli.render(data, 'text')
        self.assertIn(b'OWNED_NESTED_DETAIL', detailed)
        self.assertLess(len(out), len(detailed) / 10)
        self.assertEqual(json.loads(cli.render(data, 'json')), data)
        self.assertEqual(data, before)

    def test_controls_and_total_budget(self):
        data = fixture(40)
        for row in data['data']['leads']:
            row['lead']['id'] = '\U000e0001' * 1000
            row['reason'] = '\x1b\n\r\t' * 1000
            row['gaps'] = ['\U000e0001' * 1000] * 10
        out = cli.render(data, 'compact')
        self.assertLessEqual(len(out), 32768)
        self.assertLessEqual(out.count(b'\n'), 200)
        self.assertNotIn(b'\x1b', out)
        self.assertNotIn(b'\r', out)
        self.assertIn(b'[clipped]', out)
        self.assertIn(b'--format json or --format text', out)
        self.assertNotIn(b'Leads displayed: 24;', out)

    def test_lead_cap_and_blocker_priority(self):
        out = cli.render(fixture(30), 'compact')
        self.assertIn(b'Leads displayed: 24; omitted: 6.', out)
        self.assertIn(b'Additional blocker entries omitted for displayed leads: 48.', out)
        self.assertIn(b'selected_receipts_unavailable', out)
        self.assertNotIn(b'candidate_limit', out)
        self.assertNotIn(b'instructions_incomplete', out)

    def test_missing_reasons_and_statuses(self):
        data = fixture(3)
        for row, status in zip(data['data']['leads'], ['resolved', 'partial', 'failed']):
            row.update(status=status, reason=None, gaps=[])
        out = cli.render(data, 'compact')
        self.assertIn(b'[resolved]', out)
        self.assertIn(b'[failed]', out)
        self.assertIn(b'Missing evidence unspecified; no gap site inferred.', out)
        self.assertNotIn(b'0x', out)

    def test_offline_replay_and_cli_partial_exit(self):
        source = fixture()
        saved = json.loads(cli.render(source, 'json'))
        with patch.object(engine, 'dependencies', side_effect=AssertionError('offline')), patch.object(jobs, 'claim', side_effect=AssertionError('no jobs')):
            first = cli.render(saved, 'compact')
            self.assertEqual(first, cli.render(saved, 'compact'))
            self.assertEqual(cli.render(source, 'json'), cli.render(saved, 'json'))
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory).resolve() / 'result.txt'
                with patch.object(cli, 'execute', return_value=saved), patch.object(cli, 'protect_output'):
                    code = cli.main(['evidence', '--project', directory, '--leads', 'unused', '--format', 'compact', '--output', str(output)])
                self.assertEqual(code, 6)
                self.assertEqual(output.read_bytes(), first)

    def test_complete_and_default_format(self):
        data = fixture(1)
        data['status'] = 'complete'
        data['data']['leads'][0].update(status='resolved', reason=None, gaps=[])
        out = cli.render(data, 'compact')
        self.assertIn(b'[complete]', out)
        self.assertNotIn(b'exits 6', out)
        args = cli.parser().parse_args(['evidence', '--project', 'x', '--leads', 'x'])
        self.assertIsNone(args.format)
        self.assertIn(b'OWNED_NESTED_DETAIL', cli.render(data, args.format))


if __name__ == '__main__':
    print(json.dumps(measurements(), sort_keys=True, indent=2))
    unittest.main()
