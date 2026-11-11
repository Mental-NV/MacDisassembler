"""Engine-free validation of Stage D measurement and replay interpretation."""
import copy
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_focused_import import TARGETS, benchmark, summarize, verify_replay, worker_metrics


class FocusedBenchmarkTests(unittest.TestCase):
    def test_optimized_python_is_rejected_before_output_creation(self):
        with patch('benchmark_focused_import.sys.flags', SimpleNamespace(optimize=1)):
            with self.assertRaisesRegex(ValueError, 'without Python optimization'):
                benchmark(None)

    def test_five_exact_owned_entries_exclude_unbounded_last_symbol(self):
        self.assertEqual(len(TARGETS), len(set(TARGETS)))
        self.assertEqual(len(TARGETS), 5)
        self.assertNotIn('_owned_end', TARGETS)

    def test_exploratory_run_has_median_range_but_no_p95(self):
        self.assertEqual(summarize([5, 1, 3, 4, 2]), {'samples': 5, 'minimum_seconds': 1,
            'median_seconds': 3, 'maximum_seconds': 5})
        self.assertNotIn('p95_seconds', summarize(list(range(19))))

    def test_nearest_rank_p95_requires_twenty(self):
        result = summarize(list(range(1, 21)))
        self.assertEqual(result['p95_seconds'], 19)
        self.assertNotIn('target_met', result)

    def test_reject_invalid_samples(self):
        for samples in ([], [-1], [True], [float('nan')], [float('inf')]):
            with self.subTest(samples=samples), self.assertRaises(ValueError):
                summarize(samples)

    def timing(self):
        opening = {'elapsed_ns': 200000000, 'opened': True}
        job = {'status': 'complete', 'selected_entry': '0x1000', 'elapsed_seconds': 4,
               'startup': {'status': 'ready', 'observed_seconds': 2, 'ghidra_reported_ms': 1500},
               'decompiler_timing': {'open_program': opening, 'call_count': 1, 'total_call_ns': 30000000}}
        raw = {'validation': {'headless_analysis_enabled': False}, 'decompiler_timing': {
            'open_program': opening, 'calls': [{'entry': '0x1000', 'elapsed_ns': 30000000}]}}
        return job, raw

    def test_worker_intervals_are_independent_and_missing_times_null(self):
        result = worker_metrics(*self.timing(), '0x1000')
        self.assertEqual(result['launch_to_ready_seconds'], 2)
        self.assertEqual(result['ghidra_startup_seconds'], 1.5)
        self.assertEqual(result['decompiler_open_program_seconds'], .2)
        self.assertEqual(result['decompile_call_seconds'], .03)
        self.assertIsNone(result['program_database_open_seconds'])
        self.assertIsNone(result['receipt_publication_seconds'])

    def test_raw_and_summary_timing_must_agree(self):
        job, raw = self.timing()
        job['decompiler_timing']['call_count'] = 2
        with self.assertRaises(ValueError):
            worker_metrics(job, raw, '0x1000')

    def test_no_analysis_and_one_selected_call(self):
        job, raw = self.timing()
        for key, value in (('entry', '0x1001'), ('entry', None)):
            changed = copy.deepcopy(raw)
            changed['decompiler_timing']['calls'][0][key] = value
            with self.assertRaises(ValueError):
                worker_metrics(job, changed, '0x1000')
        raw['validation']['headless_analysis_enabled'] = True
        with self.assertRaises(ValueError):
            worker_metrics(job, raw, '0x1000')

    def test_replay_only_adds_known_reuse_metadata(self):
        original = {'command': 'decompile', 'status': 'partial', 'data': {'instructions': [{'bytes': 'c3'}], 'control_flow_gaps': ['kept']}}
        replay = dict(original, command='jobs resume', data=dict(original['data'], resumed_from='job', reused_restart=True))
        verify_replay(original, replay, 'job')
        for key, value in (('coverage', {}), ('analysis_id', 'changed'), ('diagnostics', ['lost'])):
            with self.assertRaises(ValueError):
                verify_replay(original, dict(replay, **{key: value}), 'job')
        for data in (dict(replay['data'], reused_restart=False), dict(replay['data'], control_flow_gaps=[]),
                     dict(replay['data'], fabricated='field')):
            with self.assertRaises(ValueError):
                verify_replay(original, dict(replay, data=data), 'job')


if __name__ == '__main__':
    unittest.main()
