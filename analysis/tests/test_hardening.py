"""Stdlib regression tests for direct baseline evidence and process ownership."""
import copy
import importlib.util
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


runner = module('baseline_runner', 'analysis/run_baseline.py')
evaluate = module('baseline_evaluate', 'analysis/evaluate.py')
manifest = module('fixture_manifest', 'fixture/build/write_manifest.py')


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.d = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_exclusive_publication_preserves_existing(self):
        p = self.d / 'f.json'; runner.exclusive_json(p, {'old': True})
        with self.assertRaises(FileExistsError): runner.exclusive_json(p, {'old': False})
        self.assertEqual(json.loads(p.read_text()), {'old': True})

    def test_main_missing_inputs_fails_aggregate_and_refuses_reuse(self):
        args = ['DebugAnalysis-arm64-sym', '--build-root', str(self.d / 'missing'),
                '--runs-root', str(self.d / 'runs'), '--run-id', 'regression']
        with patch.object(runner, 'engine_identity', side_effect=AssertionError('unexpected engine probe')) as probe:
            self.assertEqual(runner.main(args), 1)
        probe.assert_not_called()
        identity = json.loads((self.d / 'runs/regression/identity.json').read_text())
        self.assertEqual(identity['engine_preflight'], 'not_required')
        self.assertNotIn('jdk_version', identity)
        summary = self.d / 'runs/regression/summary.json'
        before = summary.read_bytes()
        self.assertEqual(json.loads(before)['status'], 'failed')
        with self.assertRaises(FileExistsError): runner.main(args)
        self.assertEqual(before, summary.read_bytes())

    def test_missing_toolchain_fails_cases_without_launch_and_preserves_evidence(self):
        case = 'DebugAnalysis-arm64-sym'
        root = self.d / 'build/analyst' / case
        app = root / 'CalculatorFixture.app/Contents/MacOS/CalculatorFixture'
        app.parent.mkdir(parents=True)
        app.write_bytes(b'owned input for preflight failure')
        (root / 'CorpusFixture').write_bytes(b'owned tool for preflight failure')
        args = [case, '--build-root', str(self.d / 'build'),
                '--runs-root', str(self.d / 'runs'), '--run-id', 'toolchain-failure']
        with patch.object(runner, 'engine_identity', side_effect=FileNotFoundError('missing owned toolchain')) as probe, \
             patch.object(runner, 'bounded_command', side_effect=AssertionError('unexpected worker launch')) as launch:
            self.assertEqual(runner.main(args), 1)
        probe.assert_called_once()
        launch.assert_not_called()
        out = self.d / 'runs/toolchain-failure'
        summary = json.loads((out / 'summary.json').read_text())
        self.assertEqual(summary['status'], 'failed')
        self.assertEqual(len(summary['records']), 2)
        self.assertTrue(all(row['status'] == 'failed' and 'missing owned toolchain' in row['error']
                            and 'input_sha256' in row and 'engine' not in row for row in summary['records']))
        identity = json.loads((out / 'identity.json').read_text())
        self.assertEqual(identity['engine_preflight'], 'failed')
        self.assertIn('missing owned toolchain', identity['engine_error'])
        self.assertEqual(json.loads((out / 'freeze.json').read_text())['artifacts'], [])
        before = {name: (out / name).read_bytes() for name in ('identity.json', 'summary.json', 'freeze.json')}
        with self.assertRaises(FileExistsError):
            runner.main(args)
        self.assertEqual(before, {name: (out / name).read_bytes() for name in before})

    def test_first_valid_input_defers_and_records_successful_preflight_once(self):
        case = 'DebugAnalysis-arm64-sym'
        root = self.d / 'build/analyst' / case
        root.mkdir(parents=True)
        (root / 'CorpusFixture').write_bytes(b'owned tool input')
        out = self.d / 'runs/deferred-success'
        args = [case, '--build-root', str(self.d / 'build'),
                '--runs-root', str(self.d / 'runs'), '--run-id', 'deferred-success']

        def identity():
            self.assertEqual((out / ('ghidra-' + case + '-tool') / 'input.bin').read_bytes(), b'owned tool input')
            self.assertFalse((out / 'identity.json').exists())
            return {'jdk_version': 'owned test identity'}

        def launch(*args, **kwargs):
            recorded = json.loads((out / 'identity.json').read_text())
            self.assertEqual(recorded['engine_preflight'], 'complete')
            self.assertEqual(recorded['jdk_version'], 'owned test identity')
            return {'exit_code': 9, 'failure': None}

        with patch.object(runner, 'engine_identity', side_effect=identity) as probe, \
             patch.object(runner, 'bounded_command', side_effect=launch) as worker:
            self.assertEqual(runner.main(args), 1)
        probe.assert_called_once()
        worker.assert_called_once()
        records = json.loads((out / 'summary.json').read_text())['records']
        self.assertIn('FileNotFoundError', records[0]['error'])
        self.assertEqual(records[1]['error'], 'ValueError: engine process failed')

    def test_bounded_process_success(self):
        r = runner.bounded_command([sys.executable, '-c', 'print("hello")'], self.d / 'log', 5)
        self.assertEqual(r['exit_code'], 0); self.assertIsNone(r['failure'])

    def test_nonzero_engine_is_not_success(self):
        r = runner.bounded_command([sys.executable, '-c', 'raise SystemExit(9)'], self.d / 'log', 5)
        self.assertEqual(r['exit_code'], 9)

    def test_owned_timeout_does_not_kill_unrelated_process(self):
        unrelated = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(8)'], start_new_session=True)
        try:
            r = runner.bounded_command([sys.executable, '-c', 'import time;time.sleep(8)'], self.d / 'log', .1)
            self.assertEqual(r['failure'], 'whole_command_timeout')
            self.assertIsNone(unrelated.poll())
            self.assertLess(r['elapsed_secs'], 4)
        finally:
            unrelated.terminate(); unrelated.wait()

    def test_log_limit(self):
        r = runner.bounded_command([sys.executable, '-c', 'print("a"*50000)'], self.d / 'log', 5, max_log_bytes=100)
        self.assertEqual(r['failure'], 'log_size_limit'); self.assertEqual((self.d / 'log').stat().st_size, 100)

    def test_output_limit(self):
        code = 'from pathlib import Path;import time;Path(' + repr(str(self.d / 'large.partial')) + ').write_bytes(b"x"*1000);time.sleep(5)'
        r = runner.bounded_command([sys.executable, '-c', code], self.d / 'log', 5, watch=self.d, max_output_bytes=100)
        self.assertEqual(r['failure'], 'result_size_limit')

    def test_missing_and_malformed_json_fail(self):
        with self.assertRaises(FileNotFoundError): runner.validate_baseline(self.d / 'absent')
        p = self.d / 'bad'; p.write_text('{')
        with self.assertRaises(json.JSONDecodeError): runner.validate_baseline(p)

    def baseline(self):
        return {'schema': 'macscope-baseline/2', 'blind_profile': 'binary-only-v2', 'decompiler_opened': True, 'analysis_timeout_occurred': False,
            'effective_analysis_options': {'DWARF': 'false', 'External Symbol Resolver': 'false'},
            'functions_truncated': False, 'function_count_enumerated': '1', 'function_count_total_reported_by_engine': '1',
            'decompile_summary_attempted': '1', 'decompile_summary_completed': '1',
            'decompile_summary_timed_out': '0', 'decompile_summary_failed': '0',
            'decompile_summary_cancelled': '0', 'decompile_summary_not_requested': '0',
            'functions': [{'entry_va': '0x100', 'decompile_status': 'complete', 'pseudocode': 'return;',
                           'instruction_count': 0, 'instructions': [], 'block_count': 0, 'blocks': []}]}

    def test_valid_summary(self):
        p = self.d / 'base'; p.write_text(json.dumps(self.baseline()))
        self.assertEqual(runner.validate_baseline(p)['complete'], 1)

    def test_each_invalid_status_and_summary_rejected(self):
        for field, value in [('decompiler_opened', False), ('analysis_timeout_occurred', True),
                             ('decompile_summary_completed', '0'), ('functions_truncated', True)]:
            d = self.baseline(); d[field] = value
            p = self.d / 'base'; p.write_text(json.dumps(d))
            with self.subTest(field=field), self.assertRaises(ValueError): runner.validate_baseline(p)
        for status, suffix in [('timeout', 'timed_out'), ('cancelled', 'cancelled'), ('failed', 'failed')]:
            d = self.baseline(); d['functions'][0]['decompile_status'] = status
            d['decompile_summary_completed'] = '0'; d['decompile_summary_' + suffix] = '1'
            p.write_text(json.dumps(d))
            with self.subTest(status=status), self.assertRaises(ValueError): runner.validate_baseline(p)

    def test_dwarf_enabled_rejected(self):
        d = self.baseline(); d['effective_analysis_options']['DWARF'] = 'true'
        p = self.d / 'base'; p.write_text(json.dumps(d))
        with self.assertRaises(ValueError): runner.validate_baseline(p)

    def freeze(self):
        ws = self.d / 'workspace'; ws.mkdir(); f = ws / 'baseline.json'; f.write_text('{}')
        evidence = {'schema': 'macscope-freeze/1', 'artifacts': [{'path': 'workspace/baseline.json', 'sha256': evaluate.digest(f)}]}
        (ws / 'freeze.json').write_text(json.dumps(evidence))
        return ws, f, evidence

    def test_freeze_verified_and_tamper_rejected(self):
        ws, f, _ = self.freeze(); self.assertEqual(len(evaluate.verify_freeze(self.d, ws)), 1)
        f.write_text('{"tampered":true}')
        with self.assertRaises(ValueError): evaluate.verify_freeze(self.d, ws)

    def test_freeze_duplicate_rejected(self):
        ws, _, evidence = self.freeze(); evidence['artifacts'] *= 2
        (ws / 'freeze.json').write_text(json.dumps(evidence))
        with self.assertRaises(ValueError): evaluate.verify_freeze(self.d, ws)

    def test_freeze_missing_rejected(self):
        ws, f, _ = self.freeze(); f.unlink()
        with self.assertRaises(FileNotFoundError): evaluate.verify_freeze(self.d, ws)

    def test_freeze_outside_workspace_rejected(self):
        ws, _, evidence = self.freeze(); evidence['artifacts'][0]['path'] = '../escape'
        (ws / 'freeze.json').write_text(json.dumps(evidence))
        with self.assertRaises(ValueError): evaluate.verify_freeze(self.d, ws)

    def test_unlisted_baseline_rejected(self):
        ws, _, _ = self.freeze(); evaluate.WS = ws; evaluate.FREEZE_HASHES = evaluate.verify_freeze(self.d, ws)
        with self.assertRaises(ValueError): evaluate.load('not-frozen')

    def test_stripped_missing_and_incomplete_need_attention(self):
        rec = {'missing': [], 'incomplete': [], 'stripped_missing': [], 'stripped_incomplete': [], 'layout_sym_eq_stripped': True}
        self.assertFalse(evaluate.needs_attention(rec))
        for field in ['stripped_missing', 'stripped_incomplete']:
            bad = copy.deepcopy(rec); bad[field] = ['calc_add']; self.assertTrue(evaluate.needs_attention(bad))

    def test_equal_counts_do_not_prove_bytes_or_boundaries(self):
        f = {'body_ranges': [['0x10', '0x13']], 'instructions': [{'addr': '0x10', 'bytes': 'aabb'}]}
        a = evaluate.instruction_adjudication(['10:\taa bb\tinsn'], f)
        self.assertTrue(a['instruction_boundaries_and_bytes_agree'])
        for line in ['10:\taa bc\tinsn', '11:\taa bb\tinsn']:
            a = evaluate.instruction_adjudication([line], f)
            self.assertTrue(a['count_agree']); self.assertFalse(a['instruction_boundaries_and_bytes_agree'])

    def test_raw_section_bytes_not_formatted_text(self):
        data = bytearray(187); data[:4] = b'\xcf\xfa\xed\xfe'
        struct.pack_into('<II', data, 16, 1, 152); struct.pack_into('<II', data, 32, 0x19, 152)
        struct.pack_into('<I', data, 96, 1); struct.pack_into('<16s16s', data, 104, b'__text', b'__TEXT')
        struct.pack_into('<QI', data, 144, 3, 184); data[184:] = b'abc'
        p = self.d / 'thin'; p.write_bytes(data)
        self.assertEqual(manifest.text_bytes(p), b'abc')
        self.assertEqual(manifest.text_hash(p), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_malformed_macho_section_rejected(self):
        p = self.d / 'bad'; p.write_bytes(b'not a macho')
        with self.assertRaises(ValueError): manifest.text_bytes(p)


if __name__ == '__main__': unittest.main()
