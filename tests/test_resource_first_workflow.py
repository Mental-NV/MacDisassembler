"""Engine-free negative controls for the opt-in owned Stage C rehearsal."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from macscope import cli, storage
import integration_resource_first_calendar as workflow


def nib_capture():
    owner = {'object_index': 1, 'archive_class': 'NSCustomObject', 'declared_class': workflow.CLASS}
    button = {'object_index': 2, 'archive_class': 'NSButton'}
    view = {'object_index': 3, 'archive_class': 'NSCustomView'}
    rows = [
        {'kind': 'action', 'label': workflow.ACTION, 'source': button, 'destination': owner},
        {'kind': 'outlet', 'label': 'advancedToggle', 'source': owner, 'destination': button},
        {'kind': 'outlet', 'label': 'advancedRow', 'source': owner, 'destination': view},
    ]
    return cli.envelope('resources nib', {'relative_path': workflow.NIB, 'records': rows},
                        cov=cli.coverage('owned nib declarations', 3, 3))


class ResourceFirstWorkflowTests(unittest.TestCase):
    def test_wiring_is_only_a_declared_class_and_endpoint_match(self):
        capture = nib_capture()
        before = copy.deepcopy(capture)
        result = workflow.wiring(capture)
        self.assertEqual(result['action']['destination']['declared_class'], workflow.CLASS)
        self.assertNotIn('visible', result)
        self.assertNotIn('reachable', result)
        self.assertEqual(capture, before)

    def test_wiring_rejects_partial_missing_duplicate_and_wrong_direction(self):
        mutations = [
            lambda r: r.update(status='partial'),
            lambda r: r['coverage'].update(status='partial', known_total=None),
            lambda r: r['data']['records'].pop(),
            lambda r: r['data']['records'].append(copy.deepcopy(r['data']['records'][0])),
            lambda r: r['data']['records'][0].update(source=r['data']['records'][0]['destination']),
            lambda r: r['data'].update(relative_path='Contents/Other.nib'),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                row = nib_capture()
                mutate(row)
                with self.assertRaises((AssertionError, ValueError)):
                    workflow.wiring(row)

    def test_class_or_row_identity_cannot_be_inferred_from_a_label(self):
        for change in ('class', 'row', 'toggle'):
            capture = nib_capture()
            rows = capture['data']['records']
            if change == 'class':
                rows[0]['destination'] = dict(rows[0]['destination'], declared_class='OtherOwner')
            elif change == 'row':
                rows[2]['destination'] = rows[0]['source']
            else:
                rows[1]['destination'] = dict(rows[0]['source'], object_index=99)
            with self.subTest(change=change), self.assertRaises(AssertionError):
                workflow.wiring(capture)

    def test_apple_selection_is_an_exclusive_address_range_not_a_name_match(self):
        text = 'file:\nlabel:\n0000000100001000\tcmp x0, x1\n0000000100001004\tb.eq 0x10000100c\n0000000100001008\tstr x0, [x2]\n000000010000100c\tret\n'
        rows = workflow.selected_apple_instructions(text, 0x100001004, 0x10000100c)
        self.assertEqual([r['address'] for r in rows], ['0x100001004', '0x100001008'])
        with self.assertRaises(AssertionError):
            workflow.selected_apple_instructions(text, 0x2000, 0x3000)

    def test_harness_forbids_analyze_before_launching_subprocess(self):
        with patch.object(workflow.subprocess, 'run', side_effect=AssertionError('launched')) as run:
            with self.assertRaisesRegex(AssertionError, 'Whole-image analysis'):
                workflow.invoke(Path('/unused'), 'forbidden', 'analyze')
            run.assert_not_called()

    def test_html_is_deterministic_escaped_and_keeps_epistemic_sections(self):
        report = {key: [] for key in ('facts', 'bounded_inferences', 'unknowns', 'coverage_by_step',
                                     'resources', 'metadata', 'apple_instructions', 'byte_oracle', 'source_identity')}
        report.update(pin={'arch': 'arm64', 'slice_sha256': 'a' * 64, 'import_program_sha256': 'b' * 64},
                      selected_evidence={'data': {'leads': []}})
        report['unknowns'] = ['<script>not established</script>']
        first = workflow.render(report)
        self.assertEqual(first, workflow.render(copy.deepcopy(report)))
        self.assertIn(b'Bounded inferences', first)
        self.assertIn(b'Unknowns', first)
        self.assertIn(b'&lt;script&gt;', first)
        self.assertNotIn(b'<script>', first)
        self.assertIn(b"default-src 'none'", first)

    def test_existing_capture_is_replayed_before_any_new_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = str(Path(temporary).resolve())
            root = Path(tmp) / 'arm64'
            root.mkdir()
            storage.write_json(root / 'context.json', {'owned': 'saved', 'arch': 'arm64'})
            with (patch.object(workflow.sys, 'argv', ['rehearsal', '--output-dir', tmp, '--arch', 'arm64']),
                  patch.object(workflow, 'prepare', side_effect=AssertionError('rebuilt')) as prepare,
                  patch.object(workflow, 'replay', return_value={'status': 'passed'}) as replay,
                  patch('builtins.print')):
                workflow.main()
                prepare.assert_not_called()
                replay.assert_called_once_with(root, {'owned': 'saved', 'arch': 'arm64'})

    def test_incomplete_capture_is_not_overwritten_or_restarted(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = str(Path(temporary).resolve())
            (Path(tmp) / 'arm64').mkdir()
            with (patch.object(workflow.sys, 'argv', ['rehearsal', '--output-dir', tmp, '--arch', 'arm64']),
                  patch.object(workflow, 'prepare') as prepare, patch('builtins.print')):
                with self.assertRaises(SystemExit):
                    workflow.main()
                prepare.assert_not_called()

    def test_replay_requires_saved_captures(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = str(Path(temporary).resolve())
            with (patch.object(workflow.sys, 'argv', ['rehearsal', '--output-dir', tmp, '--arch', 'arm64', '--replay']),
                  patch.object(workflow, 'prepare') as prepare, patch('builtins.print')):
                with self.assertRaises(SystemExit):
                    workflow.main()
                prepare.assert_not_called()

    def test_one_architecture_failure_does_not_skip_the_other(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = str(Path(temporary).resolve())
            for arch in ('arm64', 'x86_64'):
                root = Path(tmp) / arch
                root.mkdir()
                storage.write_json(root / 'context.json', {'arch': arch})
            def replay(root, context):
                if context['arch'] == 'arm64':
                    raise AssertionError('owned arm64 failure')
                return {'arch': 'x86_64', 'status': 'passed'}
            with (patch.object(workflow.sys, 'argv', ['rehearsal', '--output-dir', tmp]),
                  patch.object(workflow, 'replay', side_effect=replay) as replayed,
                  patch('builtins.print')):
                with self.assertRaises(SystemExit):
                    workflow.main()
                self.assertEqual(replayed.call_count, 2)
                rows = storage.strict_json((Path(tmp) / 'summary.json').read_bytes())
                self.assertEqual([row['status'] for row in rows], ['failed', 'passed'])
                self.assertEqual(rows[0]['reason'], 'owned arm64 failure')


if __name__ == '__main__':
    unittest.main()
