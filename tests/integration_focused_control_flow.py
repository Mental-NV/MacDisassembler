#!/usr/bin/env python3
"""Static-only owned fixture: proven tail calls, terminal traps and unresolved BR."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from macscope.schema import validate_envelope
from macscope import focused


def invoke(root, label, *words, expected=(0,)):
    result = subprocess.run([sys.executable, '-m', 'macscope', *map(str, words), '--json'],
                            capture_output=True, timeout=240)
    (root / (label + '.json')).write_bytes(result.stdout)
    (root / (label + '.stderr')).write_bytes(result.stderr)
    assert result.returncode in expected, (label, result.returncode, result.stderr, result.stdout)
    response = json.loads(result.stdout)
    validate_envelope(response)
    return response


def run(root, source):
    root.mkdir(parents=True, exist_ok=True)
    binary = root / 'OwnedFocusedControlFlow.dylib'
    subprocess.run(['/usr/bin/xcrun', 'clang', '-arch', 'arm64', '-dynamiclib',
                    str(source), '-o', str(binary)], check=True, timeout=60)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    symbols = {}
    for line in subprocess.check_output(['/usr/bin/xcrun', 'nm', '-n', str(binary)], text=True).splitlines():
        row = line.split()
        if len(row) == 3 and row[2].startswith('_owned_'):
            symbols[row[2]] = hex(int(row[0], 16))
    expected = {'local': '_owned_tail_local', 'import': '_owned_tail_import',
                'trap': '_owned_trap', 'indirect': '_owned_indirect',
                **{kind:'_owned_escape_'+kind for kind in ('constant','same','overwritten','unused','conditional','fallthrough')}}
    assert set(expected.values()) <= symbols.keys(), symbols
    project = root / 'project'
    invoke(root, 'create', 'project', 'create', project)
    invoke(root, 'import', 'import', binary, '--project', project, '--arch', 'arm64',
           '--experimental-trusted-input', '--timeout', '180')
    summaries = {}
    for label, symbol in expected.items():
        report = invoke(root, 'decompile-' + label, 'decompile', '--project', project,
                        '--arch', 'arm64', '--address', symbols[symbol], '--from-import',
                        '--experimental-trusted-input', '--timeout', '150',
                        '--function-timeout', '25', expected=(0, 6))
        function = report['data']
        assert function['pseudocode'] and not function['pseudocode_truncated'], label
        assert function['entry_va'] == symbols[symbol], label
        proof = function['origin']['extent']
        payload = binary.read_bytes()[int(proof['slice_file_offset'], 16):
                                      int(proof['slice_file_offset'], 16) + proof['length']]
        raw = bytes.fromhex(''.join(row['bytes'] for row in function['instructions']))
        assert payload == raw, (label, 'selected bytes changed or missing')
        assert hashlib.sha256(raw).hexdigest() == function['instruction_bytes_sha256'], label
        escape = label in ('constant','same','overwritten','unused','conditional','fallthrough')
        if label == 'indirect' or escape:
            assert report['status'] == function['decompile_status'] == 'partial', report
            assert function.get('control_flow_gaps'), label
            if escape:
                assert any(gap['reason']=='focused_flow_outside_body' for gap in function['control_flow_gaps']), label
                assert function['tail_call_recovery']['decisions']==[], label
        else:
            assert report['status'] == function['decompile_status'] == 'complete', report
            assert not function.get('control_flow_gaps'), label
            assert 'Could not recover jumptable' not in function['pseudocode'], label
            assert 'Treating indirect jump as call' not in function['pseudocode'], label
        if not escape or label == 'constant':
            assert function['native_scope']['outside_body_operations'] == 0, label
            assert function['native_scope']['status'] == 'complete', label
        if label in ('local','import'):
            decisions = function['tail_call_recovery']['decisions']
            assert len(decisions) == 1 and decisions[0]['outcome'] == 'applied', label
            kind = 'linker_function_start' if label == 'local' else 'declared_import_stub'
            assert proof['tail_calls']['candidates'][0]['target_kind'] == kind, label
            calls = list(focused.direct_calls('arm64', function))
            assert len(calls) == 1 and calls[0][1] == proof['tail_calls']['candidates'][0]['target_va'], label
        if label == 'trap':
            assert len(function['control_flow_traps']) == 1, label
            assert 'SoftwareBreakpoint' in function['pseudocode'], function['pseudocode']
            assert any(row['bytes'] == '200020d4' for row in function['instructions']), label
        if label == 'local':
            assert '0x2a' not in function['pseudocode'], 'callee body leaked into selected function'
        summaries[label] = {'status': report['status'], 'entry_va': function['entry_va'],
                            'instruction_count': function['instruction_count'],
                            'pseudocode_characters': len(function['pseudocode']),
                            'outside_body_operations':function['native_scope']['outside_body_operations'],
                            'flow_gap_reasons':[gap['reason'] for gap in function.get('control_flow_gaps',[])]}
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest
    summary = {'root': str(root), 'fixture_sha256': digest, 'binary_unchanged': True,
               'application_executed': False, 'checks': summaries}
    (root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1] /
                        'fixture' / 'focused-control-flow' / 'OwnedFocusedControlFlow.s')
    args = parser.parse_args()
    output = args.output_dir or Path(tempfile.mkdtemp(prefix='macscope-focused-flow.'))
    run(output, args.source)
