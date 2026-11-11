#!/usr/bin/env python3
"""Static-only owned handler/linkage and internal-flow proof on each architecture.

Run on macOS with an existing Ghidra/JDK. Never loads or executes the fixtures.
The source tree, generated binaries and saved projects stay separate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from macscope import storage
from macscope.schema import validate_envelope


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(root, label, *words, expected=(0,), env=None):
    result = subprocess.run([sys.executable, '-m', 'macscope', *map(str, words), '--json'],
                            capture_output=True, timeout=240, env=env)
    (root / (label + '.json')).write_bytes(result.stdout)
    (root / (label + '.stderr')).write_bytes(result.stderr)
    assert result.returncode in expected, (label, result.returncode, result.stderr, result.stdout)
    response = json.loads(result.stdout)
    validate_envelope(response)
    return response


def run(root, arch):
    root.mkdir(parents=True, exist_ok=True)
    suffix = 'Arm64' if arch == 'arm64' else 'X86_64'
    source = Path(__file__).resolve().parents[1] / 'fixture' / 'flow-gap-evidence' / ('OwnedFlowGap' + suffix + '.s')
    binary = root / ('OwnedFlowGap-' + arch + '.dylib')
    subprocess.run(['/usr/bin/xcrun', 'clang', '-arch', arch, '-dynamiclib', str(source), '-o', str(binary)],
                   check=True, timeout=60)
    fixture_digest = digest(binary)
    symbols = {}
    nm = subprocess.check_output(['/usr/bin/xcrun', 'nm', '-n', str(binary)], text=True)
    (root / 'nm.txt').write_text(nm)
    for line in nm.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2].startswith('_owned_'):
            symbols[fields[2]] = hex(int(fields[0], 16))
    for label, words in [('disassembly', ['otool', '-tvV']), ('load-commands', ['otool', '-l']),
                         ('fixups', ['dyld_info', '-fixups'])]:
        result = subprocess.run(['/usr/bin/xcrun', *words, str(binary)], capture_output=True, timeout=30)
        (root / (label + '.txt')).write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        assert result.returncode == 0, (label, result.stderr)
    project = root / 'project'
    invoke(root, 'create', 'project', 'create', project)
    invoke(root, 'import', 'import', binary, '--project', project, '--arch', arch,
           '--experimental-trusted-input', '--timeout', '180')
    saved = storage.Project(project)
    image = saved.select(arch=arch)
    program_digest = image['engine_baseline_sha256']
    reports = {}
    for name in ('handler', 'linkage', 'wrapper_named', 'internal'):
        response = invoke(root, 'decompile-' + name, 'decompile', '--project', project, '--arch', arch,
                          '--address', symbols['_owned_' + name], '--from-import',
                          '--experimental-trusted-input', '--timeout', '150', '--function-timeout', '25',
                          expected=(0,) if name == 'handler' else (6,))
        function = response['data']
        extent = function['origin']['extent']
        assert extent['policy'] == 'macscope-focused-import/3'
        assert extent['program_sha256'] == program_digest
        start = int(extent['slice_file_offset'], 16)
        payload = binary.read_bytes()[start:start + extent['length']]
        captured = bytes.fromhex(''.join(row['bytes'] for row in function['instructions']))
        assert captured == payload
        assert hashlib.sha256(captured).hexdigest() == function['instruction_bytes_sha256']
        assert function['pseudocode'] and not function['pseudocode_truncated']
        assert function['entry_va'] == symbols['_owned_' + name]
        if name == 'handler':
            assert function['decompile_status'] == response['status'] == 'complete'
            assert not function.get('control_flow_gaps')
            # Independent fixture-byte oracle for the local compare/write. The
            # text is retained as engine evidence, not used to prove the effect.
            if arch == 'arm64':
                assert captured == bytes.fromhex('020040b95f00016b40000054010000b9c0035fd6')
            else:
                assert captured == bytes.fromhex('393774028937c3')
        else:
            assert function['decompile_status'] == response['status'] == 'partial'
            gaps = function['control_flow_gaps']
            assert gaps and all(g['evidence']['policy'] == 'macscope-control-flow-gap-evidence/2' for g in gaps)
            kinds = {g['evidence']['classification']['kind'] for g in gaps}
            expected = {'linkage': 'verified_linkage_boundary', 'internal': 'unresolved_internal_transfer',
                        'wrapper_named': 'unclassified'}[name]
            assert expected in kinds, (name, kinds, gaps)
            if name == 'wrapper_named':
                assert kinds == {'unclassified'}, gaps
            for gap in gaps:
                extension = gap['evidence']
                assert extension['function']['program_sha256'] == program_digest
                if extension['classification']['kind'] == 'verified_linkage_boundary':
                    assert extension['classification']['runtime_target'] == 'unresolved'
                    assert extension['classification']['proof']['binding']['symbol'] == '_puts'
                if 'warning' in gap:
                    assert extension['location'] == {'kind': 'unavailable', 'reason': 'warning_has_no_independent_site'}
        reports[name] = response
    assert digest(binary) == fixture_digest
    assert saved.select(arch=arch)['engine_baseline_sha256'] == program_digest
    pins = {key: image[key] for key in ('image_id', 'arch', 'artifact_sha256')}
    pins.update(slice_sha256=image['sha256'], import_program_sha256=program_digest)
    manifest = {'schema': 'macscope-evidence-leads/1', 'images': [pins], 'leads': [
        {'id': name, 'image_id': image['image_id'], 'kind': 'address', 'value': row['data']['entry_va'],
         'query_job': row['data']['origin']['job_id']} for name, row in reports.items()]}
    manifest_path = root / 'leads.json'
    storage.write_json(manifest_path, manifest)
    offline = dict(os.environ, MACSCOPE_GHIDRA='/nonexistent-stage-b-engine', MACSCOPE_JAVA_HOME='/nonexistent-stage-b-java')
    hidden = binary.with_suffix('.temporarily-unavailable')
    binary.rename(hidden)
    try:
        for name, original in reports.items():
            job = original['data']['origin']['job_id']
            receipt = project / 'jobs' / job / 'query-result.json'
            before = receipt.read_bytes()
            replay = invoke(root, 'replay-' + name, 'jobs', 'resume', job, '--project', project, '--experimental-trusted-input',
                            env=offline, expected=(0,) if name == 'handler' else (6,))
            for key in ('pseudocode', 'instructions', 'control_flow_gaps', 'origin'):
                assert replay['data'].get(key) == original['data'].get(key), (name, key)
            assert receipt.read_bytes() == before
        exports = []
        for index in (1, 2):
            exports.append(invoke(root, 'evidence-' + str(index), 'evidence', '--project', project,
                                  '--leads', manifest_path, '--link-focused', env=offline, expected=(6,)))
        assert exports[0] == exports[1]
        linkage = next(row for row in exports[0]['data']['leads'] if row['lead']['id'] == 'linkage')
        assert any(row['target_entry_va'] == symbols['_owned_handler']
                   for row in linkage['selected_calls']['links']), linkage
    finally:
        hidden.rename(binary)
    summary = {'architecture': arch, 'fixture_sha256': fixture_digest, 'program_sha256': program_digest,
               'binary_unchanged': digest(binary) == fixture_digest, 'application_executed': False,
               'offline_replay': True, 'deterministic_json': True, 'selected_handler_call': True,
               'checks': {name: {'status': row['status'], 'entry_va': row['data']['entry_va'],
                   'gap_kinds': sorted({g['evidence']['classification']['kind']
                       for g in row['data'].get('control_flow_gaps', [])})} for name, row in reports.items()}}
    storage.write_json(root / 'summary.json', summary)
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--arch', choices=('arm64', 'x86_64', 'both'), default='both')
    args = parser.parse_args()
    root = args.output_dir or Path(tempfile.mkdtemp(prefix='macscope-flow-gap.'))
    architectures = ('arm64', 'x86_64') if args.arch == 'both' else (args.arch,)
    print(json.dumps([run(root / arch, arch) for arch in architectures], indent=2))
