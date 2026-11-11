"""Actual owned receipt text gate; supply the same six-receipt project/manifest."""
import json
from pathlib import Path
import subprocess
import sys
import integration_native_callback_counterexamples as gate


def run(project, manifest):
    manifest = gate.validate_manifest(manifest)
    before = gate.job_snapshot(project)
    pins = gate.verify_receipts(project, manifest)
    p = manifest['positive']
    common = [sys.executable, '-m', 'macscope', 'disasm', '--project', str(project),
        '--from-import', '--range', p['thunk']['range'], '--receipt', p['thunk']['job_id'],
        '--callback-evidence', '--callback-provenance', '--callback-abi', 'aapcs64',
        '--callback-target-receipt', p['writer']['job_id'],
        '--callback-invocation-receipt', p['invocation']['job_id'],
        '--callback-context-register', 'x20', '--callback-invocation-fallthrough',
        '--callback-writer-call-obligations', '--ghidra', '/nonexistent/ghidra',
        '--java-home', '/nonexistent/java']
    texts = {}
    for name in ('positive', *gate.CASES):
        assignment = p['assignment'] if name == 'positive' else manifest['negative'][name]
        args = common + ['--callback-assignment-receipt', assignment['job_id']]
        results = {}
        for format_ in ('json', 'text'):
            command = args + ['--format', format_]
            outputs = [subprocess.run(command, capture_output=True, text=True,
                       check=True, timeout=60).stdout for _ in range(2)]
            gate.require(outputs[0] == outputs[1], 'Nondeterministic output')
            results[format_] = outputs[0]
        comp = gate.check_result(manifest, name, json.loads(results['json']), pins)
        diagnostic = comp['assignment_diagnostic']
        reason = {'positive':'unique_matching_pair_observed',
                  'overwritten_target':'no_matching_address_store',
                  'unknown_target':'no_address_valued_store'}[name]
        gate.require(diagnostic['reason'] == reason, 'Incorrect assignment diagnostic')
        gate.require(diagnostic['selection'] == assignment['selection'], 'Diagnostic selection changed')
        gate.require(diagnostic['source_envelope_sha256'] == comp['role_identities']['assignment']['source_envelope_sha256'], 'Diagnostic receipt identity changed')
        gate.require(diagnostic['counts']['stores'] == 2 and diagnostic['omitted_stores'] == 0, 'Diagnostic store accounting changed')
        text = results['text']
        summary = text[text.index('Callback evidence (bounded summary'):]
        gate.require(len(summary.encode()) <= 16384 and len(summary.splitlines()) <= 64, 'Text budget exceeded')
        for value in ('Analysis status: inconclusive', 'Composition candidate: '+comp['candidate_status'],
                      'Application writer attribution: unknown', 'runtime execution: unknown',
                      'persistence: unknown', 'fallthrough=nonzero', 'side effects unknown', '--format json'):
            gate.require(value in summary, 'Missing text evidence: '+value)
        gate.require('Assignment diagnostic: '+reason in summary, 'Diagnostic absent from text')
        if name != 'positive':
            gate.require('unique_paired_assignment_not_proven' in summary, 'Missing negative gap')
        stores = [s for s in comp['independent_evidence']['assignment']['sites'] if s['kind']=='memory_store']
        v = stores[0]['value']
        expected = v['value'] if v['kind']=='address' else v['register']
        gate.require('value='+v['kind']+':'+expected in summary, 'Missing observed assignment target')
        texts[name] = text
    gate.require(len(set(texts.values())) == 3, 'Three native outcomes render identically')
    gate.require(gate.job_snapshot(project) == before, 'Replay mutated jobs')
    print('PASS: native text distinguishes conditional positive and both negatives; JSON gate preserved; immutable deterministic engine-free replay')


if __name__ == '__main__':
    run(Path(sys.argv[1]).resolve(), gate.bounded_json(Path(sys.argv[2]), gate.MAX_MANIFEST)[0])
