#!/usr/bin/env python3
"""Direct full-Ghidra experiment runner, not the macscope CLI.

Own fixtures only. New exclusive run directory every time. No old project
is deleted, no completed JSON replaced, and failures affect aggregate exit.
Network-denied seatbelt is required; filesystem confinement is NOT provided.
"""
import argparse
import hashlib
import json
import os
import re
import resource
import selectors
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
JAVA = Path('/opt/homebrew/Cellar/openjdk@25/25.0.5.0.3/libexec/openjdk.jdk/Contents/Home')
GHIDRA = Path('/opt/homebrew/opt/ghidra/libexec')
CASES = [f'{cfg}-{arch}-{state}' for cfg in ('DebugAnalysis', 'ReleaseAnalysis')
         for arch in ('arm64', 'x86_64') for state in ('sym', 'stripped')]


def sha(p):
    h = hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def exclusive_json(path, value):
    # Publish only after an fsynced complete serialization; link refuses overwrite.
    path = Path(path)
    temporary = path.with_name(path.name + '.partial')
    with temporary.open('x') as f:
        json.dump(value, f, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
    os.link(temporary, path)
    temporary.unlink()


def stop_owned(proc):
    # A new session/process group was created for this child only.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            break
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            continue
    proc.wait()


def child_file_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))


def bounded_command(argv, log, timeout, env=None, max_log_bytes=16 << 20,
                    watch=None, max_output_bytes=64 << 20, limit_child_files=True):
    """Bound whole subprocess group, captured log and watched result file."""
    started = time.monotonic()
    reason = None
    total = 0
    with Path(log).open('xb') as f:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True, env=env,
                                preexec_fn=child_file_limit if limit_child_files else None)
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        try:
            while sel.get_map():
                elapsed = time.monotonic() - started
                if elapsed > timeout:
                    reason = 'whole_command_timeout'; stop_owned(proc)
                if watch and watch.exists() and sum(p.stat().st_size for p in watch.iterdir()
                                                   if p.is_file() and p.suffix in {'.json', '.partial'}) > max_output_bytes:
                    reason = 'result_size_limit'; stop_owned(proc)
                for key, _ in sel.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        sel.unregister(key.fileobj); continue
                    remaining = max_log_bytes - total
                    f.write(chunk[:max(remaining, 0)]); total += min(len(chunk), max(remaining, 0))
                    if len(chunk) > remaining:
                        reason = 'log_size_limit'; stop_owned(proc)
                if reason:
                    break
            proc.wait(timeout=max(0.1, timeout - (time.monotonic() - started)))
        except BaseException:
            stop_owned(proc)
            raise
        finally:
            sel.close(); proc.stdout.close()
    return {'argv': [str(a) for a in argv], 'exit_code': proc.returncode,
            'elapsed_secs': round(time.monotonic() - started, 3), 'failure': reason,
            'log_bytes': total, 'log_sha256': sha(log)}


def validate_baseline(path):
    if path.stat().st_size > 64 << 20:
        raise ValueError('baseline exceeds 64MiB')
    d = json.loads(path.read_text())
    if d.get('schema') != 'macscope-baseline/2' or not d.get('decompiler_opened'):
        raise ValueError('missing schema/failed native openProgram')
    if d.get('analysis_timeout_occurred'):
        raise ValueError('Ghidra auto-analysis timeout')
    if d.get('blind_profile') != 'binary-only-v2':
        raise ValueError('trusted pre-script did not complete')
    opts = d.get('effective_analysis_options', {})
    if opts.get('DWARF') != 'false':
        raise ValueError('DWARF disablement absent')
    for k, v in opts.items():
        if '.' not in k and re.search('dwarf|pdb|dsym|source|^external symbol resolver$', k, re.I) and v != 'false':
            raise ValueError(f'blind analyzer enabled: {k}')
    functions = d['functions']
    if int(d['function_count_enumerated']) != len(functions) or not functions:
        raise ValueError('function count invalid')
    if d.get('functions_truncated') is not False:
        raise ValueError('function enumeration truncated')
    names = {'complete': 'completed', 'failed': 'failed', 'timeout': 'timed_out',
             'cancelled': 'cancelled', 'not_requested': 'not_requested'}
    counts = {name: 0 for name in names}
    entries = set()
    for f in functions:
        status = f['decompile_status']; counts[status] += 1
        if f['entry_va'] in entries:
            raise ValueError('duplicate function entry')
        entries.add(f['entry_va'])
        if status == 'complete' and not f.get('pseudocode'):
            raise ValueError('complete without pseudocode')
        for facet in ['body_ranges_error', 'instruction_error', 'cfg_error', 'xrefs_to_error', 'xrefs_from_error']:
            if f.get(facet):
                raise ValueError('facet export error: ' + facet)
        if f['instruction_count'] != len(f['instructions']) or f['block_count'] != len(f['blocks']):
            raise ValueError('facet count mismatch')
    for name, suffix in names.items():
        if counts[name] != int(d['decompile_summary_' + suffix]):
            raise ValueError('summary count mismatch: ' + name)
    if int(d['decompile_summary_attempted']) != len(functions) - counts['not_requested']:
        raise ValueError('attempted count mismatch')
    if counts['failed'] or counts['timeout'] or counts['cancelled']:
        raise ValueError('incomplete decompile: ' + str(counts))
    return counts


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('cases', nargs='*', choices=CASES)
    p.add_argument('--build-root', type=Path, default=REPO / 'build')
    p.add_argument('--runs-root', type=Path, default=REPO / 'build/baseline-runs')
    p.add_argument('--run-id', default=time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8])
    p.add_argument('--job-timeout', type=float, default=1800)
    p.add_argument('--case-timeout', type=float, default=600)
    a = p.parse_args(argv)
    if not re.fullmatch('[A-Za-z0-9_-]{1,80}', a.run_id) or min(a.job_timeout, a.case_timeout) <= 0:
        p.error('invalid run id or timeout')
    os.umask(0o077)
    a.runs_root.mkdir(parents=True, exist_ok=True)
    out = a.runs_root / a.run_id
    out.mkdir()  # refuses all prior runs, completed or interrupted
    started = time.monotonic()
    records = []
    freeze = []
    env = dict(os.environ, JAVA_HOME=str(JAVA), PATH=str(JAVA / 'bin') + ':' + os.environ['PATH'])
    env.pop('_JAVA_OPTIONS', None); env.pop('JDK_JAVA_OPTIONS', None)
    env['JAVA_TOOL_OPTIONS'] = f'-Dapplication.settingsdir={out}/settings -Dapplication.cachedir={out}/cache -Dapplication.tempdir={out}/tmp'
    identity = {'schema': 'macscope-baseline-run/2', 'run_id': a.run_id,
                'limits': {'job_secs': a.job_timeout, 'case_secs': a.case_timeout, 'log_bytes': 16 << 20, 'json_bytes': 64 << 20},
                'isolation': 'sandbox-exec deny network; no filesystem confinement; own fixture inputs only',
                'ghidra_properties_sha256': sha(GHIDRA / 'Ghidra/application.properties'),
                'native_decompiler_sha256': sha(GHIDRA / 'Ghidra/Features/Decompiler/os/mac_arm_64/decompile'),
                'scripts': {f.name: sha(f) for f in (REPO / 'analysis/scripts').glob('*.java')},
                'source_revision': subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(),
                'jdk_version': subprocess.check_output([str(JAVA / 'bin/java'), '-version'], stderr=subprocess.STDOUT, text=True).strip(),
                'host_arch': __import__('platform').machine(),
                'build_manifest_sha256': sha(a.build_root / 'manifest.json') if (a.build_root / 'manifest.json').exists() else None,
                'runner_sha256': sha(__file__), 'java_home': str(JAVA), 'java_tool_options': env['JAVA_TOOL_OPTIONS']}
    exclusive_json(out / 'identity.json', identity)
    for case in a.cases or CASES:
        for kind, rel in [('app', 'CalculatorFixture.app/Contents/MacOS/CalculatorFixture'), ('tool', 'CorpusFixture')]:
            tag = case + '-' + kind
            d = out / ('ghidra-' + tag); d.mkdir()
            rec = {'tag': tag}
            try:
                source = a.build_root / 'analyst' / case / rel
                # Binary snapshot only. No sources/dSYMs/maps supplied to engine.
                inp = d / 'input.bin'; inp.write_bytes(source.read_bytes())
                rec['input_sha256'] = sha(inp)
                (d / 'project').mkdir()
                baseline = d / 'baseline.json'
                argv = ['/usr/bin/sandbox-exec', '-f', str(REPO / 'analysis/nonet.sb'),
                    str(GHIDRA / 'support/analyzeHeadless'), str(d / 'project'), 'fixture',
                    '-import', str(inp), '-loader', 'MachoLoader', '-loader-loadLibraries', 'false',
                    '-loader-linkExistingProjectLibraries', 'false',
                    '-preScript', 'MacscopeBlindProfile.java',
                    '-postScript', 'MacscopeBaseline.java', str(baseline), '5000', '30',
                    '-scriptPath', str(REPO / 'analysis/scripts'), '-log', str(d / 'engine.log'),
                    '-scriptlog', str(d / 'script.log'), '-max-cpu', '4', '-analysisTimeoutPerFile', '540']
                remaining = a.job_timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError('whole experiment timeout')
                rec['engine'] = bounded_command(argv, d / 'headless.log', min(a.case_timeout, remaining), env, watch=d)
                if rec['engine']['exit_code'] or rec['engine']['failure']:
                    raise ValueError('engine process failed')
                rec['counts'] = validate_baseline(baseline)
                freeze.append({'path': str(baseline.relative_to(REPO)), 'sha256': sha(baseline)})
                arch = 'arm64' if '-arm64-' in case else 'x86_64'
                llvm = out / ('llvm-' + tag + '.txt')
                remaining = a.job_timeout - (time.monotonic() - started)
                if remaining <= 0: raise TimeoutError('whole experiment timeout')
                rec['llvm'] = bounded_command(['xcrun', 'llvm-objdump', '--macho', '--arch=' + arch,
                    '--disassemble', str(inp)], llvm, min(60, remaining), env)
                if rec['llvm']['exit_code'] or rec['llvm']['failure']:
                    raise ValueError('LLVM reference failed')
                freeze.append({'path': str(llvm.relative_to(REPO)), 'sha256': sha(llvm)})
                rec['status'] = 'complete'
            except Exception as e:
                rec.update(status='failed', error=f'{type(e).__name__}: {e}')
            exclusive_json(d / 'result.json', rec); records.append(rec)
            print(tag + ': ' + rec['status'], flush=True)
    exclusive_json(out / 'freeze.json', {'schema': 'macscope-freeze/2', 'artifacts': freeze,
        'classification': 'binary-only engine inputs; source-aware evaluator; filesystem isolation absent'})
    summary = {'records': records, 'elapsed_secs': round(time.monotonic() - started, 3),
               'status': 'complete' if all(r['status'] == 'complete' for r in records) else 'failed'}
    exclusive_json(out / 'summary.json', summary)
    print(out)
    return 0 if summary['status'] == 'complete' else 1


if __name__ == '__main__':
    sys.exit(main())
