#!/usr/bin/env python3
"""Direct full-Ghidra experiment runner, not the macscope CLI.

Own fixtures only. New exclusive run directory every time. No old project
is deleted, no completed JSON replaced, and failures affect aggregate exit.
Each worker receives a case-private sandbox and reads one owned binary.
"""
import argparse
import hashlib
import json
import os
import re
import resource
import selectors
import subprocess
import sys
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
from macscope.engine import terminate_owned as stop_owned
from macscope.macho import read_regular

JAVA = Path('/opt/homebrew/Cellar/openjdk@25/25.0.5.0.3/libexec/openjdk.jdk/Contents/Home')
GHIDRA = Path('/opt/homebrew/opt/ghidra/libexec')
SCRIPTS = ('MacscopeBlindProfile.java', 'MacscopeBaseline.java')
PRIVATE_READ_ROOTS = ('/Users', '/private/tmp', '/private/var/folders', '/Volumes')
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


def child_file_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))


def bounded_command(argv, log, timeout, env=None, max_log_bytes=16 << 20,
                    watch=None, max_output_bytes=64 << 20, limit_child_files=True, cwd=None):
    """Bound whole subprocess group, captured log and watched result file."""
    started = time.monotonic()
    reason = None
    total = 0
    with Path(log).open('xb') as f:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True, env=env, cwd=cwd,
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


def case_policy(directory, build_root):
    root = json.dumps(str(directory))
    private_roots = (*PRIVATE_READ_ROOTS, str(REPO), str(build_root), str(directory.parent))
    private = " ".join(f'(subpath {json.dumps(path)})' for path in dict.fromkeys(private_roots))
    input_path = json.dumps(str(directory / 'input.bin'))
    scripts = json.dumps(str(directory / 'scripts'))
    return (f'(version 1)\n(allow default)\n(deny network*)\n'
            f'(deny file-read-data (require-all (require-any {private}) (require-not (subpath {root}))))\n'
            f'(deny file-write* (require-all (require-not (subpath {root})) '
            f'(require-not (literal "/dev/null"))))\n'
            f'(deny file-write* (literal {input_path}) (subpath {scripts}))\n'
            f'(deny process-exec (subpath {root}))\n')


def case_environment(directory, java):
    for name in ('home', 'settings', 'cache', 'tmp'):
        (directory / name).mkdir()
    jvm = {'user.home': 'home', 'application.settingsdir': 'settings',
           'application.cachedir': 'cache', 'application.tempdir': 'tmp', 'java.io.tmpdir': 'tmp'}
    return {'HOME': str(directory / 'home'), 'TMPDIR': str(directory / 'tmp') + '/',
            'JAVA_HOME': str(java), 'PATH': str(java / 'bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
            'LANG': 'en_US.UTF-8', 'JAVA_TOOL_OPTIONS': ' '.join(
                f'-D{key}={json.dumps(str(directory / name))}' for key, name in jvm.items())}


def verify_case_isolation(sandbox, directory, input_path, sibling, blocked, env):
    # Verify access with the same profile as the worker. An unreadable canary
    # in the supervisor would make a denied read ambiguous.
    for path in blocked:
        with path.open('rb') as stream:
            if not stream.read(1):
                raise ValueError('Isolation probe requires a nonempty control file')
    probe = """
        /bin/cat "$1" >/dev/null || exit 1
        if (: >>"$1") 2>/dev/null || (: >>"$2") 2>/dev/null; then exit 3; fi
        shift 2
        for path do
            if /bin/cat "$path" >/dev/null 2>/dev/null; then exit 2; fi
        done
    """
    result = bounded_command(['/usr/bin/sandbox-exec', '-f', str(sandbox), '/bin/sh', '-c',
                              probe, 'isolation-probe', str(input_path), str(sibling), *map(str, blocked)],
                             directory / 'isolation.log', 10, env, cwd=directory)
    return result


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
    a.build_root = a.build_root.resolve()
    a.runs_root.mkdir(parents=True, exist_ok=True)
    out = a.runs_root.resolve() / a.run_id
    out.mkdir()  # refuses all prior runs, completed or interrupted
    started = time.monotonic()
    records = []
    freeze = []
    ghidra, java = GHIDRA.resolve(), JAVA.resolve()
    sibling_probe = out / 'other-case-canary'
    sibling_probe.write_bytes(b'owned sibling capture control\n')
    manifest_path = a.build_root / 'manifest.json'
    manifest = read_regular(manifest_path, 1024 * 1024) if manifest_path.exists() else None
    expected = {} if manifest is None else {
        (row['config'], row['arch'], row['symbols'], row['name']): row['sha256']
        for row in json.loads(manifest)['artifacts'] if row['container'] == 'thin'
    }
    identity = {'schema': 'macscope-baseline-run/2', 'run_id': a.run_id,
                'limits': {'job_secs': a.job_timeout, 'case_secs': a.case_timeout, 'log_bytes': 16 << 20, 'json_bytes': 64 << 20},
                'isolation': 'macscope-baseline-case/1',
                'ghidra_properties_sha256': sha(GHIDRA / 'Ghidra/application.properties'),
                'native_decompiler_sha256': sha(GHIDRA / 'Ghidra/Features/Decompiler/os/mac_arm_64/decompile'),
                'scripts': {name: sha(REPO / 'analysis/scripts' / name) for name in SCRIPTS},
                'source_revision': subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(),
                'jdk_version': subprocess.check_output([str(JAVA / 'bin/java'), '-version'], stderr=subprocess.STDOUT, text=True).strip(),
                'host_arch': __import__('platform').machine(),
                'build_manifest_sha256': hashlib.sha256(manifest).hexdigest() if manifest is not None else None,
                'runner_sha256': sha(__file__), 'java_home': str(java)}
    exclusive_json(out / 'identity.json', identity)
    for case in a.cases or CASES:
        for kind, rel in [('app', 'CalculatorFixture.app/Contents/MacOS/CalculatorFixture'), ('tool', 'CorpusFixture')]:
            tag = case + '-' + kind
            d = out / ('ghidra-' + tag); d.mkdir()
            config, arch, symbols = case.split('-')
            rec = {'tag': tag, 'condition': 'binary-plus-symbol-table' if symbols == 'sym' else 'binary-only'}
            try:
                source = a.build_root / 'analyst' / case / rel
                inp = d / 'input.bin'
                inp.write_bytes(read_regular(source))
                inp.chmod(0o400)
                rec['input_sha256'] = sha(inp)
                binary_name = 'CalculatorFixture' if kind == 'app' else 'CorpusFixture'
                if manifest is not None and expected.get((config, arch, symbols, binary_name)) != rec['input_sha256']:
                    raise ValueError('Owned binary differs from the recorded fixture manifest')
                (d / 'project').mkdir()
                scripts = d / 'scripts'
                scripts.mkdir()
                for name in SCRIPTS:
                    (scripts / name).write_bytes(read_regular(REPO / 'analysis/scripts' / name))
                    if sha(scripts / name) != identity['scripts'][name]:
                        raise ValueError('Baseline script changed after recording its digest')
                sandbox = d / 'worker.sb'
                sandbox.write_text(case_policy(d, a.build_root))
                rec['sandbox_sha256'] = sha(sandbox)
                env = case_environment(d, java)
                dsym = a.build_root / 'evaluator' / f'{config}-{arch}' / (
                    'CalculatorFixture.app.dSYM' if kind == 'app' else 'CorpusFixture.dSYM')
                debug_binary = dsym / 'Contents/Resources/DWARF' / binary_name
                probes = {'source': REPO / 'fixture/src/calc_core.c', 'unstaged_binary': source,
                          'sibling_case': sibling_probe}
                if debug_binary.is_file():
                    probes['evaluator_dsym'] = debug_binary
                rec['isolation_probe'] = verify_case_isolation(sandbox, d, inp, sibling_probe, probes.values(), env)
                if rec['isolation_probe']['exit_code'] or rec['isolation_probe']['failure']:
                    raise ValueError('Blind capture failed its file isolation probe')
                rec['denied_read_probes'] = sorted(probes)
                baseline = d / 'baseline.json'
                argv = ['/usr/bin/sandbox-exec', '-f', str(sandbox),
                    str(ghidra / 'support/analyzeHeadless'), str(d / 'project'), 'fixture',
                    '-import', str(inp), '-loader', 'MachoLoader', '-loader-loadLibraries', 'false',
                    '-loader-linkExistingProjectLibraries', 'false', '-loader-reexport', 'false',
                    '-preScript', 'MacscopeBlindProfile.java',
                    '-postScript', 'MacscopeBaseline.java', str(baseline), '5000', '30',
                    '-scriptPath', str(scripts), '-log', str(d / 'engine.log'),
                    '-scriptlog', str(d / 'script.log'), '-max-cpu', '4', '-analysisTimeoutPerFile', '540']
                remaining = a.job_timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError('whole experiment timeout')
                rec['engine'] = bounded_command(argv, d / 'headless.log', min(a.case_timeout, remaining),
                                                env, watch=d, cwd=d)
                if rec['engine']['exit_code'] or rec['engine']['failure']:
                    raise ValueError('engine process failed')
                if b'Skipping unsupported -loader-' in (d / 'headless.log').read_bytes():
                    raise ValueError('Pinned loader rejected a safety option')
                rec['counts'] = validate_baseline(baseline)
                freeze.append({'path': str(baseline), 'sha256': sha(baseline)})
                llvm = out / ('llvm-' + tag + '.txt')
                remaining = a.job_timeout - (time.monotonic() - started)
                if remaining <= 0: raise TimeoutError('whole experiment timeout')
                rec['llvm'] = bounded_command(['/usr/bin/xcrun', 'llvm-objdump', '--macho', '--arch=' + arch,
                    '--disassemble', str(inp)], llvm, min(60, remaining))
                if rec['llvm']['exit_code'] or rec['llvm']['failure']:
                    raise ValueError('LLVM reference failed')
                freeze.append({'path': str(llvm), 'sha256': sha(llvm)})
                rec['status'] = 'complete'
            except Exception as e:
                rec.update(status='failed', error=f'{type(e).__name__}: {e}')
            exclusive_json(d / 'result.json', rec); records.append(rec)
            print(tag + ': ' + rec['status'], flush=True)
    exclusive_json(out / 'freeze.json', {'schema': 'macscope-freeze/2', 'artifacts': freeze,
        'classification': 'isolated engine captures; binary-only and binary-plus-symbol-table conditions'})
    summary = {'records': records, 'elapsed_secs': round(time.monotonic() - started, 3),
               'status': 'complete' if all(r['status'] == 'complete' for r in records) else 'failed'}
    exclusive_json(out / 'summary.json', summary)
    print(out)
    return 0 if summary['status'] == 'complete' else 1


if __name__ == '__main__':
    sys.exit(main())
