#!/usr/bin/env python3
"""Measure separate owned focused-import CLI queries and offline receipt replay.

This is a measurement driver, not a product batch interface. It never analyzes
an image or executes the compiled fixture. Raw samples remain private.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

from macscope import focused, storage
from macscope.schema import validate_envelope

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ('_owned_handler', '_owned_linkage', '_owned_wrapper_named', '_owned_internal', '_owned_boundary')
TRUST = '--experimental-trusted-input'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def summarize(values):
    """No percentile claim from fewer than 20 samples; no performance gate."""
    if not values or any(type(x) not in (float, int) or not math.isfinite(x) or x < 0 for x in values):
        raise ValueError('Expected finite nonnegative samples')
    ordered = sorted(values)
    result = {'samples': len(values), 'minimum_seconds': ordered[0],
              'median_seconds': statistics.median(ordered), 'maximum_seconds': ordered[-1]}
    if len(values) >= 20:
        result['p95_seconds'] = ordered[math.ceil(len(values) * .95) - 1]
    return result


def worker_metrics(job, raw, entry):
    """Retain independently reported intervals, never add nested durations."""
    if job['status'] != 'complete' or job['selected_entry'] != entry:
        raise ValueError('Worker did not complete the selected entry')
    if raw['validation']['headless_analysis_enabled'] is not False:
        raise ValueError('Whole-image analysis was enabled')
    timing = raw['decompiler_timing']
    opening, calls = timing['open_program'], timing['calls']
    if not opening or not opening['opened'] or len(calls) != 1 or calls[0]['entry'] != entry:
        raise ValueError('Expected one decompiler open and one exact selected call')
    if job['decompiler_timing'] != {'open_program': opening, 'call_count': 1,
                                  'total_call_ns': calls[0]['elapsed_ns']}:
        raise ValueError('Raw and manifest timing differ')
    startup = job['startup']
    if startup['status'] != 'ready':
        raise ValueError('Readiness not confirmed')
    return {'worker_seconds': job['elapsed_seconds'],
            'launch_to_ready_seconds': startup['observed_seconds'],
            'ghidra_startup_seconds': startup['ghidra_reported_ms'] / 1000,
            'decompiler_open_program_seconds': opening['elapsed_ns'] / 1e9,
            'decompile_call_seconds': calls[0]['elapsed_ns'] / 1e9,
            'program_database_open_seconds': None, 'receipt_publication_seconds': None}


def verify_replay(original, replayed, job_id):
    data = dict(replayed['data'])
    if data.pop('resumed_from', None) != job_id or data.pop('reused_restart', None) is not True:
        raise ValueError('Replay was not a reused saved receipt')
    if dict(replayed, command=original['command'], data=data) != original:
        raise ValueError('Replay changed captured evidence or status')


def source_identity():
    files = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sorted((ROOT / 'src').rglob('*'))
             if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}
    return {'runtime_files_sha256': storage.identity(files), 'runtime_files': files,
            'runner_sha256': sha(Path(__file__).read_bytes())}


def benchmark(args):
    if sys.flags.optimize:
        raise ValueError('Run without Python optimization; measurement integrity assertions are required')
    output = args.output_dir.absolute()
    if output.parent.resolve() != output.parent or not any(output.is_relative_to(root) and output != root
            for root in (Path(tempfile.gettempdir()).resolve(), Path('/tmp').resolve())):
        raise ValueError('Use a canonical new directory under the system temporary directory')
    output.mkdir(mode=0o700)
    report = {'schema': 'macscope-focused-import-benchmark/1', 'status': 'running', 'rounds': args.runs,
              'source': source_identity(), 'host': {'architecture': platform.machine(),
                  'macos': platform.mac_ver()[0], 'python': platform.python_version()},
              'method': {'entry_order': list(TARGETS), 'serial': True, 'warmup_discarded': 0,
                  'cache': 'OS caches warm naturally; first launch retained',
                  'database_open': 'unmeasured: no isolated timer in pinned runtime',
                  'receipt_publication': 'unmeasured: included in CLI wall time',
                  'export_publication': 'combined evidence CLI wall time, not isolated disk publication',
                  'intervals': 'nested intervals must not be summed',
                  'replay': 'saved evidence replay, not fresh analysis'},
              'architectures': {}, 'commands': []}
    for key, name in [('memory_bytes', 'hw.memsize'), ('cpu', 'machdep.cpu.brand_string')]:
        value = subprocess.check_output(['/usr/sbin/sysctl', '-n', name], text=True).strip()
        report['host'][key] = int(value) if key == 'memory_bytes' else value
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONDONTWRITEBYTECODE='1')
    offline = dict(env, MACSCOPE_GHIDRA='/nonexistent-stage-d-engine', MACSCOPE_JAVA_HOME='/nonexistent-stage-d-java')

    def save():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    def invoke(label, *words, expected=(0, 6), environment=env, format='json', target=None):
        command = [sys.executable, '-m', 'macscope', *map(str, words), '--format', format]
        if target is not None:
            command += ['--output', str(target)]
        started = time.monotonic_ns()
        proc = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, timeout=210)
        wall = (time.monotonic_ns() - started) / 1e9
        index = len(report['commands']) + 1
        (output / f'{index:04d}.stdout').write_bytes(proc.stdout)
        (output / f'{index:04d}.stderr').write_bytes(proc.stderr)
        report['commands'].append({'label': label, 'argv': command[3:], 'exit': proc.returncode,
                                   'wall_seconds': wall})
        if proc.returncode not in expected:
            raise RuntimeError(f'{label}: exit {proc.returncode}; capture {index:04d}')
        data = target.read_bytes() if target is not None else proc.stdout
        if format == 'json':
            response = json.loads(data)
            validate_envelope(response)
            return response, wall
        return data, wall

    try:
        for arch in (('arm64', 'x86_64') if args.arch == 'both' else (args.arch,)):
            root = output / arch
            root.mkdir(mode=0o700)
            suffix = 'Arm64' if arch == 'arm64' else 'X86_64'
            source = ROOT / 'fixture' / 'flow-gap-evidence' / ('OwnedFlowGap' + suffix + '.s')
            binary = root / ('OwnedFlowGap-' + arch + '.dylib')
            compiler = ['/usr/bin/xcrun', 'clang', '-arch', arch, '-dynamiclib', str(source), '-o', str(binary)]
            built = subprocess.run(compiler, capture_output=True, timeout=60)
            (root / 'build.stderr').write_bytes(built.stderr)
            if built.returncode:
                raise RuntimeError('Owned fixture compilation failed')
            nm = subprocess.check_output(['/usr/bin/xcrun', 'nm', '-n', str(binary)], text=True)
            (root / 'nm.txt').write_text(nm)
            symbols = {}
            for line in nm.splitlines():
                fields = line.split()
                if len(fields) == 3 and fields[2] in TARGETS:
                    if fields[2] in symbols:
                        raise ValueError('Duplicate selected symbol')
                    symbols[fields[2]] = hex(int(fields[0], 16))
            if set(symbols) != set(TARGETS) or len(set(symbols.values())) != 5:
                raise ValueError('Expected five unique exact owned linker entries')
            for label, words in [('disassembly', ['otool', '-tvV']), ('load_commands', ['otool', '-l'])]:
                (root / (label + '.txt')).write_bytes(subprocess.check_output(['/usr/bin/xcrun', *words, str(binary)]))
            project = root / 'project'
            invoke(arch + ':create', 'project', 'create', project, expected=(0,))
            imported, _ = invoke(arch + ':import', 'import', binary, '--project', project, '--arch', arch,
                                 TRUST, '--timeout', '180', expected=(0,))
            saved = storage.Project(project)
            image = saved.select(arch=arch)
            assert image['active_analysis'] is None
            pins = {key: image[key] for key in ('image_id', 'arch', 'artifact_sha256')}
            pins.update(slice_sha256=image['sha256'], import_program_sha256=image['engine_baseline_sha256'])
            extents = {name: focused.select(saved, image, symbols[name])[0] for name in TARGETS}
            record = {'pins': pins, 'fixture_sha256': sha(binary.read_bytes()),
                      'fixture_source_sha256': sha(source.read_bytes()), 'compiler_argv': compiler,
                      'symbols': symbols, 'extents': extents, 'samples': [], 'round_samples': []}
            report['architectures'][arch] = record
            scope = ('--project', project, '--image', image['image_id'], '--arch', arch)
            invoke(arch + ':verify-before', 'status', '--project', project, '--verify-programs',
                   environment=offline, expected=(0,))
            seen_job_ids = {imported['data'][0]['job_id']}
            for number in range(1, args.runs + 1):
                originals = {}
                rows = []
                for name in TARGETS:
                    original, wall = invoke(f'{arch}:{number}:focused:{name}', 'decompile', *scope,
                        '--address', symbols[name], '--from-import', TRUST, '--timeout', '150',
                        '--startup-timeout', '60', '--function-timeout', '25')
                    function = original['data']
                    assert original['analysis_id'] is None
                    assert function['entry_va'] == symbols[name]
                    assert function['origin']['extent']['program_sha256'] == pins['import_program_sha256']
                    proof, payload = focused.select(saved, image, symbols[name])
                    focused.verify_instructions(proof, payload, function)
                    job_id = function['origin']['job_id']
                    if job_id in seen_job_ids:
                        raise ValueError('Focused command reused an existing job instead of a fresh query')
                    seen_job_ids.add(job_id)
                    job_dir = project / 'jobs' / job_id
                    job = json.loads((job_dir / 'job.json').read_bytes())
                    raw = json.loads((job_dir / 'bridge.json').read_bytes())
                    metrics = worker_metrics(job, raw, symbols[name])
                    dependencies = {k: v for k, v in job['dependencies'].items() if k not in ('ghidra_path', 'java_home')}
                    assert report.setdefault('dependencies', dependencies) == dependencies
                    assert report.setdefault('worker_limits', job['limits']) == job['limits']
                    receipt = job_dir / 'query-result.json'
                    row = {'round': number, 'name': name, 'entry_va': symbols[name], 'job_id': job_id,
                           'status': original['status'], 'decompile_status': function['decompile_status'],
                           'focused_wall_seconds': wall, **metrics, 'receipt_sha256': sha(receipt.read_bytes())}
                    rows.append(row)
                    originals[name] = original
                before_jobs = sorted(p.name for p in (project / 'jobs').iterdir())
                absent = binary.with_suffix('.unavailable')
                binary.rename(absent)
                try:
                    for row in rows:
                        replayed, wall = invoke(f'{arch}:{number}:replay:{row["name"]}', 'jobs', 'resume', row['job_id'],
                                                '--project', project, TRUST, environment=offline)
                        original = originals[row['name']]
                        verify_replay(original, replayed, row['job_id'])
                        receipt = project / 'jobs' / row['job_id'] / 'query-result.json'
                        assert sha(receipt.read_bytes()) == row['receipt_sha256']
                        row['replay_wall_seconds'] = wall
                    leads = {'schema': 'macscope-evidence-leads/1', 'images': [pins], 'leads': [
                        {'id': row['name'], 'image_id': image['image_id'], 'kind': 'address',
                         'value': row['entry_va'], 'query_job': row['job_id']} for row in rows]}
                    manifest = root / f'leads-{number:02}.json'
                    manifest.write_text(json.dumps(leads) + '\n')
                    exports = {}
                    for fmt in ('json', 'html'):
                        destination = root / f'evidence-{number:02}.{fmt}'
                        _, elapsed = invoke(f'{arch}:{number}:export:{fmt}', 'evidence', '--project', project,
                            '--leads', manifest, '--link-focused', environment=offline, format=fmt, target=destination)
                        exports[fmt + '_export_wall_seconds'] = elapsed
                        # Independent second publication is checked for determinism, not included in timing summary.
                        repeat = root / f'evidence-{number:02}-repeat.{fmt}'
                        invoke(f'{arch}:{number}:export-repeat:{fmt}', 'evidence', '--project', project,
                            '--leads', manifest, '--link-focused', environment=offline, format=fmt, target=repeat)
                        assert destination.read_bytes() == repeat.read_bytes()
                    assert sorted(p.name for p in (project / 'jobs').iterdir()) == before_jobs
                finally:
                    absent.rename(binary)
                assert sha(binary.read_bytes()) == record['fixture_sha256']
                assert saved.select(**{'image': image['image_id'], 'arch': arch}) == image
                record['samples'].extend(rows)
                record['round_samples'].append({'round': number,
                    'five_focused_wall_seconds': sum(row['focused_wall_seconds'] for row in rows),
                    'five_replay_wall_seconds': sum(row['replay_wall_seconds'] for row in rows), **exports})
                save()
                print(f'{arch}: round {number}/{args.runs} complete', flush=True)
            invoke(arch + ':verify-after', 'status', '--project', project, '--verify-programs',
                   environment=offline, expected=(0,))
            record['status_counts'] = dict(Counter(row['status'] for row in record['samples']))
            record['summary'] = {}
            for name in TARGETS:
                values = [row for row in record['samples'] if row['name'] == name]
                record['summary'][name] = {key: summarize([row[key] for row in values]) for key in values[0]
                    if key.endswith('_seconds') and values[0][key] is not None}
            record['round_summary'] = {key: summarize([row[key] for row in record['round_samples']])
                                       for key in record['round_samples'][0] if key != 'round'}
            record['actual_job_count'] = len(list((project / 'jobs').iterdir()))
            assert record['actual_job_count'] == 1 + 5 * args.runs
        assert source_identity() == report['source']
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--arch', choices=('arm64', 'x86_64', 'both'), default='both')
    parser.add_argument('--runs', type=int, choices=range(1, 101), default=20)
    parser.add_argument('--experimental-trusted-input', action='store_true')
    args = parser.parse_args()
    if not args.experimental_trusted_input:
        parser.error('Explicit --experimental-trusted-input is required')
    report = benchmark(args)
    print(json.dumps({arch: data['round_summary'] for arch, data in report['architectures'].items()}, indent=2))


if __name__ == '__main__':
    main()
