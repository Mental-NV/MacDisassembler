#!/usr/bin/env python3
"""Opt-in owned-fixture comparison. Never accepts an external target or deletes runs."""
import argparse
import hashlib
import json
import os
import platform
import signal
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
NAMES = {'_owned_add', '_owned_select', '_owned_mix'}


def run(output, rounds):
    from macscope import engine
    from macscope.schema import validate_envelope
    from macscope.storage import Project
    output.mkdir(mode=0o700)  # Must be new. Never overwrite previous evidence.
    env = dict(os.environ, PYTHONPATH=str(ROOT/'src'), PYTHONDONTWRITEBYTECODE='1')
    commands = []

    def command(argv, expected=(0,)):
        start = time.monotonic()
        number = len(commands)+1
        proc = subprocess.Popen(list(map(str, argv)), env=env, cwd=ROOT,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        timed_out, interrupted, forced, drain_timeout = False, False, False, False
        try:
            stdout, stderr = proc.communicate(timeout=1200)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as stop:
            timed_out = isinstance(stop, subprocess.TimeoutExpired)
            interrupted = isinstance(stop, KeyboardInterrupt)
            # Give the CLI a chance to execute its owned-worker teardown finally.
            try:
                proc.send_signal(signal.SIGINT)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = proc.communicate(timeout=30)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                forced = True
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired as drain:
                    drain_timeout = True
                    stdout, stderr = drain.output or b'', drain.stderr or b''
                    # Descendants can retain pipe handles even after supervisor exit.
                    proc.stdout.close()
                    proc.stderr.close()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
        elapsed = time.monotonic()-start
        (output/f'{number:03}.stdout').write_bytes(stdout)
        (output/f'{number:03}.stderr').write_bytes(stderr)
        commands.append({'argv':list(map(str, argv)), 'exit':proc.returncode,
                         'wall_seconds':elapsed, 'timed_out':timed_out, 'interrupted':interrupted,
                         'pipe_drain_timed_out':drain_timeout,
                         'forced_supervisor_kill':forced,
                         'teardown_verification':'not_checked' if timed_out or interrupted else 'not_applicable'})
        (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if timed_out or interrupted:
            raise RuntimeError(f'Command {number} stopped after timeout/interruption; evidence retained, native teardown unverified; stop and inspect before retrying')
        if proc.returncode not in expected:
            raise RuntimeError(f'Command {number} failed with exit {proc.returncode}; inspect saved stderr/stdout')
        return stdout, elapsed

    def cli(*args, expected=(0,)):
        raw, elapsed = command([sys.executable,'-m','macscope',*args,'--json'],expected)
        result = json.loads(raw)
        validate_envelope(result)
        return result, elapsed

    compiler, _ = command(['xcrun','clang','--version'])
    runner_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    fixture_sha = hashlib.sha256((ROOT/'fixture/batch/owned_batch.c').read_bytes()).hexdigest()
    command(['xcrun','clang','-O0','-fno-inline','-arch','arm64',
             ROOT/'fixture/batch/owned_batch.c','-o',output/'owned'])
    baseline = output/'baseline'
    cli('project','create',baseline)
    cli('import',output/'owned','--project',baseline,'--arch','arm64','--trust-input')
    cli('analyze','--project',baseline,'--trust-input',expected=(0,6))
    project = Project(baseline)
    image = project.select()
    snapshot, active = project.snapshot(image)
    selected = [f for f in snapshot['functions'] if NAMES & {n['name'] for n in f['names']}]
    if len(selected) != 3 or {n['name'] for f in selected for n in f['names']} & NAMES != NAMES:
        raise RuntimeError('Owned fixture selection was not recovered exactly')
    entries = sorted([f['entry_va'] for f in selected],key=lambda e:int(e,16))
    source = engine.analyzed_program(project,active)
    original_digest = engine.tree_digest(source)
    trials = []
    for iteration in range(rounds):
        for size in ([1,3] if iteration%2==0 else [3,1]):
            trial = output/f'trial-{iteration+1}-size-{size}'
            shutil.copytree(baseline,trial)
            args = ['batch-export','--project',trial,'--batch-size',str(size),
                    '--reserve-mib','128','--trust-input']
            for entry in entries:args += ['--entry',entry]
            result, elapsed = cli(*args,expected=(6,))
            data = result['data']
            if data['selected_count'] != 3 or data['outcomes'] != {'complete':3}:
                raise RuntimeError('Incomplete batch output; no throughput comparison')
            export = Path(data['path'])
            manifest = json.loads((export/'manifest.json').read_text())
            records = [json.loads((export/'functions'/f'{e}.json').read_text()) for e in entries]
            job_ids = sorted({r['job_id'] for r in records})
            jobs = [json.loads((trial/'jobs'/j/'job.json').read_text()) for j in job_ids]
            if len(job_ids) != 3//size or any((trial/'jobs'/j/'program').exists() for j in job_ids):
                raise RuntimeError('Unexpected worker count or leftover successful Program copy')
            trial_project = Project(trial)
            trial_image = trial_project.select()
            trial_snapshot, trial_active = trial_project.snapshot(trial_image)
            if (engine.tree_digest(engine.analyzed_program(trial_project,trial_active)) != original_digest
                    or (trial_snapshot,trial_active) != (snapshot,active)):
                raise RuntimeError('Analyzed baseline changed')
            trials.append({'round':iteration+1,'batch_size':size,'wall_seconds':elapsed,
                           'functions':[r['function'] for r in records],
                           'manifest':manifest,'job_count':len(job_ids),
                           'decompiler_timings':[j.get('decompiler_timing') for j in jobs],
                           'export_ref':str(export.relative_to(output))})
    if engine.tree_digest(source) != original_digest:
        raise RuntimeError('Original baseline changed')
    reference = trials[0]['functions']
    identical = all(t['functions']==reference for t in trials)
    identity_keys = ('image_id','analysis_id','bridge_sha256','program_sha256','runtime','entries','limits','semantics')
    # max_functions is intentionally size-specific in worker limits; all other limits must match.
    def comparable_manifest(t):
        m = {k:t['manifest'][k] for k in identity_keys}
        m['limits'] = {k:v for k,v in m['limits'].items() if k != 'max_functions'}
        return m
    identities = all(comparable_manifest(t)==comparable_manifest(trials[0]) for t in trials)
    timings = {str(size):[t['wall_seconds'] for t in trials if t['batch_size']==size] for size in (1,3)}
    medians = {size:statistics.median(values) for size,values in timings.items()}
    report = {'schema':'macscope-owned-batch-comparison/1',
              'input_sha256':hashlib.sha256((output/'owned').read_bytes()).hexdigest(),
              'runner_sha256':runner_sha, 'fixture_source_sha256':fixture_sha,
              'python_version':sys.version, 'platform':platform.platform(),
              'compiler_version':compiler.decode('utf-8',errors='replace'),
              'entries':entries,'rounds':rounds,'all_function_records_equal':identical,
              'identities_equal_except_chunk_size':identities,'wall_seconds':timings,
              'median_wall_seconds':medians,
              'ratio_size1_over_size3':medians['1']/medians['3'] if identical and identities else None,
              'baseline_preserved':True,'trials':trials,
              'limitations':['Tiny owned fixture, warm host, alternating fixed order; not TickTick performance.',
                             'Compares analyzed-image batch sizes, not focused-import or fresh single decompile commands.',
                             'Wall time includes CLI/runtime validation/copy/publication; intervals overlap and are not added.',
                             'Equal pseudocode is not proof of semantic equivalence or complete discovery.',
                             'No RSS measurement or cold-cache control; small sample, no p95 estimate.']}
    (output/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k != 'trials'},indent=2))
    if not identical or not identities:
        raise RuntimeError('Outputs/identities differ; measurement retained, no speedup claim')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',action='store_true',required=True,help='Explicitly run native analysis of the repository-owned fixture')
    p.add_argument('--out',type=Path,required=True,help='New physical output directory; all evidence retained')
    p.add_argument('--rounds',type=int,choices=range(1,6),default=3)
    args = p.parse_args()
    try:
        run(args.out.absolute(),args.rounds)
    except Exception as exc:
        # Do not overwrite anything if --out already existed before this invocation.
        print(f'Batch experiment stopped: {exc}',file=sys.stderr)
        raise
