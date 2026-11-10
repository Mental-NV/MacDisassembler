"""Exact full-headless engine, isolated user state and owned-process jobs.

Experimental trusted-owned inputs only. Seatbelt denies network and other
user-home data; this is NOT a complete hostile-input filesystem sandbox.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import stat
import subprocess
import time
import uuid
from copy import deepcopy
from . import callee_parameters, direct_signatures, dispatch_returns, engine_checks, flow_boundaries, forwarded_returns, jobs, scalar_signatures, switch_tables, worker_lifecycle
from .annotations import MAX_TYPE_HINTS
from .errors import Error
from .storage import canonical, identity, write_json
from .macho import read_regular

GHIDRA = '/opt/homebrew/opt/ghidra/libexec'
JAVA = '/opt/homebrew/Cellar/openjdk@25/25.0.5.0.3/libexec/openjdk.jdk/Contents/Home'
BRIDGE = Path(__file__).parent/'bridge'
BRIDGE_VERSION = '1.7.0'
SIGNATURE_RECOVERIES = {
    'dispatch_return_recovery': (dispatch_returns, 'dispatch-return'),
    'direct_signature_recovery': (direct_signatures, 'direct-signatures'),
    'scalar_signature_recovery': (scalar_signatures, 'scalar-signatures'),
    'callee_parameter_recovery': (callee_parameters, 'callee-parameters'),
    'forwarded_return_recovery': (forwarded_returns, 'forwarded-return'),
    'switch_table_recovery': (switch_tables, 'switch-table'),
}


def signature_request(plan):
    for field, (policy, _) in SIGNATURE_RECOVERIES.items():
        if plan['policy'] == policy.POLICY:
            digest = hashlib.sha256(canonical(plan) + b"\n").hexdigest()
            return field, {'policy': policy.POLICY, 'request_sha256': digest}
    raise Error('signature_recovery_scope', 'Unknown signature recovery policy', 2)

ANALYSIS_PROFILES = {
    'baseline': {'name': 'baseline', 'identity': 'baseline/1',
                 'marker': 'macscope-binary-only/1', 'parameter_inference': False},
    'parameter-inference': {'name': 'parameter-inference', 'identity': 'parameter-inference/1',
                 'marker': 'macscope-binary-only-parameters/1', 'parameter_inference': True},
    'deep': {
        'name': 'deep', 'identity': 'deep/1',
        'marker': 'macscope-binary-only-deep/1', 'parameter_inference': True,
        'required_options': {
            'Reference': 'true',
            'Reference.Create Address Tables': 'true',
            'Reference.Address Table Alignment': '1',
            'Reference.Address Table Minimum Size': '2',
            'Reference.Relocation Table Guide': 'true',
            'Reference.Switch Table References': 'false',
            'Aggressive Instruction Finder': 'false',
        },
    },
}


def analysis_profile(name='baseline'):
    try:
        return deepcopy(ANALYSIS_PROFILES[name])
    except (KeyError, TypeError):
        raise Error('unsupported_profile',
                    'Supported profiles are baseline, parameter-inference and deep', 3) from None


def profile_for_snapshot(snapshot):
    identity_value = snapshot.get('identity', {}).get('profile')
    for name, spec in ANALYSIS_PROFILES.items():
        if spec['identity'] == identity_value:
            return analysis_profile(name)
    raise Error('unsupported_profile', 'Saved analysis profile is unsupported; no baseline fallback', 3)


def validate_analysis_profile(raw, expected, mode):
    """Confirm the requested policy actually ran before publishing its provenance."""
    if expected != analysis_profile(expected.get('name')):
        raise Error('profile_contract', 'Invalid requested profile configuration', 10)
    recorded = raw.get('analysis_profile', {})
    if (recorded.get('name') != expected['marker']
            or recorded.get('applied') is not True
            or recorded.get('ghidra_version') != '12.2'
            or recorded.get('parameter_inference_enabled') is not expected['parameter_inference']):
        raise Error('profile_mismatch', 'Saved Program does not have the requested analysis profile', 10)
    options = raw.get('effective_analysis_options', {})
    desired = 'true' if expected['parameter_inference'] else 'false'
    required = {'Decompiler Parameter ID': desired, **expected.get('required_options', {})}
    for name, value in required.items():
        if options.get(name) != value:
            raise Error('profile_options_mismatch', 'Analyzer option differs from the requested profile: ' + name, 10)
    option_coverage = raw.get('coverage', {}).get('effective_analysis_options', {})
    if (option_coverage.get('status') != 'complete'
            or option_coverage.get('truncated') is not False or option_coverage.get('error')
            or option_coverage.get('emitted') != len(options)):
        raise Error('profile_options_incomplete', 'Effective analysis options were not fully recorded', 10)
    if mode == 'query':
        # Reopen can register dormant defaults; never run their analysis here.
        if raw.get('validation', {}).get('headless_analysis_enabled') is not False:
            raise Error('query_analysis', 'Reopened query unexpectedly enabled autoanalysis', 10)
    else:
        for name, value in options.items():
            if re.search(r'dwarf|pdb|source|demangl|external|library|debug', name, re.I) and value == 'true':
                raise Error('profile_source_option', 'A source/external analyzer was unexpectedly enabled: ' + name, 10)


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as s:
        for b in iter(lambda:s.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()


def tree_digest(root):
    h = hashlib.sha256()
    for p in sorted(root.rglob('*')):
        if p.is_symlink():
            h.update(str(p.relative_to(root)).encode()+b'\0link\0'+os.readlink(p).encode()+b'\n')
        elif p.is_file():
            h.update(str(p.relative_to(root)).encode()+b'\0'+digest(p).encode()+b'\n')
    return h.hexdigest()


def dependencies(ghidra=None, java=None, full=False):
    g = Path(ghidra or os.environ.get('MACSCOPE_GHIDRA', GHIDRA)).resolve()
    j = Path(java or os.environ.get('MACSCOPE_JAVA_HOME', JAVA)).resolve()
    host = platform.machine()
    if platform.system() != 'Darwin' or host != 'arm64':
        raise Error('unsupported_host', 'This experimental engine pin is tested only on macOS arm64', 4)
    hashes = engine_checks.layout(g,j,BRIDGE)
    try:
        v = subprocess.run([str(j/'bin/java'), '-version'], capture_output=True, timeout=10, env={'PATH':'/usr/bin:/bin','JAVA_HOME':str(j)}, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Error('jdk_startup', 'Cannot start pinned JDK: '+str(e), 4) from e
    version = (v.stderr+v.stdout).decode(errors='replace').strip()
    if v.returncode or not engine_checks.java_version_matches(version):
        raise Error('incompatible_jdk', 'Requires tested JDK 25.0.5.0.3', 4)
    result = {'ghidra_version':engine_checks.GHIDRA_VERSION, 'ghidra_path':str(g), 'java_home':str(j), 'jdk_version':version, 'host_arch':host, 'host_os':platform.platform(), **hashes, 'bridge_sha256':identity({p.name:digest(p) for p in sorted(BRIDGE.glob('*.java'))}), 'isolation':'experimental-trusted-owned-input-only; deny-network, restrict user-home reads and confine writes to the current job; not a hostile-input sandbox', 'hard_process_memory_limit':False}
    if full:
        result['ghidra_tree_sha256'] = tree_digest(g)
    return result


def profile(project, dependencies, *, write_root):
    # Seatbelt strings are JSON quoted, never shell interpolated.
    reads = [str(project.path), str(BRIDGE.resolve()), dependencies['ghidra_path'], dependencies['java_home']]
    ancestors = sorted({str(p) for p in project.path.parents} | {str(p) for p in BRIDGE.resolve().parents})
    literal = lambda p: json.dumps(p,ensure_ascii=False)
    exclusions = ' '.join('(require-not (subpath '+literal(p)+'))' for p in reads) + ' ' + ' '.join('(require-not (literal '+literal(p)+'))' for p in ancestors)
    if not write_root.is_absolute() or not write_root.is_relative_to(project.path) or '..' in write_root.parts:
        raise Error('worker_isolation_scope', 'Worker write directory must be inside the private workspace', 3)
    writable = literal(str(write_root))
    return ('(version 1)\n(allow default)\n(deny network*)\n'
            '(deny file-read-data (require-all (subpath "/Users") '+exclusions+'))\n'
            '(deny file-write* (require-all (require-not (subpath '+writable+')) '
            '(require-not (literal "/dev/null"))))\n')



def job_sandbox_sha256(project, dependencies, job_id):
    if not isinstance(job_id, str) or not jobs.JOB_ID.fullmatch(job_id):
        raise Error('job_manifest', 'Invalid worker job identifier')
    job = project.path/'jobs'/job_id
    return hashlib.sha256(profile(project, dependencies, write_root=job).encode()).hexdigest()


def worker_exited(proc):
    # Keep the group leader's PID reserved until all group signaling is done.
    return os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def signal_owned(proc, signum):
    try:
        worker_exited(proc)  # Confirm the leader is still our unreaped child.
        os.killpg(proc.pid, signum)
    except (ChildProcessError, ProcessLookupError):
        pass
    except PermissionError:
        # Darwin skips zombie group members and returns EPERM when no member
        # can receive the signal. Trusted workers keep the caller's identity.
        if platform.system() != 'Darwin' or not worker_exited(proc):
            raise


def terminate_owned(proc):
    try:
        if not worker_exited(proc):
            signal_owned(proc, signal.SIGTERM)
            deadline = time.monotonic() + 2
            while not worker_exited(proc) and time.monotonic() < deadline:
                time.sleep(0.05)
    except ChildProcessError:
        pass
    finally:
        signal_owned(proc, signal.SIGKILL)
        proc.wait(timeout=10)


def check_worker_budgets(cwd, log_path, max_log):
    if log_path.stat().st_size > max_log:
        raise Error('worker_output_limit', 'Worker log exceeds its byte limit', 7)
    total = 0
    for path in cwd.rglob('*'):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue  # Workers may remove temporary files between samples.
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
            if total > 512*1024*1024:
                raise Error('worker_storage_limit', 'Sampled job storage exceeds 512 MiB (not a hard filesystem quota)', 7)


def check_worker_cancellation(manifest_path, manifest):
    if jobs.cancel_requested(manifest_path, manifest['ownership_token']):
        raise Error('worker_cancelled', 'Worker cancellation requested by the workspace owner', 130, retryable=True)


def run_process(argv, *, cwd, env, timeout, log_path, manifest_path, manifest, max_log=8*1024*1024):
    start = time.monotonic()
    proc = None
    manifest_path = Path(manifest_path)
    owner = jobs.claim(manifest_path)
    try:
        gated = manifest.get('mode') in ('import','analyze','query') and 'job_id' in manifest
        if gated:
            manifest.update(launch_protocol=worker_lifecycle.PROTOCOL, boot_session_id=worker_lifecycle.boot_session())
        manifest.update(status='starting', argv=argv, timeout_seconds=timeout, started_unix=time.time(), ownership_token=uuid.uuid4().hex)
        write_json(manifest_path, manifest, force=True)
        check_worker_cancellation(manifest_path, manifest)
        with open(log_path, 'xb', buffering=0) as log:
            proc, gate = worker_lifecycle.start(argv, gated=gated, cwd=cwd, env=env, log=log)
            try:
                manifest.update(status='running', pid=proc.pid, process_group=proc.pid)
                write_json(manifest_path, manifest, force=True)
                if gate is not None:
                    worker_lifecycle.release(gate)
                while not worker_exited(proc):
                    check_worker_cancellation(manifest_path, manifest)
                    if time.monotonic()-start > timeout:
                        raise Error('worker_timeout', 'Worker wall-clock timeout', 7, retryable=True)
                    check_worker_budgets(Path(cwd), Path(log_path), max_log)
                    time.sleep(0.1)
            finally:
                if gate is not None:
                    os.close(gate)
                terminate_owned(proc)
            check_worker_cancellation(manifest_path, manifest)
            check_worker_budgets(Path(cwd), Path(log_path), max_log)
        if proc.returncode:
            raise Error('worker_failed', 'Headless worker exited '+str(proc.returncode)+'; see private job log', 10)
        manifest['status'] = 'complete'
    except KeyboardInterrupt:
        manifest['status'] = 'cancelled'
        raise Error('interrupted', 'Interrupted; prior committed snapshots remain available', 130) from None
    except Error as e:
        status = {7: 'timeout', 130: 'cancelled'}.get(e.exit_code, 'failed')
        manifest.update(status=status, error={'code':e.code,'message':str(e)})
        raise
    except OSError as e:
        manifest.update(status='failed', error={'code':'worker_startup','message':str(e)})
        raise Error('worker_startup', str(e), 4) from e
    finally:
        try:
            if proc is not None:
                if proc.returncode is None:
                    terminate_owned(proc)
                manifest['returncode'] = proc.returncode
            manifest['elapsed_seconds'] = round(time.monotonic()-start, 6)
            write_json(manifest_path, manifest, force=True)
        finally:
            os.close(owner)


def worker_limits(args, max_functions):
    return {
        'timeout_seconds': args.timeout, 'function_timeout_seconds': args.function_timeout,
        'max_functions': max_functions, 'jobs': 1, 'java_heap_mib': args.heap_mib,
        'process_memory_limit': None, 'sampled_job_storage_bytes': 512*1024*1024,
        'storage_is_hard_quota': False,
    }


def run(project, image, mode, args, deps, *, entry=None, hints=None, analysis_request=None,
        import_request=None, query_request=None, resumed_from=None, boundary_request=None, signature_plan=None):
    if any(c in str(project.path) for c in ('\"', '\\', '\n', '\r')):
        raise Error('worker_path_unsupported','Engine workspace paths containing quotes, backslashes or line breaks are not supported',3)
    if not args.experimental_trusted_input:
        raise Error('isolation_required', 'Engine operations currently require --experimental-trusted-input for explicitly trusted, user-owned fixtures. Hostile-input isolation is not validated. No unsafe fallback is automatic.', 3)
    if image['arch'] not in ('arm64','x86_64'):
        raise Error('unsupported_arch', 'Engine operations require an ordinary arm64 or x86_64 slice', 3)
    if args.jobs != 1:
        raise Error('jobs_unsupported', 'Only --jobs 1 is supported', 3)
    if args.max_memory_mib is not None:
        raise Error('hard_memory_unsupported', 'A hard process-memory budget cannot be enforced here. --heap-mib caps only the Java heap.', 3)
    if args.startup_timeout is not None:
        raise Error('startup_budget_unsupported', 'Separate startup deadlines are not yet supported; use --timeout for a total wall deadline', 3)
    if entry is not None and (mode != 'query' or not re.fullmatch(r'0x[0-9a-f]{1,16}', entry)):
        raise Error('query_entry', 'Selected query requires an exact saved RAM function entry', 2)
    if hints is not None and (entry is None or not 1<=len(hints)<=MAX_TYPE_HINTS):
        raise Error('type_hint_scope', 'Accepted hints require a bounded selected-function query', 2)
    if boundary_request is not None and mode != 'analyze':
        raise Error('boundary_recovery_scope', 'Boundary recovery requires analysis of an imported image', 2)
    recovery = None
    bound_recoveries = {key: query_request[key] for key in jobs.SIGNATURE_RECOVERY_FIELDS
                        if query_request is not None and key in query_request}
    if signature_plan is not None:
        recovery = signature_request(signature_plan)
        recovery_field, recovery_identity = recovery
        recovery_policy, recovery_stem = SIGNATURE_RECOVERIES[recovery_field]
        if (mode != 'query' or entry is None or hints is not None or signature_plan['entry_va'] != entry
                or signature_plan['image_sha256'] != image['sha256']
                or bound_recoveries != {recovery_field: recovery_identity}):
            raise Error('signature_recovery_scope', 'Signature recovery requires its exact selected query', 2)
    elif bound_recoveries:
        raise Error('signature_recovery_scope', 'The selected query is missing its signature recovery plan', 2)
    requested_profile = analysis_profile(getattr(args, 'profile', 'baseline')) if mode == 'analyze' else None
    if mode == 'query':
        saved_snapshot, active = project.snapshot(image)
        requested_profile = profile_for_snapshot(saved_snapshot)
        if entry is not None:
            saved_digest = saved_snapshot['identity'].get('engine', {}).get('ghidra_tree_sha256')
            if not saved_digest or saved_digest != deps.get('ghidra_tree_sha256'):
                raise Error('query_engine_mismatch', 'Installed Ghidra differs from the saved analysis; rerun analyze', 4)
        if not re.fullmatch(r'[a-f0-9]{32}', active.get('job_id','')):
            raise Error('analysis_program_missing','Active analyzed Program reference is invalid')
        source = project.path/'jobs'/active['job_id']/'program'
        if (source.parent.is_symlink() or source.is_symlink() or not source.is_dir()
                or active.get('analysis_program_sha256') != tree_digest(source)):
            raise Error('analysis_program_integrity','Saved analyzed Program is missing or changed; rerun analyze')
    elif mode == 'analyze':
        # Fresh analysis starts from the saved no-analysis import.
        source = project.path/'engine'/image['image_id']
    jobid = uuid.uuid4().hex
    job = project.path/'jobs'/jobid
    job.mkdir(mode=0o700)
    (job/'tmp').mkdir(mode=0o700)
    worker_home = job/'home'
    worker_home.mkdir(mode=0o700)
    outfile = job/'bridge.json'
    sandbox = job/'sandbox.sb'
    sandbox.write_text(profile(project, deps, write_root=job), encoding="utf-8")
    g, j = Path(deps['ghidra_path']), Path(deps['java_home'])
    engine_dir = job/'program'
    if mode == 'import':
        engine_dir.mkdir(mode=0o700)
    else:
        if source.is_symlink():
            raise Error('analysis_program_integrity', 'Saved Program directory is a symbolic link')
        shutil.copytree(source, engine_dir, symlinks=True)
        if any(p.is_symlink() for p in engine_dir.rglob('*')):
            raise Error('analysis_program_integrity', 'Saved Program contains a symbolic link')
    if signature_plan is not None:
        if tree_digest(engine_dir) != active['analysis_program_sha256']:
            raise Error('analysis_program_integrity', 'Copied Program differs from the saved signature query input')
        recovery_request = job/(recovery_stem + '-request.json')
        recovery_report = job/(recovery_stem + '-result.json')
        write_json(recovery_request, signature_plan, mode=0o400)
    argv = ['/usr/bin/sandbox-exec', '-f', str(sandbox), str(g/'support/analyzeHeadless'), str(engine_dir), 'image']
    if mode == 'import':
        argv += ['-import', str(project.path/'inputs'/(image['image_id']+'.macho')), '-noanalysis', '-loader', 'MachoLoader', '-loader-loadLibraries', 'false', '-loader-linkExistingProjectLibraries', 'false', '-loader-reexport', 'false']
    else:
        argv += ['-process', image['image_id']+'.macho']
        if mode == 'query':
            argv += ['-readOnly', '-noanalysis']
            if signature_plan is not None and signature_plan['requests']:
                script = getattr(recovery_policy, 'SCRIPT', 'RecoverCallSignatures.java')
                argv += ['-preScript', script, str(recovery_request), str(recovery_report),
                         str(args.function_timeout)]
        else:
            argv += ['-preScript', 'MacscopeProfile.java']
            if requested_profile['name'] != 'baseline':
                argv += [requested_profile['name']]
    max_functions = 1 if entry is not None else args.max_functions
    argv += ['-scriptPath', str(BRIDGE.resolve()), '-postScript', 'MacscopeBridge.java',
             str(outfile), mode, str(max_functions), str(args.function_timeout)]
    if boundary_request is not None:
        boundaries = job/'boundary-request.json'
        write_json(boundaries,boundary_request,mode=0o400)
        argv.append(str(boundaries))
    if entry is not None:
        argv.append(entry)
    if hints is not None:
        request = job/'type-hints.json'
        write_json(request, {'schema':'macscope-return-hints/1','hints':hints})
        argv.append(str(request))
    argv += ['-max-cpu', '1', '-analysisTimeoutPerFile', str(args.timeout), '-log',
             str(job/'engine.log'), '-scriptlog', str(job/'script.log')]
    env = {'PATH':'/usr/bin:/bin:/usr/sbin:/sbin', 'HOME':str(worker_home), 'USER':os.environ.get('USER','macscope'), 'TMPDIR':str(job/'tmp')+'/', 'JAVA_HOME':str(j), 'GHIDRA_HEADLESS_MAXMEM':str(args.heap_mib)+'M', 'JAVA_TOOL_OPTIONS':'-Duser.home='+json.dumps(str(worker_home),ensure_ascii=False)+' -Djava.io.tmpdir='+json.dumps(str(job/'tmp'),ensure_ascii=False), 'LANG':'en_US.UTF-8'}
    manifest = {'job_id':jobid, 'mode':mode, 'analysis_profile':requested_profile, 'image_id':image['image_id'], 'dependencies':deps, 'limits':worker_limits(args,max_functions), 'environment':env, 'sandbox_sha256':digest(sandbox)}
    if analysis_request is not None:
        manifest['analysis_request'] = analysis_request
    if boundary_request is not None:
        manifest['boundary_recovery'] = flow_boundaries.recovery_identity(boundary_request)
    if mode == 'query' and 'boundary_recovery' in saved_snapshot['identity']:
        manifest['boundary_recovery'] = saved_snapshot['identity']['boundary_recovery']
    if import_request is not None:
        manifest['import_request'] = import_request
    if query_request is not None:
        manifest['query_request'] = query_request
    if recovery is not None:
        manifest[recovery_field] = recovery_identity
    if resumed_from is not None:
        manifest['resumed_from'] = resumed_from
    if entry is not None:
        manifest.update(selected_entry=entry, source_analysis_id=image['active_analysis'])
    if hints is not None:
        manifest.update(type_hint_view_id=identity({'source_analysis_id':image['active_analysis'],'hints':hints}),
                        type_hints_sha256=digest(request),type_hints=hints)
    try:
        run_process(argv, cwd=job, env=env, timeout=args.timeout, log_path=job/'launcher.log', manifest_path=job/'job.json', manifest=manifest)
    except Error as error:
        if error.partial is None:
            error.partial = {'job_id':jobid}
        raise
    try:
        if b'Skipping unsupported -loader-' in read_regular(job/'launcher.log',8*1024*1024):
            raise Error('loader_option_unsupported','Pinned loader rejected a requested safety option',4)
        result = json.loads(read_regular(outfile,64*1024*1024))
    except (ValueError, Error) as e:
        if isinstance(e,Error) and e.code=='loader_option_unsupported':
            manifest.update(status='failed',error={'code':e.code,'message':str(e)})
            write_json(job/'job.json',manifest,force=True)
            e.partial = {'job_id':jobid}
            raise
        manifest.update(status='failed', error={'code':'bridge_result','message':'Missing, oversized or invalid bridge result'})
        write_json(job/'job.json',manifest,force=True)
        raise Error('bridge_result', 'Worker did not publish a valid bridge result; see private log', 10,
                    partial={'job_id':jobid}) from e
    try:
        if (result.get('schema') != 'macscope-bridge/1' or result.get('mode') != mode
                or result.get('ghidra_version') != engine_checks.GHIDRA_VERSION
                or result.get('bridge_version') != BRIDGE_VERSION):
            raise Error('bridge_contract', 'Bridge result version or mode mismatch', 4)
        runtime = result.pop('java_runtime', None)
        engine_checks.verify_runtime(runtime,deps['java_home'])
        manifest['java_runtime'] = runtime
        if result.get('executable_format') != 'Mac OS X Mach-O':
            raise Error('loader_mismatch', 'Ghidra did not use the Mach-O loader')
        lang = result.get('language_id','')
        if not ((image['arch'] == 'arm64' and lang == 'AARCH64:LE:64:AppleSilicon' and result.get('compiler_spec_id') == 'default') or (image['arch'] == 'x86_64' and lang == 'x86:LE:64:default' and result.get('compiler_spec_id') == 'gcc')):
            raise Error('language_mismatch', 'Loaded Ghidra language disagrees with selected slice')
        if result.get('executable_sha256') != image['sha256']:
            raise Error('engine_input_integrity', 'Ghidra loaded a different input digest')
        if result.get('status') == 'failed':
            raise Error('bridge_failed', 'Bridge failed: '+str(result.get('errors')), 10)
        if mode != 'import':
            validate_analysis_profile(result, requested_profile, mode)
        flow_boundaries.verify_recovery(result,boundary_request)
        if entry is not None:
            rows = result.get('functions', [])
            if (result.get('selected_entry') != entry or len(rows) != 1
                    or rows[0].get('entry_va') != entry):
                raise Error('query_result_mismatch', 'Worker did not return the exact selected function', 10)
        applied = result.get('applied_type_hints', [])
        if not isinstance(applied,list) or any(not isinstance(row,dict) for row in applied):
            raise Error('type_hint_result_mismatch','Worker returned malformed type-hint provenance',10)
        if hints is not None:
            received = [{key:row.get(key) for key in ('entry_va','return_type','revision')} for row in applied]
            if received != hints:
                raise Error('type_hint_result_mismatch','Worker did not apply the exact accepted hints',10)
        elif applied:
            raise Error('type_hint_result_mismatch','Worker applied unrequested type hints',10)
        if signature_plan is not None:
            if any(tree_digest(path) != active['analysis_program_sha256'] for path in (source, engine_dir)):
                raise Error('analysis_program_integrity', 'Signature recovery changed a saved Program on disk', 10)
            report = None
            if signature_plan['requests'] or recovery_report.exists():
                try:
                    report = json.loads(read_regular(recovery_report,64*1024))
                except (Error,ValueError) as error:
                    raise Error('signature_recovery_result', 'Worker did not publish a valid signature decision', 10) from error
            result[recovery_field] = dict(recovery_identity, **recovery_policy.decision(signature_plan,report))
        if mode == 'import' and result.get('validation',{}).get('headless_analysis_enabled') is not False:
            raise Error('import_analysis','Import did not disable autoanalysis',10)
        write_json(job/'job.json',manifest,force=True)
        if mode == 'import' and import_request is None:
            destination = project.path/'engine'/image['image_id']
            if destination.exists():
                raise Error('engine_project_exists', 'An engine baseline already exists without an image record; inspect workspace before retry', 8)
            os.rename(engine_dir,destination)
    except (Error, OSError) as e:
        manifest.update(status='failed',error={'code':getattr(e,'code','bridge_publication'),'message':str(e)})
        write_json(job/'job.json',manifest,force=True)
        if isinstance(e,Error) and e.partial is None:
            e.partial = {'job_id':jobid}
        raise
    return result, manifest
