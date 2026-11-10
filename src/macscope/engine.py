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
from . import callee_parameters, direct_signatures, dispatch_returns, engine_checks, flow_boundaries, forwarded_returns, jobs, manual_boundaries, scalar_signatures, switch_tables, worker_lifecycle
from . import focused, loader_mapping
from .annotations import MAX_TYPE_HINTS, structure_definitions
from .errors import Error
from .storage import canonical, identity, is_digest, strict_json, write_json
from .macho import checked_path, read_regular

GHIDRA = '/opt/homebrew/opt/ghidra/libexec'
JAVA = '/opt/homebrew/Cellar/openjdk@25/25.0.5.0.3/libexec/openjdk.jdk/Contents/Home'
BRIDGE = Path(__file__).parent/'bridge'
BRIDGE_VERSION = '1.14.0'
STARTUP_TIMEOUT_SECONDS = 300
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


def bridge_digest():
    return identity({path.name: digest(path) for path in sorted(BRIDGE.glob('*.java'))})


def tree_digest(root, *, ignore=()):
    h = hashlib.sha256()
    for p in sorted(root.rglob('*')):
        relative = p.relative_to(root)
        if str(relative) in ignore and not p.is_symlink() and p.is_file():
            continue
        if p.is_symlink():
            h.update(str(relative).encode()+b'\0link\0'+os.readlink(p).encode()+b'\n')
        elif p.is_file():
            h.update(str(relative).encode()+b'\0'+digest(p).encode()+b'\n')
    return h.hexdigest()


def saved_program_digest(root, error_code):
    """Check the pinned local Ghidra project layout before using its tree digest."""
    try:
        root = checked_path(root, directory=True)
        repository = root/'image.rep'
        data = repository/'idata'
        checked_path(root/'image.gpr')
        for required in (repository/'project.prp', data/'~index.dat'):
            if checked_path(required).stat().st_size == 0:
                raise ValueError('Empty Ghidra project metadata')
        has_database = False
        for path in root.rglob('*'):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('Nonregular Ghidra project entry')
            if path.is_relative_to(data) and path.suffix == '.gbf' and info.st_size:
                has_database = True
        if not has_database:
            raise ValueError('Missing Ghidra Program database')
        return tree_digest(root)
    except (Error, OSError, ValueError) as error:
        raise Error(error_code, 'Saved Ghidra Program is missing or incomplete') from error


def analyzed_program(project, record):
    job_id = record.get('job_id')
    if not isinstance(job_id, str) or not jobs.JOB_ID.fullmatch(job_id):
        raise Error('analysis_program_missing', 'Active analyzed Program reference is invalid')
    source = project.path/'jobs'/job_id/'program'
    expected = record.get('analysis_program_sha256')
    if not is_digest(expected) or saved_program_digest(source, 'analysis_program_integrity') != expected:
        raise Error('analysis_program_integrity', 'Saved analyzed Program is missing or changed; rerun analyze')
    return source


def import_program_path(project, image):
    provider = image.get('engine_baseline_job_id')
    if provider is None:
        return project.path/'engine'/image['image_id']
    if not isinstance(provider, str) or not jobs.JOB_ID.fullmatch(provider):
        raise Error('baseline_integrity', 'Invalid saved import Program provider')
    return project.path/'jobs'/provider/'program'


def imported_program(project, image):
    source = import_program_path(project, image)
    expected = image.get('engine_baseline_sha256')
    if not is_digest(expected) or saved_program_digest(source, 'baseline_integrity') != expected:
        raise Error('baseline_integrity', 'Saved import Program is missing or changed')
    return source


def copy_program(source, destination, expected_digest, integrity_error):
    if source.is_symlink():
        raise Error('analysis_program_integrity', 'Saved Program directory is a symbolic link')
    try:
        shutil.copytree(source, destination, symlinks=True)
        if any(path.is_symlink() for path in destination.rglob('*')):
            raise Error('analysis_program_integrity', 'Saved Program contains a symbolic link')
        if tree_digest(destination) != expected_digest:
            raise Error(integrity_error, 'Copied Program differs from the recorded source digest')
    except OSError as error:
        raise Error(integrity_error, 'Could not copy and verify the saved Program') from error


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
    result = {'ghidra_version':engine_checks.GHIDRA_VERSION, 'ghidra_path':str(g), 'java_home':str(j), 'jdk_version':version, 'host_arch':host, 'host_os':platform.platform(), **hashes, 'bridge_sha256':bridge_digest(), 'isolation':'experimental-trusted-owned-input-only; deny-network, restrict user-home reads and confine writes to the current job; not a hostile-input sandbox', 'hard_process_memory_limit':False}
    if full:
        result['ghidra_tree_sha256'] = tree_digest(g)
    return result


def workspace_exec_rule(project):
    paths = (json.dumps(str(project.path/name), ensure_ascii=False) for name in ('inputs', 'jobs'))
    return '(deny process-exec ' + ' '.join(f'(subpath {path})' for path in paths) + ')\n'


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
            '(require-not (literal "/dev/null"))))\n'
            + workspace_exec_rule(project))



def job_profile(project, dependencies, job_id):
    if not isinstance(job_id, str) or not jobs.JOB_ID.fullmatch(job_id):
        raise Error('job_manifest', 'Invalid worker job identifier')
    job = project.path/'jobs'/job_id
    return profile(project, dependencies, write_root=job)


def job_sandbox_sha256(project, dependencies, job_id):
    return hashlib.sha256(job_profile(project, dependencies, job_id).encode()).hexdigest()


def job_sandbox_matches(project, dependencies, job_id, recorded):
    current = job_profile(project, dependencies, job_id)
    # Recognize the previous profile for recovery. New launches use the current one.
    previous = current.removesuffix(workspace_exec_rule(project))
    return any(hashlib.sha256(policy.encode()).hexdigest() == recorded for policy in (current, previous))


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


def check_worker_deadline(now, deadline, startup_deadline):
    if startup_deadline is not None and startup_deadline < deadline and now >= startup_deadline:
        raise Error('worker_startup_timeout', 'Headless initialization exceeded its startup deadline', 7, retryable=True)
    if now >= deadline:
        raise Error('worker_timeout', 'Worker wall-clock timeout', 7, retryable=True)


def run_process(argv, *, cwd, env, timeout, log_path, manifest_path, manifest,
                startup_timeout=None, max_log=8*1024*1024):
    start = time.monotonic()
    deadline = start + timeout
    proc = None
    probe = worker_lifecycle.StartupProbe() if startup_timeout is not None else None
    manifest_path = Path(manifest_path)
    owner = jobs.claim(manifest_path)
    try:
        gated = manifest.get('mode') in ('import','analyze','query') and 'job_id' in manifest
        if gated:
            manifest.update(launch_protocol=worker_lifecycle.PROTOCOL, boot_session_id=worker_lifecycle.boot_session(),
                            restart_protocol=jobs.RESTART_PROTOCOL)
        if probe is not None:
            manifest['startup'] = {'status': 'waiting', 'evidence': worker_lifecycle.STARTUP_EVIDENCE}
        manifest.update(status='starting', argv=argv, timeout_seconds=timeout, started_unix=time.time(), ownership_token=uuid.uuid4().hex)
        write_json(manifest_path, manifest, force=True)
        check_worker_cancellation(manifest_path, manifest)
        if gated:
            jobs.record_restart_attempt(manifest_path, manifest)
        with open(log_path, 'x+b', buffering=0) as log:
            launch_started = time.monotonic()
            startup_deadline = launch_started + startup_timeout if probe is not None else None
            proc, gate = worker_lifecycle.start(argv, gated=gated, cwd=cwd, env=env, log=log)
            try:
                manifest.update(status='running', pid=proc.pid, process_group=proc.pid)
                write_json(manifest_path, manifest, force=True)
                if gate is not None:
                    worker_lifecycle.release(gate)
                while True:
                    exited = worker_exited(proc)
                    check_worker_cancellation(manifest_path, manifest)
                    check_worker_deadline(time.monotonic(), deadline, startup_deadline)
                    check_worker_budgets(Path(cwd), Path(log_path), max_log)
                    reported = probe.poll(log.fileno()) if probe is not None else None
                    now = time.monotonic()
                    check_worker_deadline(now, deadline, startup_deadline)
                    if reported is not None:
                        manifest['startup'].update(status='ready', ghidra_reported_ms=reported,
                                                   observed_seconds=round(now-launch_started, 6))
                        write_json(manifest_path, manifest, force=True)
                        probe = startup_deadline = None
                    if exited:
                        break
                    next_deadline = deadline if startup_deadline is None else min(deadline, startup_deadline)
                    time.sleep(min(0.1, max(0, next_deadline-time.monotonic())))
            finally:
                if gate is not None:
                    os.close(gate)
                terminate_owned(proc)
            check_worker_cancellation(manifest_path, manifest)
            check_worker_budgets(Path(cwd), Path(log_path), max_log)
        if proc.returncode:
            raise Error('worker_failed', 'Headless worker exited '+str(proc.returncode)+'; see private job log', 10)
        if probe is not None:
            raise Error('worker_startup_unconfirmed', 'Headless startup marker missing from the bounded launcher log', 4)
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
            if probe is not None and 'startup' in manifest:
                failure = manifest.get('error', {}).get('code')
                manifest['startup']['status'] = 'timeout' if failure == 'worker_startup_timeout' else 'unconfirmed'
            if proc is not None:
                if proc.returncode is None:
                    terminate_owned(proc)
                manifest['returncode'] = proc.returncode
            manifest['elapsed_seconds'] = round(time.monotonic()-start, 6)
            write_json(manifest_path, manifest, force=True)
        finally:
            os.close(owner)


def worker_limits(args, max_functions):
    limits = {
        'timeout_seconds': args.timeout, 'function_timeout_seconds': args.function_timeout,
        'max_functions': max_functions, 'jobs': 1, 'java_heap_mib': args.heap_mib,
        'process_memory_limit': None, 'sampled_job_storage_bytes': 512*1024*1024,
        'storage_is_hard_quota': False,
    }
    if args.startup_timeout is not None:
        limits['startup_timeout_seconds'] = args.startup_timeout
    return limits


def decompiler_timing(result, max_functions):
    """Validate worker timing and retain only its summary in the job manifest."""
    timing = result.pop('decompiler_timing', None)
    if result['mode'] == 'import' and timing is None:
        return None
    error = Error('decompiler_timing', 'Worker returned invalid decompiler timing evidence', 10)
    if result['mode'] == 'import' or not isinstance(timing, dict) or timing.keys() != {'open_program', 'calls'}:
        raise error
    opening, calls = timing['open_program'], timing['calls']
    if (not isinstance(calls, list) or len(calls) > max_functions
            or (opening is not None and (not isinstance(opening, dict)
                or opening.keys() != {'elapsed_ns', 'opened'} or type(opening['opened']) is not bool
                or type(opening['elapsed_ns']) is not int or not 0 <= opening['elapsed_ns'] < 2**63))):
        raise error
    summary = result.get('decompile_summary')
    attempted = summary.get('attempted') if isinstance(summary, dict) else None
    if type(attempted) is not int or not 0 <= attempted <= max_functions:
        raise error
    if len(calls) != (attempted if opening and opening['opened'] else 0):
        raise error
    for call in calls:
        if (not isinstance(call, dict) or call.keys() != {'entry', 'elapsed_ns'}
                or (call['entry'] is not None and (not isinstance(call['entry'], str) or len(call['entry']) > 128))
                or type(call['elapsed_ns']) is not int or not 0 <= call['elapsed_ns'] < 2**63):
            raise error
    return {'open_program': opening, 'call_count': len(calls),
            'total_call_ns': sum(call['elapsed_ns'] for call in calls)}


def read_worker_object(path, maximum):
    result = strict_json(read_regular(path, maximum))
    if not isinstance(result, dict):
        raise ValueError('Expected a worker result object')
    return result


def record_array(value):
    return isinstance(value, list) and all(isinstance(row, dict) for row in value)


def verify_macho_loader(result, image):
    if result.get('executable_format') != 'Mac OS X Mach-O':
        raise Error('loader_mismatch', 'Ghidra did not use the Mach-O loader')
    expected = {'arm64': ('AARCH64:LE:64:AppleSilicon', 'default'),
                'x86_64': ('x86:LE:64:default', 'gcc')}
    if (result.get('language_id'), result.get('compiler_spec_id')) != expected.get(image['arch']):
        raise Error('language_mismatch', 'Loaded Ghidra language disagrees with selected slice')
    if result.get('executable_sha256') != image['sha256']:
        raise Error('engine_input_integrity', 'Ghidra loaded a different input digest')


def validate_bridge_shape(result, max_functions, *, full_functions):
    error = Error('bridge_result', 'Worker result has invalid status or evidence structure', 10)
    status = result.get('status')
    if status == 'failed':
        return  # The bridge can fail before collecting its facets.
    if status not in ('complete', 'partial'):
        raise error
    for key in ('coverage', 'validation', 'analysis_profile', 'effective_analysis_options'):
        if not isinstance(result.get(key), dict):
            raise error
    if any(not isinstance(facet, dict) for facet in result['coverage'].values()):
        raise error
    for key in ('address_references', 'computed_flow_sites', 'imports', 'exports', 'sections', 'strings', 'symbols'):
        if key in result and not record_array(result[key]):
            raise error
    functions = result.get('functions')
    count = result.get('function_count_enumerated')
    if (not record_array(functions) or type(count) is not int or count != len(functions)
            or count > max_functions or (result['mode'] == 'import' and count)):
        raise error
    for function in functions:
        coverage = function.get('coverage')
        if (not isinstance(function.get('entry_va'), str) or not isinstance(coverage, dict)
                or any(not isinstance(facet, dict) for facet in coverage.values())
                or not isinstance(coverage.get('pseudocode', {}).get('status'), str)
                or not isinstance(function.get('decompile_status'), str)
                or type(function.get('pseudocode_truncated')) is not bool
                or 'pseudocode' not in function or not isinstance(function['pseudocode'], (str, type(None)))):
            raise error
        if full_functions and (not isinstance(function.get('name'), str)
                or not record_array(function.get('instructions')) or not record_array(function.get('blocks'))
                or not isinstance(function.get('body_ranges'), list)):
            raise error


def run(project, image, mode, args, deps, *, entry=None, hints=None, analysis_request=None,
        import_request=None, query_request=None, resumed_from=None, boundary_request=None, signature_plan=None,
        manual_request=None, from_import=False):
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
    if entry is not None and (mode != 'query' or not re.fullmatch(r'0x[0-9a-f]{1,16}', entry)):
        raise Error('query_entry', 'Selected query requires an exact saved RAM function entry', 2)
    if from_import and (mode != 'query' or entry is None or any(value is not None for value in
            (hints, query_request, signature_plan))):
        raise Error('focused_scope', 'Focused import requires one exact entry without saved-analysis options', 2)
    if hints is not None and (entry is None or not 1<=len(hints)<=MAX_TYPE_HINTS):
        raise Error('type_hint_scope', 'Accepted hints require a bounded selected-function query', 2)
    hint_request = None
    if hints is not None:
        hint_request = {'schema':'macscope-type-hints/2','hints':hints}
        if len(canonical(hint_request)) + 1 > 65536:
            raise Error('type_hint_request_limit','Accepted hints exceed the worker request size limit',7)
    if boundary_request is not None and mode != 'analyze':
        raise Error('boundary_recovery_scope', 'Boundary recovery requires analysis of an imported image', 2)
    if manual_request is not None and (mode != 'analyze' or boundary_request is not None):
        raise Error('boundary_edit_scope', 'Manual boundary edits require a separate analysis', 2)
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
    if from_import:
        imported_engine = image.get('import_dependencies')
        if (not image['imported'] or not deps.get('ghidra_tree_sha256') or
                not isinstance(imported_engine, dict) or
                imported_engine.get('ghidra_tree_sha256') != deps['ghidra_tree_sha256']):
            raise Error('focused_import_engine', 'Focused query requires a committed import from the selected Ghidra', 4)
        proof, payload = focused.select(project, image, entry)
        source = import_program_path(project,image)
        source_digest = image.get('engine_baseline_sha256')
        if (not source_digest or source.parent.is_symlink() or source.is_symlink() or not source.is_dir()
                or tree_digest(source) != source_digest):
            raise Error('baseline_integrity', 'Saved import Program is missing or differs from its digest', 4)
        proof = dict(proof, program_sha256=source_digest)
        focus_request = jobs.focused_request(project,image,proof)
        if resumed_from is not None and jobs.focused_record(jobs.get(project,resumed_from)[1]) != focus_request:
            raise Error('job_resume_inputs', 'Focused retry differs from the original selected extent', 8)
        program_content_digest = tree_digest(source, ignore=focused.PROJECT_BACKUPS)
    elif mode == 'query':
        saved_snapshot, active = project.snapshot(image)
        requested_profile = profile_for_snapshot(saved_snapshot)
        if entry is not None:
            saved_digest = saved_snapshot['identity'].get('engine', {}).get('ghidra_tree_sha256')
            if not saved_digest or saved_digest != deps.get('ghidra_tree_sha256'):
                raise Error('query_engine_mismatch', 'Installed Ghidra differs from the saved analysis; rerun analyze', 4)
        if query_request is not None and (
                query_request.get('source_program_sha256') != active.get('analysis_program_sha256')
                or query_request.get('source_snapshot_sha256') != active.get('snapshot_sha256')):
            raise Error('job_resume_inputs', 'The saved Program or snapshot changed before the query', 8)
        source = analyzed_program(project, active)
        source_digest = active['analysis_program_sha256']
    elif mode == 'analyze':
        # Fresh analysis starts from the saved no-analysis import.
        source = import_program_path(project,image)
        source_digest = image.get('engine_baseline_sha256')
        if not is_digest(source_digest):
            raise Error('baseline_integrity', 'Saved import Program has no valid recorded digest')
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
    if signature_plan is not None:
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
            if from_import:
                focus_report = job/'focused-proof.json'
                argv += ['-preScript', 'MacscopeFocus.java', str(focus_report), image['sha256'],
                         proof['entry_va'], proof['end_va_exclusive'], proof['extent_sha256']]
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
    if manual_request is not None:
        boundaries = job/'manual-boundaries.json'
        write_json(boundaries,manual_request,mode=0o400)
        argv.append(str(boundaries))
    if entry is not None:
        argv.append(entry)
    if from_import:
        argv.append('--from-import')
    if hints is not None:
        request = job/'type-hints.json'
        write_json(request,hint_request,mode=0o400)
        argv.append(str(request))
    argv += ['-max-cpu', '1', '-analysisTimeoutPerFile', str(args.timeout), '-log',
             str(job/'engine.log'), '-scriptlog', str(job/'script.log')]
    env = {'PATH':'/usr/bin:/bin:/usr/sbin:/sbin', 'HOME':str(worker_home), 'USER':os.environ.get('USER','macscope'), 'TMPDIR':str(job/'tmp')+'/', 'JAVA_HOME':str(j), 'GHIDRA_HEADLESS_MAXMEM':str(args.heap_mib)+'M', 'JAVA_TOOL_OPTIONS':'-Duser.home='+json.dumps(str(worker_home),ensure_ascii=False)+' -Djava.io.tmpdir='+json.dumps(str(job/'tmp'),ensure_ascii=False), 'LANG':'en_US.UTF-8'}
    manifest = {'job_id':jobid, 'mode':mode, 'analysis_profile':requested_profile, 'image_id':image['image_id'], 'dependencies':deps, 'limits':worker_limits(args,max_functions), 'environment':env, 'sandbox_sha256':digest(sandbox)}
    if analysis_request is not None:
        manifest['analysis_request'] = analysis_request
    if boundary_request is not None:
        manifest['boundary_recovery'] = flow_boundaries.recovery_identity(boundary_request)
    if mode == 'query' and not from_import and 'boundary_recovery' in saved_snapshot['identity']:
        manifest['boundary_recovery'] = saved_snapshot['identity']['boundary_recovery']
    if manual_request is not None:
        manifest['manual_boundaries'] = manual_boundaries.request_identity(manual_request)
    if mode == 'query' and not from_import and 'manual_boundaries' in saved_snapshot['identity']:
        manifest['manual_boundaries'] = saved_snapshot['identity']['manual_boundaries']
    if import_request is not None:
        manifest['import_request'] = import_request
    if query_request is not None:
        manifest['query_request'] = query_request
    if recovery is not None:
        manifest[recovery_field] = recovery_identity
    if resumed_from is not None:
        manifest['resumed_from'] = resumed_from
    if entry is not None:
        manifest.update(selected_entry=entry, source_analysis_id=None if from_import else image['active_analysis'])
    if from_import:
        manifest['focused_import'] = proof
        manifest['focused_request'] = focus_request
    if hints is not None:
        manifest.update(type_hint_view_id=identity({'source_analysis_id':image['active_analysis'],'hints':hints}),
                        type_hints_sha256=digest(request),type_hints=hints)
    if mode != 'import':
        integrity_error = 'baseline_integrity' if mode == 'analyze' or from_import else 'analysis_program_integrity'
        try:
            copy_program(source, engine_dir, source_digest, integrity_error)
        except Error as error:
            manifest.update(status='failed', error={'code':error.code,'message':str(error)})
            write_json(job/'job.json',manifest)
            error.partial = {'job_id':jobid}
            raise
    try:
        run_process(argv, cwd=job, env=env, timeout=args.timeout, startup_timeout=args.startup_timeout,
                    log_path=job/'launcher.log', manifest_path=job/'job.json', manifest=manifest)
    except Error as error:
        if error.partial is None:
            error.partial = {'job_id':jobid}
        raise
    try:
        if b'Skipping unsupported -loader-' in read_regular(job/'launcher.log',8*1024*1024):
            raise Error('loader_option_unsupported','Pinned loader rejected a requested safety option',4)
        result = read_worker_object(outfile,64*1024*1024)
    except (ValueError, RecursionError, OSError, Error) as e:
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
        validate_bridge_shape(result,max_functions,full_functions=entry is None or from_import)
        runtime = result.pop('java_runtime', None)
        engine_checks.verify_runtime(runtime,deps['java_home'])
        manifest['java_runtime'] = runtime
        verify_macho_loader(result,image)
        if result.get('status') == 'failed':
            rejected = result.get('manual_boundary_rejection')
            if manual_request is not None and isinstance(rejected,str):
                raise Error('boundary_edit_rejected',rejected,3)
            raise Error('bridge_failed', 'Bridge failed: '+str(result.get('errors')), 10)
        timing = decompiler_timing(result,max_functions)
        if timing is not None:
            manifest['decompiler_timing'] = timing
        if mode != 'import' and not from_import:
            validate_analysis_profile(result, requested_profile, mode)
        flow_boundaries.verify_recovery(result,boundary_request)
        manual_boundaries.verify(result,manual_request)
        if entry is not None:
            rows = result.get('functions', [])
            if (result.get('selected_entry') != entry or len(rows) != 1
                    or rows[0].get('entry_va') != entry):
                raise Error('query_result_mismatch', 'Worker did not return the exact selected function', 10)
        if from_import:
            if result.get('validation', {}).get('headless_analysis_enabled') is not False:
                raise Error('query_analysis', 'Focused query unexpectedly enabled autoanalysis', 10)
            try:
                report = read_worker_object(focus_report, 4096)
            except (ValueError, RecursionError, OSError, Error) as error:
                raise Error('focused_worker_proof', 'Worker did not publish the selected range proof', 10) from error
            focused.verify(proof, payload, report, rows[0])
            if (tree_digest(source) != source_digest or
                    tree_digest(engine_dir, ignore=focused.PROJECT_BACKUPS) != program_content_digest):
                raise Error('baseline_integrity', 'Focused query changed a saved Program database', 10)
        applied = result.get('applied_type_hints', [])
        if not isinstance(applied,list) or any(not isinstance(row,dict) for row in applied):
            raise Error('type_hint_result_mismatch','Worker returned malformed type-hint provenance',10)
        if hints is not None:
            hint_fields = ('entry_va','return_type','parameter_types','revision')
            received = [{key:row[key] for key in hint_fields if key in row} for row in applied]
            if received != hints:
                raise Error('type_hint_result_mismatch','Worker did not apply the exact accepted hints',10)
        elif applied:
            raise Error('type_hint_result_mismatch','Worker applied unrequested type hints',10)
        types = (value for hint in hints or ()
                 for value in ([hint['return_type']] if 'return_type' in hint else hint['parameter_types']))
        definitions = {f'struct {name}{{{fields}}}' for name,fields in structure_definitions(types).items()}
        layouts = result.get('aggregate_type_layouts',[])
        if (not isinstance(layouts,list) or len(layouts) != len(definitions)
                or any(not isinstance(row,dict) or not isinstance(row.get('definition'),str) for row in layouts)
                or {row['definition'] for row in layouts} != definitions):
            raise Error('type_hint_result_mismatch','Worker returned different aggregate type definitions',10)
        if hints is not None or signature_plan is not None:
            if any(tree_digest(path) != active['analysis_program_sha256'] for path in (source, engine_dir)):
                raise Error('analysis_program_integrity', 'Fresh query changed a Program on disk', 10)
        if signature_plan is not None:
            report = None
            if signature_plan['requests'] or recovery_report.exists():
                try:
                    report = read_worker_object(recovery_report,64*1024)
                except (Error, ValueError, RecursionError, OSError) as error:
                    raise Error('signature_recovery_result', 'Worker did not publish a valid signature decision', 10) from error
            result[recovery_field] = dict(recovery_identity, **recovery_policy.decision(signature_plan,report))
        if mode == 'import':
            if result['validation'].get('headless_analysis_enabled') is not False:
                raise Error('import_analysis','Import did not disable autoanalysis',10)
            manifest['loader_mapping'] = loader_mapping.verify(result,image)
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
