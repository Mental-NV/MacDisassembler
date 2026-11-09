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
import subprocess
import time
import uuid
from .errors import Error
from .storage import canonical, identity, write_json
from .macho import read_regular

GHIDRA = '/opt/homebrew/opt/ghidra/libexec'
JAVA = '/opt/homebrew/Cellar/openjdk@25/25.0.5.0.3/libexec/openjdk.jdk/Contents/Home'
BRIDGE = Path(__file__).parent/'bridge'

ANALYSIS_PROFILES = {
    'baseline': {'name': 'baseline', 'identity': 'baseline/1',
                 'marker': 'macscope-binary-only/1', 'parameter_inference': False},
    'parameter-inference': {'name': 'parameter-inference', 'identity': 'parameter-inference/1',
                 'marker': 'macscope-binary-only-parameters/1', 'parameter_inference': True},
}


def analysis_profile(name='baseline'):
    try:
        return dict(ANALYSIS_PROFILES[name])
    except (KeyError, TypeError):
        raise Error('unsupported_profile',
                    'Supported profiles are baseline and experimental parameter-inference; deep remains unsupported', 3) from None


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
    if options.get('Decompiler Parameter ID') != desired:
        raise Error('profile_options_mismatch', 'Parameter-inference option differs from the requested profile', 10)
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
    native = g/'Ghidra/Features/Decompiler/os/mac_arm_64/decompile'
    required = [g/'support/analyzeHeadless', g/'Ghidra/application.properties', native, j/'bin/java', j/'lib/server/libjvm.dylib', BRIDGE/'MacscopeBridge.java', BRIDGE/'MacscopeProfile.java']
    for p in required:
        if not p.is_file():
            raise Error('missing_dependency', 'Missing required dependency: '+str(p), 4)
    for p in (g/'support/analyzeHeadless',native,j/'bin/java'):
        if not os.access(p,os.X_OK):raise Error('dependency_permissions','Required dependency is not executable: '+str(p),4)
    props = (g/'Ghidra/application.properties').read_text()
    if '\napplication.version=12.2\n' not in '\n'+props:
        raise Error('incompatible_ghidra', 'Requires exactly full Ghidra 12.2', 4)
    try:
        v = subprocess.run([str(j/'bin/java'), '-version'], capture_output=True, timeout=10, env={'PATH':'/usr/bin:/bin','JAVA_HOME':str(j)}, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Error('jdk_startup', 'Cannot start pinned JDK: '+str(e), 4) from e
    version = (v.stderr+v.stdout).decode(errors='replace').strip()
    if v.returncode or '25.0.5.0.3' not in version:
        raise Error('incompatible_jdk', 'Requires tested JDK 25.0.5.0.3', 4)
    result = {'ghidra_version':'12.2', 'ghidra_path':str(g), 'java_home':str(j), 'jdk_version':version, 'host_arch':host, 'host_os':platform.platform(), 'native_decompiler_sha256':digest(native), 'java_sha256':digest(j/'bin/java'), 'jvm_sha256':digest(j/'lib/server/libjvm.dylib'), 'bridge_sha256':identity({p.name:digest(p) for p in sorted(BRIDGE.glob('*.java'))}), 'application_properties_sha256':digest(g/'Ghidra/application.properties'), 'isolation':'experimental-trusted-owned-input-only; deny-network and user-home filesystem restrictions; not a hostile-input sandbox', 'hard_process_memory_limit':False}
    if full:
        result['ghidra_tree_sha256'] = tree_digest(g)
    return result


def profile(project, dependencies):
    # Seatbelt strings are JSON quoted, never shell interpolated.
    reads = [str(project.path), str(BRIDGE.resolve()), dependencies['ghidra_path'], dependencies['java_home']]
    ancestors = sorted({str(p) for p in project.path.parents} | {str(p) for p in BRIDGE.resolve().parents})
    literal = lambda p: json.dumps(p,ensure_ascii=False)
    exclusions = ' '.join('(require-not (subpath '+literal(p)+'))' for p in reads) + ' ' + ' '.join('(require-not (literal '+literal(p)+'))' for p in ancestors)
    return '(version 1)\n(allow default)\n(deny network*)\n(deny file-read-data (require-all (subpath "/Users") '+exclusions+'))\n(deny file-write* (require-all (subpath "/Users") (require-not (subpath '+literal(str(project.path))+'))))\n'



def terminate_owned(proc):
    # start_new_session creates a new session/group, retained only while its
    # group leader is our unreaped child. No PID files are used to kill jobs.
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=2)
        # Reap leader then terminate remaining descendants in this owned group.
        time.sleep(0.1)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=10)


def run_process(argv, *, cwd, env, timeout, log_path, manifest_path, manifest, max_log=8*1024*1024):
    start = time.monotonic()
    proc = None
    manifest.update(status='starting', argv=argv, timeout_seconds=timeout, started_unix=time.time(), ownership_token=uuid.uuid4().hex)
    write_json(manifest_path, manifest, force=True)
    try:
        with open(log_path, 'xb', buffering=0) as log:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            manifest.update(status='running', pid=proc.pid, process_group=proc.pid)
            write_json(manifest_path, manifest, force=True)
            while proc.poll() is None:
                if time.monotonic()-start > timeout:
                    raise Error('worker_timeout', 'Worker wall-clock timeout', 7, retryable=True)
                if Path(log_path).stat().st_size > max_log:
                    raise Error('worker_output_limit', 'Worker log exceeds 8 MiB', 7)
                total = sum(p.stat().st_size for p in Path(cwd).rglob('*') if p.is_file() and not p.is_symlink())
                if total > 512*1024*1024:
                    raise Error('worker_storage_limit', 'Sampled job storage exceeds 512 MiB (not a hard filesystem quota)', 7)
                time.sleep(0.1)
        if proc.returncode:
            raise Error('worker_failed', 'Headless worker exited '+str(proc.returncode)+'; see private job log', 10)
        manifest['status'] = 'complete'
    except KeyboardInterrupt:
        manifest['status'] = 'cancelled'
        raise Error('interrupted', 'Interrupted; prior committed snapshots remain available', 130) from None
    except Error as e:
        manifest.update(status='timeout' if e.exit_code == 7 else 'failed', error={'code':e.code,'message':str(e)})
        raise
    except OSError as e:
        manifest.update(status='failed', error={'code':'worker_startup','message':str(e)})
        raise Error('worker_startup', str(e), 4) from e
    finally:
        if proc is not None:
            terminate_owned(proc)
            manifest['returncode'] = proc.returncode
        manifest['elapsed_seconds'] = round(time.monotonic()-start, 6)
        write_json(manifest_path, manifest, force=True)


def run(project, image, mode, args, deps, *, entry=None):
    if any(c in str(project.path) for c in ('\"', '\\', '\n', '\r')):
        raise Error('worker_path_unsupported','Engine workspace paths containing quotes, backslashes or line breaks are not supported',3)
    if not args.experimental_trusted_input:
        raise Error('isolation_required', 'Engine operations currently require --experimental-trusted-input for explicitly trusted, user-owned fixtures. Hostile-input isolation is not validated. No unsafe fallback is automatic.', 3)
    if args.jobs != 1:
        raise Error('jobs_unsupported', 'Only --jobs 1 is supported', 3)
    if args.max_memory_mib is not None:
        raise Error('hard_memory_unsupported', 'A hard process-memory budget cannot be enforced here. --heap-mib caps only the Java heap.', 3)
    if args.startup_timeout is not None:
        raise Error('startup_budget_unsupported', 'Separate startup deadlines are not yet supported; use --timeout for a total wall deadline', 3)
    if entry is not None and (mode != 'query' or not re.fullmatch(r'0x[0-9a-f]{1,16}', entry)):
        raise Error('query_entry', 'Selected query requires an exact saved RAM function entry', 2)
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
        if not source.is_dir() or active.get('analysis_program_sha256') != tree_digest(source):
            raise Error('analysis_program_integrity','Saved analyzed Program is missing or changed; rerun analyze')
    elif mode == 'analyze':
        # Fresh analysis starts from the saved no-analysis import.
        source = project.path/'engine'/image['image_id']
    jobid = uuid.uuid4().hex
    job = project.path/'jobs'/jobid
    job.mkdir(mode=0o700)
    (job/'tmp').mkdir(mode=0o700)
    outfile = job/'bridge.json'
    sandbox = job/'sandbox.sb'
    sandbox.write_text(profile(project, deps))
    g, j = Path(deps['ghidra_path']), Path(deps['java_home'])
    engine_dir = job/'program'
    if mode == 'import':
        engine_dir.mkdir(mode=0o700)
    else:
        shutil.copytree(source, engine_dir, symlinks=False)
    argv = ['/usr/bin/sandbox-exec', '-f', str(sandbox), str(g/'support/analyzeHeadless'), str(engine_dir), 'image']
    if mode == 'import':
        argv += ['-import', str(project.path/'inputs'/(image['image_id']+'.macho')), '-noanalysis', '-loader', 'MachoLoader', '-loader-loadLibraries', 'false', '-loader-linkExistingProjectLibraries', 'false', '-loader-reexport', 'false']
    else:
        argv += ['-process', image['image_id']+'.macho']
        if mode == 'query':
            argv += ['-readOnly', '-noanalysis']
        else:
            argv += ['-preScript', 'MacscopeProfile.java']
            if requested_profile['parameter_inference']:
                argv += [requested_profile['name']]
    max_functions = 1 if entry is not None else args.max_functions
    argv += ['-scriptPath', str(BRIDGE.resolve()), '-postScript', 'MacscopeBridge.java',
             str(outfile), mode, str(max_functions), str(args.function_timeout)]
    if entry is not None:
        argv.append(entry)
    argv += ['-max-cpu', '1', '-analysisTimeoutPerFile', str(args.timeout), '-log',
             str(job/'engine.log'), '-scriptlog', str(job/'script.log')]
    worker_home = project.path/'home'
    if entry is not None:
        # Concurrent readers use independent Ghidra user settings.
        worker_home = job/'home'
        worker_home.mkdir(mode=0o700)
    env = {'PATH':'/usr/bin:/bin:/usr/sbin:/sbin', 'HOME':str(worker_home), 'USER':os.environ.get('USER','macscope'), 'TMPDIR':str(job/'tmp')+'/', 'JAVA_HOME':str(j), 'GHIDRA_HEADLESS_MAXMEM':str(args.heap_mib)+'M', 'JAVA_TOOL_OPTIONS':'-Duser.home='+json.dumps(str(worker_home),ensure_ascii=False)+' -Djava.io.tmpdir='+json.dumps(str(job/'tmp'),ensure_ascii=False), 'LANG':'en_US.UTF-8'}
    manifest = {'job_id':jobid, 'mode':mode, 'analysis_profile':requested_profile, 'image_id':image['image_id'], 'dependencies':deps, 'limits':{'timeout_seconds':args.timeout,'function_timeout_seconds':args.function_timeout,'max_functions':max_functions,'jobs':1,'java_heap_mib':args.heap_mib,'process_memory_limit':None,'sampled_job_storage_bytes':512*1024*1024,'storage_is_hard_quota':False}, 'environment':env, 'sandbox_sha256':digest(sandbox)}
    if entry is not None:
        manifest.update(selected_entry=entry, source_analysis_id=image['active_analysis'])
    run_process(argv, cwd=job, env=env, timeout=args.timeout, log_path=job/'launcher.log', manifest_path=job/'job.json', manifest=manifest)
    try:
        if b'Skipping unsupported -loader-' in read_regular(job/'launcher.log',8*1024*1024):
            raise Error('loader_option_unsupported','Pinned loader rejected a requested safety option',4)
        result = json.loads(read_regular(outfile,64*1024*1024))
    except (ValueError, Error) as e:
        if isinstance(e,Error) and e.code=='loader_option_unsupported':
            manifest.update(status='failed',error={'code':e.code,'message':str(e)})
            write_json(job/'job.json',manifest,force=True)
            raise
        manifest.update(status='failed', error={'code':'bridge_result','message':'Missing, oversized or invalid bridge result'})
        write_json(job/'job.json',manifest,force=True)
        raise Error('bridge_result', 'Worker did not publish a valid bridge result; see private log', 10) from e
    try:
        if result.get('schema') != 'macscope-bridge/1' or result.get('mode') != mode or result.get('ghidra_version') != '12.2':
            raise Error('bridge_contract', 'Bridge result version/mode mismatch', 10)
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
        if entry is not None:
            rows = result.get('functions', [])
            if (result.get('selected_entry') != entry or len(rows) != 1
                    or rows[0].get('entry_va') != entry):
                raise Error('query_result_mismatch', 'Worker did not return the exact selected function', 10)
        if mode == 'import':
            destination = project.path/'engine'/image['image_id']
            if destination.exists():
                raise Error('engine_project_exists', 'An engine baseline already exists without an image record; inspect workspace before retry', 8)
            os.rename(engine_dir,destination)
    except (Error, OSError) as e:
        manifest.update(status='failed',error={'code':getattr(e,'code','bridge_publication'),'message':str(e)})
        write_json(job/'job.json',manifest,force=True)
        raise
    return result, manifest
