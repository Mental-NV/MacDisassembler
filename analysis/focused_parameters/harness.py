"""NON-SHIPPING, owned-only three-arm experiment. Never creates product receipts.

Run one arm per invocation on an operator-created private full import-only clone.
No native execution is performed by importing this module or running its tests.
"""
import argparse
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import uuid

from macscope import callee_parameters, engine, focused, storage
from macscope.direct_signatures import arm64_direct_target

SCHEMA = 'macscope-owned-focused-parameters/1'
# Extend only by reviewed source change after freezing a separately owned fixture.
OWNED = {'53345f8f9ae61fb42d41136fdf1d1733c9bdd7bf6410bbe676ebb03a09e5eaa0':
         ('0xc2c', '0xbec', '0xc48'),
         '210b766cf884c408b39abbebcff34d6e1ac74440883da86b03987d2aeab745f1':
         ('0x2c0', '0x2d4', '0x2c8')}
ARMS = {'caller', 'prepared', 'inferred'}
LIMITS = dict(timeout_seconds=240, startup_timeout_seconds=120,
              function_timeout_seconds=25, max_functions=1, jobs=1,
              java_heap_mib=2048, process_memory_limit=None,
              sampled_job_storage_bytes=512*1024*1024, storage_is_hard_quota=False)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    data = storage.canonical(value) + b'\n'
    require(len(data) <= 256*1024, 'request/report too large')
    with Path(path).open('xb') as stream:
        stream.write(data)
    Path(path).chmod(0o600)


def safe_path(path):
    path = Path(path).absolute()
    require(path == path.resolve(), 'noncanonical or symbolic path')
    require(not any(c in str(path) for c in ('"', '\\', '\n', '\r')), 'unsupported path')
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'symbolic ancestor')
    return path


def selection(image, caller, caller_bytes, callee, callee_bytes, site, arm):
    """Pure structural/byte guard; production harness obtains proofs via focused.select."""
    require(arm in ARMS and image['arch'] == 'arm64', 'arm/architecture')
    for proof, payload in ((caller, caller_bytes), (callee, callee_bytes)):
        start, end = (int(proof[k], 16) for k in ('entry_va', 'end_va_exclusive'))
        require(0 <= start < end < 1 << 63 and start % 4 == end % 4 == 0, 'extent addresses')
        require(type(proof['length']) is int and end-start == proof['length'] == len(payload)
                and 0 < len(payload) <= 8192, 'extent length')
        require(sha256(payload).hexdigest() == proof['extent_sha256'], 'stale extent bytes')
        require(proof['policy'] == focused.POLICY, 'extent policy')
    a,b,c,d = (int(p[k],16) for p in (caller,callee) for k in ('entry_va','end_va_exclusive'))
    require(not (a < d and c < b) and b-a+d-c <= 16384, 'overlap/combined budget')
    at = int(site,16)
    require(a <= at < b and at % 4 == 0, 'call outside caller')
    raw = caller_bytes[at-a:at-a+4]
    require(len(raw)==4 and arm64_direct_target(at,raw)==c, 'not exact direct BL edge')
    return dict(policy=callee_parameters.POLICY, image_sha256=image['sha256'],arch='arm64',
                entry_va=caller['entry_va'], requests=[dict(target_va=callee['entry_va'],path=[
                    dict(owner_va=caller['entry_va'],call_va=site,target_va=callee['entry_va'],bytes=raw.hex())])],
                experiment=SCHEMA,arm=arm,caller=caller,callee=callee)


def validate_guards(request, guards, recovery):
    require(isinstance(guards,dict) and set(guards)=={'schema','arm','body_checks','native_checks'}
            and guards['schema']==SCHEMA and guards['arm']==request['arm'], 'guard identity')
    bodies, checks = guards['body_checks'], guards['native_checks']
    require(isinstance(bodies,list) and 1 <= len(bodies) <= 32, 'body checks')
    expected = {request['caller']['entry_va']: (request['caller']['extent_sha256'],False)}
    if request['arm'] != 'caller':
        expected[request['callee']['entry_va']] = (request['callee']['extent_sha256'],True)
    seen=set()
    for row in bodies:
        require(isinstance(row,dict) and set(row)=={'entry_va','extent_sha256','leaf'} and
                type(row['leaf']) is bool and expected.get(row['entry_va'])==(row['extent_sha256'],row['leaf']), 'body scope')
        seen.add(row['entry_va'])
    require(seen==set(expected), 'missing body checks')
    require(isinstance(checks,list) and len(checks)<=16, 'native checks')
    phases=set()
    for row in checks:
        require(isinstance(row,dict) and set(row)=={'entry_va','extent_sha256','operations_scanned','phase','status'}
                and row['entry_va']==request['callee']['entry_va'] and
                row['extent_sha256']==request['callee']['extent_sha256'] and row['status']=='complete'
                and type(row['operations_scanned']) is int and 0<row['operations_scanned']<=100000
                and row['phase'] in {'before_commit','after_commit'}, 'native scope check')
        phases.add(row['phase'])
    if request['arm']!='inferred':
        require(not checks and recovery is None, 'unexpected inference')
        return None
    decision=callee_parameters.decision(request,recovery)
    if decision['status']=='applied':
        require(phases=={'before_commit','after_commit'}, 'missing pre/post commit scope')
    return decision


def validate_raw(raw, image, deps, caller_entry):
    """Nonpublishing bridge contract gate. Keep raw diagnostics unchanged."""
    require(isinstance(raw,dict), 'bridge root must be an object')
    require(raw.get('schema')=='macscope-bridge/1' and raw.get('mode')=='query'
            and raw.get('ghidra_version')==engine.engine_checks.GHIDRA_VERSION
            and raw.get('bridge_version')==engine.BRIDGE_VERSION, 'bridge version/mode mismatch')
    # validate_bridge_shape deliberately allows early failed engine reports.
    # This experiment must not treat those operational failures as checked evidence.
    require(raw.get('status') in {'complete','partial'}, 'bridge failed or invalid status')
    engine.validate_bridge_shape(raw,1,full_functions=True)
    engine.verify_macho_loader(raw,image)
    engine.engine_checks.verify_runtime(raw.get('java_runtime'),deps['java_home'])
    require(raw.get('selected_entry')==caller_entry and len(raw['functions'])==1
            and raw['functions'][0].get('entry_va')==caller_entry, 'bridge selected root differs')
    require(raw['validation'].get('headless_analysis_enabled') is False, 'autoanalysis not explicitly disabled')
    for field in ('applied_type_hints','aggregate_type_layouts'):
        value=raw.get(field,[])
        require(isinstance(value,list) and not value, 'unrequested or malformed type evidence: '+field)
    # Existing validator pops timing; operate on a copy to retain raw evidence.
    timing=engine.decompiler_timing(copy.deepcopy(raw),1)
    return {'raw_status':raw['status'],'decompiler_timing':timing}


def verify_caller(proof, payload, report, function):
    focused.verify(proof,payload,report,function)
    focused.verify_native_scope(function)
    require(function.get('decompile_status')=='complete' and function['native_scope']['status']=='complete'
            and function['native_scope']['operations_scanned']>0, 'caller incomplete')
    require(function.get('body_ranges')==[[proof['entry_va'],hex(int(proof['end_va_exclusive'],16)-1)]], 'caller body changed')
    require([row['addr'] for row in function['instructions']]==
            [hex(a) for a in range(int(proof['entry_va'],16),int(proof['end_va_exclusive'],16),4)]
            and all(len(bytes.fromhex(row['bytes']))==4 for row in function['instructions']), 'caller instruction gaps')


def run(args):
    engine.require_worker_host()
    require(args.trust_owned_input and args.disposable_import_clone, 'explicit owned trust and disposable clone required')
    root=safe_path(args.project)
    require(root.is_dir() and root.stat().st_mode & 0o077 == 0, 'private clone directory required')
    project=storage.Project(root)
    with project.writer():
        return run_locked(project,args)


def run_locked(project,args):
    image=project.select(arch='arm64')
    require(image['active_analysis'] is None, 'import-only clone required')
    require(image['sha256'] in OWNED, 'input not frozen owned fixture')
    caller_entry,callee_entry,site=OWNED[image['sha256']]
    caller,cp=focused.select(project,image,caller_entry)
    callee,dp=focused.select(project,image,callee_entry)
    request=selection(image,caller,cp,callee,dp,site,args.arm)
    deps=engine.dependencies(args.ghidra,args.java_home,full=True)
    old=image.get('import_dependencies')
    require(image['imported'] and isinstance(old,dict) and deps.get('ghidra_tree_sha256') and
            deps['ghidra_tree_sha256']==old.get('ghidra_tree_sha256') and engine.matches_auxiliary_jdk(old,deps), 'import runtime mismatch')
    engine.verify_auxiliary_jdk(deps)
    source=safe_path(engine.import_program_path(project,image))
    original=engine.saved_program_digest(source,'baseline_integrity')
    require(original==image.get('engine_baseline_sha256'), 'import digest mismatch')
    normalized=engine.tree_digest(source,ignore=focused.PROJECT_BACKUPS)
    bucket=project.path/'experiments'
    if not bucket.exists(): bucket.mkdir(mode=0o700)
    safe_path(bucket)
    require(bucket.stat().st_mode & 0o077 == 0, 'private experiment directory required')
    jobid=uuid.uuid4().hex
    attempt=bucket/jobid; attempt.mkdir(mode=0o700)
    worker=attempt/'worker'; worker.mkdir(mode=0o700)
    pins={}
    def pin(path): pins[str(path)]=digest(path)
    def recheck():
        for path,expected in pins.items():
            require(safe_path(path).is_file() and digest(path)==expected, 'pinned file changed')
        require(engine.saved_program_digest(source,'baseline_integrity')==original, 'source import changed')
        require(focused.select(project,image,caller_entry)==(caller,cp) and
                focused.select(project,image,callee_entry)==(callee,dp), 'source/extent changed')
        engine.verify_auxiliary_jdk(deps)
        require(engine.dependencies(args.ghidra,args.java_home,full=True)==deps, 'runtime dependencies changed')
    pin(project.path/'project.json'); pin(project.path/'index.sqlite'); pin(safe_path(__file__))
    try:
        (worker/'home').mkdir(mode=0o700); (worker/'tmp').mkdir(mode=0o700)
        engine.copy_program(source,worker/'program',original,'baseline_integrity')
        scripts=worker/'bridge'; scripts.mkdir(mode=0o700)
        sources=[engine.BRIDGE/name for name in ('MacscopeFocus.java','MacscopeBridge.java','RecoverCallSignatures.java')]
        sources.append(Path(__file__).with_name('OwnedScopedParameters.java'))
        for src in sources:
            src=safe_path(src); pin(src); dst=scripts/src.name; shutil.copyfile(src,dst); pin(dst)
        write(attempt/'request.json',request); pin(attempt/'request.json')
        shutil.copyfile(attempt/'request.json',worker/'request.json'); pin(worker/'request.json')
        argv=['/usr/bin/sandbox-exec','-f',str(attempt/'sandbox.sb'),str(Path(deps['ghidra_path'])/'support/analyzeHeadless'),
              str(worker/'program'),'image','-process',image['image_id']+'.macho','-readOnly','-noanalysis']
        for label,proof in ([('callee',callee)] if args.arm!='caller' else [])+[('caller',caller)]:
            tail=worker/(label+'-tail.json'); write(tail,proof['tail_calls']); pin(tail)
            argv+=['-preScript','MacscopeFocus.java',str(worker/(label+'-focus.json')),image['sha256'],
                   proof['entry_va'],proof['end_va_exclusive'],proof['extent_sha256'],str(tail),digest(tail)]
        argv+=['-preScript','OwnedScopedParameters.java',str(worker/'request.json'),str(worker/'recovery.json'),'25',
               '-scriptPath',str(scripts),'-postScript','MacscopeBridge.java',str(worker/'bridge.json'),'query','1','25',caller_entry,'--from-import',
               '-max-cpu','1','-analysisTimeoutPerFile','240','-log',str(worker/'engine.log'),'-scriptlog',str(worker/'script.log')]
        sandbox=engine.profile(project,deps,write_root=worker,read_only_program=True)
        (attempt/'sandbox.sb').write_text(sandbox); pin(attempt/'sandbox.sb')
        env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(worker/'home'),'TMPDIR':str(worker/'tmp')+'/',
             'USER':os.environ.get('USER','macscope'),'JAVA_HOME':deps['java_home'],'GHIDRA_HEADLESS_MAXMEM':'2048M',
             'JAVA_TOOL_OPTIONS':'-Duser.home='+json.dumps(str(worker/'home'))+' -Djava.io.tmpdir='+json.dumps(str(worker/'tmp')),'LANG':'en_US.UTF-8'}
        manifest={'schema':SCHEMA,'kind':'owned_feasibility_operation','mode':'query','job_id':jobid,
                  'image_id':image['image_id'],'dependencies':deps,'limits':LIMITS,'environment':env,'sandbox_sha256':digest(attempt/'sandbox.sb')}
        write(attempt/'pins.json',{'files':pins,'program_sha256':original,'normalized_program_sha256':normalized,'dependencies':deps,'limits':LIMITS})
        pin(attempt/'pins.json')
        recheck()
        engine.run_process(argv,cwd=worker,env=env,timeout=240,startup_timeout=120,log_path=worker/'worker.log',
                           manifest_path=attempt/'operation.json',manifest=manifest)
        recheck()
        require(engine.tree_digest(worker/'program',ignore=focused.PROJECT_BACKUPS)==normalized,'copied Program changed')
        raw=engine.read_worker_object(worker/'bridge.json',32*1024*1024)
        raw_checks=validate_raw(raw,image,deps,caller_entry)
        read=lambda name: engine.read_worker_object(worker/name,256*1024)
        verify_caller(caller,cp,read('caller-focus.json'),raw['functions'][0])
        recovery=read('recovery.json') if (worker/'recovery.json').exists() else None
        decision=validate_guards(request,read('recovery.json.guards.json'),recovery)
        write(attempt/'assessment.json',{'schema':SCHEMA,'status':'evidence_checked','arm':args.arm,
              'parameter_decision':decision,'raw_checks':raw_checks,'limitations':['not source correctness','not product receipt','native negative gates separate','not performance evidence']})
        return attempt
    except BaseException as exc:
        integrity_error=None
        try: recheck()
        except Exception as check: integrity_error=str(check)
        write(attempt/'failure.json',{'schema':SCHEMA,'status':'failed','error':str(exc),'integrity_error':integrity_error})
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project',type=Path)
    parser.add_argument('arm',choices=sorted(ARMS))
    parser.add_argument('--ghidra',required=True); parser.add_argument('--java-home',required=True)
    parser.add_argument('--trust-owned-input',action='store_true')
    parser.add_argument('--disposable-import-clone',action='store_true')
    print(run(parser.parse_args()))

if __name__=='__main__': main()
