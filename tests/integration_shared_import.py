#!/usr/bin/env python3
"""Opt-in fixed owned fixture only. No production batch protocol or speed claim."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
NAMES={'_owned_add','_owned_select','_owned_mix'}


def validate_orders(preparation,calls):
    if sorted(preparation)!=[0,1,2] or any(type(n) is not int for n in preparation):
        raise ValueError('Three unique owned preparation entries required')
    if not 1<=len(calls)<=6 or any(type(n) is not int or n not in (0,1,2) for n in calls):
        raise ValueError('Invalid bounded call order')


def validate_output(value,entries,calls):
    if not isinstance(value,dict) or value.get('schema')!='owned-shared-import/1' or value.get('semantics')!='shared-import-preparation':
        raise ValueError('Invalid experiment output')
    if [r.get('entry') for r in value.get('prepared',[])]!=entries:
        raise ValueError('Prepared selection differs')
    if [r.get('entry') for r in value.get('calls',[])]!=[entries[i] for i in calls]:
        raise ValueError('Call sequence differs')
    for row in value['calls']:
        if row.get('completed') is not True or not isinstance(row.get('pseudocode'),str) or not row['pseudocode'].strip():
            raise ValueError('Incomplete owned output; retain evidence, no comparison claim')
    return value


def run(output):
    from macscope import cli,engine,focused,metadata
    from macscope.storage import Project,write_json
    from macscope.engine import digest
    output.mkdir(mode=0o700) # Refuse overwrite, retain all trials.
    def command(*args):
        name=f'cli-{len(list(output.glob("cli-*.json")))+1:03}'
        with (output/(name+'.json')).open('w') as out,(output/(name+'.stderr')).open('w') as err:
            with redirect_stdout(out),redirect_stderr(err):code=cli.main([*map(str,args),'--json'])
        if code not in (0,6):raise RuntimeError(f'{name} failed: {code}')
        return json.loads((output/(name+'.json')).read_text())
    compiled=subprocess.run(['xcrun','clang','-O0','-fno-inline','-arch','arm64',str(ROOT/'fixture/batch/owned_batch.c'),'-o',str(output/'owned')],capture_output=True,timeout=30)
    (output/'compiler.stdout').write_bytes(compiled.stdout);(output/'compiler.stderr').write_bytes(compiled.stderr)
    compiled.check_returncode()
    symbols=subprocess.run(['xcrun','nm','-n',str(output/'owned')],capture_output=True,text=True,timeout=30,check=True).stdout
    (output/'symbols.txt').write_text(symbols)
    selected={line.split()[-1]:hex(int(line.split()[0],16)) for line in symbols.splitlines() if line.split() and line.split()[-1] in NAMES}
    if set(selected)!=NAMES:raise RuntimeError('Owned symbols differ')
    entries=sorted(selected.values(),key=lambda v:int(v,16))
    command('project','create',output/'project')
    command('import',output/'owned','--project',output/'project','--arch','arm64','--trust-input','--timeout','120','--startup-timeout','60')
    project=Project(output/'project');image=project.select();deps=engine.dependencies(full=True)
    source=engine.imported_program(project,image);baseline=engine.tree_digest(source)
    content=engine.tree_digest(source,ignore=focused.PROJECT_BACKUPS)
    proofs=[focused.select(project,image,e)[0] for e in entries]
    spans=[{k:p[k] for k in ('entry_va','end_va_exclusive','extent_sha256')} for p in proofs]
    isolated=[]
    for e in entries:
        isolated.append(command('decompile','--project',project.path,'--address',e,'--from-import','--trust-input','--timeout','90','--startup-timeout','60'))
    write_json(output/'isolated.json',isolated)
    trials=[]
    for prep,calls in [([0,1,2],[0,1,2,0,1]),([2,1,0],[0,1,2,0,1]),([0,1,2],[1,0,2,1,0])]:
        validate_orders(prep,calls)
        with project.writer():
            jobid=uuid.uuid4().hex;job=project.path/'jobs'/jobid;job.mkdir(mode=0o700)
            for folder in ('tmp','home','scripts'):(job/folder).mkdir(mode=0o700)
            script=job/'scripts/OwnedSharedImport.java';shutil.copyfile(ROOT/'fixture/shared-import/OwnedSharedImport.java',script)
            engine.copy_program(source,job/'program',baseline,'baseline_integrity')
            plan={'input_sha256':image['sha256'],'spans':spans,'preparation_order':prep,'call_order':calls}
            write_json(job/'plan.json',plan)
            sandbox=job/'sandbox.sb';sandbox.write_text(engine.profile(project,deps,write_root=job,read_only_program=True))
            g,j=Path(deps['ghidra_path']),Path(deps['java_home'])
            argv=['/usr/bin/sandbox-exec','-f',str(sandbox),str(g/'support/analyzeHeadless'),str(job/'program'),'image','-process',image['image_id']+'.macho','-readOnly','-noanalysis','-scriptPath',str(job/'scripts'),'-postScript','OwnedSharedImport.java',str(job/'plan.json'),str(job/'output.json'),'-max-cpu','1','-analysisTimeoutPerFile','90','-log',str(job/'engine.log'),'-scriptlog',str(job/'script.log')]
            env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(job/'home'),'USER':os.environ.get('USER','macscope'),'TMPDIR':str(job/'tmp')+'/','JAVA_HOME':str(j),'GHIDRA_HEADLESS_MAXMEM':'2048M','JAVA_TOOL_OPTIONS':'-Duser.home='+str(job/'home')+' -Djava.io.tmpdir='+str(job/'tmp'),'LANG':'en_US.UTF-8'}
            manifest={'job_id':jobid,'image_id':image['image_id'],'mode':'query','experiment':'owned-shared-import/1','dependencies':deps,'plan_sha256':digest(job/'plan.json'),'script_sha256':digest(script),'sandbox_sha256':digest(sandbox),'limits':{'max_functions':3,'max_calls':6,'function_timeout_seconds':15,'sampled_job_storage_bytes':512*1024*1024}}
            engine.verify_auxiliary_jdk(deps)
            engine.run_process(argv,cwd=job,env=env,timeout=90,startup_timeout=60,log_path=job/'launcher.log',manifest_path=job/'job.json',manifest=manifest)
            engine.verify_auxiliary_jdk(deps)
            if engine.tree_digest(source)!=baseline or engine.tree_digest(job/'program',ignore=focused.PROJECT_BACKUPS)!=content:raise RuntimeError('Program changed')
            if digest(script)!=manifest['script_sha256'] or digest(job/'plan.json')!=manifest['plan_sha256']:
                raise RuntimeError('Experiment script or plan changed')
            value=validate_output(engine.read_worker_object(job/'output.json',1024*1024),entries,calls)
            trials.append({'job_id':jobid,'preparation_order':prep,'call_order':calls,'output':value,'baseline_preserved':True})
            write_json(output/'trials.json',trials,force=True)
    prep_equal=trials[0]['output']['prepared']==trials[1]['output']['prepared']==trials[2]['output']['prepared']
    if not prep_equal:raise RuntimeError('Preparation-order evidence differs; no acceptance')
    repeats={e:[r for t in trials for r in t['output']['calls'] if r['entry']==e] for e in entries}
    call_equal={e:all(r==rows[0] for r in rows) for e,rows in repeats.items()}
    # Compare only the explicitly common pseudocode/body/instruction-byte subset.
    comparisons=[]
    for e,iso in zip(entries,isolated):
        data=iso['data'];shared=repeats[e][0]
        comparisons.append({'entry':e,'isolated_status':iso['status'],'pseudocode_equal':data['pseudocode']==shared['pseudocode'],'body_ranges_equal':data['body_ranges']==shared['body_ranges'],'instruction_bytes_equal':[(r['addr'],r['bytes']) for r in data['instructions']]==[(r['address'],r['bytes']) for r in shared['instructions']]})
    report={'schema':'owned-shared-import-comparison/1','preparation_equal':prep_equal,'sampled_order_acceptance':prep_equal and all(call_equal.values()),'repeated_full_captured_record_equal':call_equal,'isolated_common_subset':comparisons,'limitations':['Captured record is C, signature, name, body ranges, instruction bytes/flow and error/completion only; not production full evidence.','No speedup, full parity, interruption/cancellation or production readiness claim.'],'runner_sha256':digest(Path(__file__)),'script_sha256':digest(ROOT/'fixture/shared-import/OwnedSharedImport.java'),'fixture_sha256':digest(ROOT/'fixture/batch/owned_batch.c'),'input_sha256':digest(output/'owned'),'baseline_preserved':engine.tree_digest(source)==baseline}
    write_json(output/'comparison.json',report);print(json.dumps(report,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true');parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    if not args.run:parser.error('--run required for owned native experiment')
    existed=args.out.exists()
    try:
        run(args.out)
    except BaseException as error:
        if not existed and args.out.is_dir():
            (args.out/'failure.json').write_text(json.dumps({'error_type':type(error).__name__,'message':str(error),'status':'stopped; retained evidence; no subsequent trial'},indent=2)+'\n')
        raise
