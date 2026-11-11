"""Installed saved-receipt hints in a spaced/quoted path; no native execution."""
import json
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
from integration_native_terminal_thunk import snapshot
import integration_native_callback_counterexamples as gate


def run(project,manifest,expected_links):
    gate.require(expected_links in (0,1),'Only owned writer and paired-thunk gates supported')
    pins=({'bcba2294518b4a04acdd5d6a5b84d553':'a210afeb015a2dbdb025afdf2174d9feceb68ecffcf44d22af5158d9e2667d2a',
           'cf58ff5c1fe54772b9d901a2edce8582':'349e3b3ebf278c2575938019564a2b15c8436ab04907f8ba90279ccdabd1cacd'} if expected_links else
          {'883e5bf9a82944b9b73d7cc1174800e7':'68e46e45d926d9b13422de266956aedd56c3523370b834aefe56fa33e7783f1f'})
    leads,_=gate.bounded_json(manifest,gate.MAX_MANIFEST)
    gate.require({r['query_job'] for r in leads['leads']}==set(pins),'Unexpected selected jobs')
    for job,digest in pins.items():
        _,raw=gate.bounded_json(project/'jobs'/job/'query-result.json',gate.MAX_RECEIPT)
        gate.require(hashlib.sha256(raw).hexdigest()==digest,'Native receipt pin changed')
    original=snapshot(project)
    # Copy only the supplied owned portable project; no system CLI installation.
    with tempfile.TemporaryDirectory(prefix='macscope-links-') as temporary:
        root=Path(temporary);copy=root/"owned project 'quoted";shutil.copytree(project,copy);copy.chmod(0o700)
        pinned=root/'leads.json';pinned.write_bytes(manifest.read_bytes());before=snapshot(copy)
        env=dict(os.environ,PATH=str(Path(sys.executable).parent)+os.pathsep+os.environ.get('PATH',''))
        gate.require((Path(sys.executable).parent/'macscope').is_file(),'Run using an installed isolated wheel')
        base=[sys.executable,'-m','macscope','evidence','--project',str(copy),'--leads',str(pinned)]
        outputs=[]
        for _ in range(2):
            r=subprocess.run(base+['--reference-links','--format','json'],cwd=root,env=env,capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=60)
            gate.require(r.returncode==6,'Expected partial selected graph');outputs.append(r.stdout)
        gate.require(outputs[0]==outputs[1],'Nondeterministic selected view')
        view=json.loads(outputs[0])['data']['selected_reference_links']
        receipts=view['receipts'];gate.require(receipts and all(r['status']=='verified' for r in receipts),'Expected verified owned receipts')
        selected=[ref for row in receipts for ref in row['references'] if ref['status']=='verified_selected_direct_link']
        gate.require(len(selected)==expected_links,'Unexpected verified selected edges')
        for row in receipts:
            hint=row['command'];gate.require(hint is not None,'Missing safe hint')
            args=shlex.split(hint)
            gate.require(args[args.index('--project')+1]==str(copy),'Unsafe path quoting')
            gate.require(args[args.index('--query-job')+1]==row['requested_job_id'],'Wrong receipt hint')
            outputs=[subprocess.run(args,cwd=root,env=env,capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=60) for _ in range(2)]
            gate.require(outputs[0].returncode in (0,6) and outputs[0].stdout==outputs[1].stdout,'Hint replay failed')
            gate.require(row['publication_job_id'] in outputs[0].stdout and 'recorded_selected_function_only' in outputs[0].stdout,'Wrong selected provenance')
        compact=subprocess.run(base+['--format','links'],cwd=root,env=env,capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=60)
        gate.require(compact.returncode==6 and len(compact.stdout.encode())<=32768 and len(compact.stdout.splitlines())<=200,'Compact status/budget failed')
        gate.require(snapshot(copy)==before,'Commands changed copied project')
    gate.require(snapshot(project)==original,'Original project changed')
    print(f'PASS: {expected_links} actual selected links; quoted installed hints execute outside checkout; partial scope and all project bytes preserved')


if __name__=='__main__':run(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),int(sys.argv[3]))
