#!/usr/bin/env python3
"""Explicit local calculator-only integration; no dependency installation.

Run: PYTHONPATH=src python3 tests/integration_macscope.py
Creates a new ignored build/cli-integration-* directory on each run.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
from macscope.schema import validate_envelope, validate_function

ROOT=Path(__file__).resolve().parents[1]
WORK=ROOT/'build'/('cli-integration-'+time.strftime('%Y%m%d-%H%M%S'))
WORK.mkdir(mode=0o700)
ENV=dict(os.environ,PYTHONPATH=str(ROOT/'src'),PYTHONDONTWRITEBYTECODE='1')
records=[]

def cli(*args, expected=(0,), dot=False):
    start=time.monotonic()
    proc=subprocess.run([sys.executable,'-m','macscope',*map(str,args)],env=ENV,cwd=ROOT,capture_output=True,timeout=420)
    records.append({'argv':list(map(str,args)),'exit':proc.returncode,'elapsed_seconds':round(time.monotonic()-start,4)})
    (WORK/(str(len(records)).zfill(3)+'.stdout')).write_bytes(proc.stdout)
    (WORK/(str(len(records)).zfill(3)+'.stderr')).write_bytes(proc.stderr)
    assert proc.returncode in expected,(args,proc.returncode,proc.stdout.decode(),proc.stderr.decode())
    if dot:
        assert proc.stdout.startswith(b'digraph cfg {')
        return proc.stdout
    response=proc.stdout
    if not response and '--output' in args:
        response=Path(args[args.index('--output')+1]).read_bytes()
    data=json.loads(response)
    validate_envelope(data)
    return data

try:
    cli('version','--json')
    cli('doctor','--json')
    arm=ROOT/'build/analyst/DebugAnalysis-arm64-sym/CorpusFixture'
    x86=ROOT/'build/analyst/DebugAnalysis-x86_64-sym/CorpusFixture'
    aa,xx=arm.read_bytes(),x86.read_bytes()
    align=4096
    offa=align;offx=((offa+len(aa)+align-1)//align)*align
    universal=bytearray(offx+len(xx))
    universal[:8]=struct.pack('>II',0xcafebabf,2)
    universal[8:40]=struct.pack('>IIQQII',0x100000c,0,offa,len(aa),12,0)
    universal[40:72]=struct.pack('>IIQQII',0x1000007,3,offx,len(xx),12,0)
    universal[offa:offa+len(aa)]=aa;universal[offx:]=xx
    fat=WORK/'UniversalFixture';fat.write_bytes(universal)
    cli('inspect',fat,'--json')
    snapshots={}
    for label,source,arch in [('arm thin',arm,'arm64'),('x86 thin',x86,'x86_64'),('arm fat64',fat,'arm64'),('x86 fat64',fat,'x86_64')]:
        p=WORK/label
        cli('project','create',p,'--json')
        if source==fat:cli('import',source,'--project',p,'--experimental-trusted-input','--json',expected=(2,))
        cli('import',source,'--project',p,'--arch',arch,'--experimental-trusted-input','--json')
        cli('analyze','--project',p,'--experimental-trusted-input','--json',expected=(0,6))
        listed=cli('functions','list','--project',p,'--limit','1000','--json')
        f=next(f for f in listed['data'] if any(n['name']=='_calc_add' for n in f['names']))
        fid=f['function_id']
        opts=['--project',p,'--function-id',fid]
        shown=cli('functions','show',*opts,'--json');validate_function(shown['data'])
        cli('disasm',*opts,'--json',expected=(0,6))
        dec=cli('decompile',*opts,'--json',expected=(0,6));assert dec['data']['pseudocode']
        cli('decompile','--project',p,'--all','--limit','1000','--json',expected=(0,6))
        cli('xrefs',*opts,'--json',expected=(0,6))
        cli('cfg',*opts,'--json',expected=(0,6));cli('cfg',*opts,'--format','dot',dot=True,expected=(0,6))
        cli('status','--project',p,'--json')
        snap=cli('export','--project',p,'--json',expected=(0,6))['data']
        assert '/Users/' not in json.dumps(snap), 'absolute personal path in export'
        snapshots[label]=snap
        out=WORK/(label+'.json')
        cli('export','--project',p,'--json','--output',out,expected=(0,6))
        original=out.read_bytes()
        cli('export','--project',p,'--json','--output',out,expected=(8,))
        assert out.read_bytes()==original
        cli('export','--project',p,'--json','--output',out,'--force',expected=(0,6))
        assert out.read_bytes()==original
    # Exercise the production uncached runner, not a separate hand-built
    # invocation: it must reopen the active analyzed Program, never the
    # no-analysis baseline. There is deliberately no public refresh flag yet.
    from macscope import engine
    from macscope.cli import parser
    from macscope.storage import Project
    project=Project(WORK/'arm thin');image=project.select()
    snap,record=project.snapshot(image)
    source=project.path/'jobs'/record['job_id']/'program'
    before=engine.tree_digest(source)
    args=parser().parse_args(['analyze','--project',str(project.path),'--experimental-trusted-input'])
    raw,job=engine.run(project,image,'query',args,engine.dependencies(full=True))
    assert engine.tree_digest(source)==before
    assert len(raw['functions'])==len(snap['functions'])>9
    assert raw['validation']['headless_analysis_enabled'] is False
    assert '-readOnly' in job['argv'] and '-noanalysis' in job['argv']
    (WORK/'production-query-verification.json').write_text(json.dumps({'status':'passed','function_count':len(raw['functions']),'source_program_sha256':before,'query_job_id':job['job_id'],'autoanalysis':False},indent=2))
    for arch in ('arm','x86'):
        left,right=snapshots[arch+' thin'],snapshots[arch+' fat64']
        assert left['image']['sha256']==right['image']['sha256']
        def content(s):
            return [(f['engine_entry'],f['name'],f['pseudocode'],[(i['addr'],i['bytes'],i['text']) for i in f['instructions']]) for f in s['functions']]
        assert content(left)==content(right),arch+' thin/fat64 analysis mismatch'
    result={'status':'passed','checks':len(records),'commands':records,'slice_parity':['arm64','x86_64'],'workspaces':[str(p.relative_to(ROOT)) for p in WORK.iterdir() if p.is_dir()]}
    print(json.dumps({'status':'passed','command_checks':len(records),'artifacts':str(WORK)}))
except BaseException as e:
    result={'status':'failed','error':repr(e),'commands':records}
    raise
finally:
    (WORK/'report.json').write_text(json.dumps(result,indent=2))
