"""Owned native positive/negative gate. Never capture, execute, or analyze inputs.

Usage with an installed package, outside the checkout:
  python integration_native_callback_counterexamples.py PROJECT MANIFEST
The externally preserved native capture must use the documented owned fixture.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

SCHEMA='macscope-owned-native-counterexamples/1'
ROLES=('assignment','invocation','thunk','writer')
CASES=('overwritten_target','unknown_target')
MAX_MANIFEST=65536
MAX_RECEIPT=2*1024*1024
MAX_JOB_FILES=256
MAX_JOB_FILE=16*1024*1024
MAX_JOB_BYTES=64*1024*1024
HEX=re.compile(r'0x[0-9a-f]{1,16}')
DIGEST=re.compile(r'[0-9a-f]{64}')
JOB=re.compile(r'[0-9a-f]{32}')
REQUIRED_UNKNOWNS={'assignment_and_invocation_slot_identity','intervening_memory_unchanged',
    'runtime_invoked_code_identity','runtime_context_identity_and_abi','execution_order',
    'application_writer_attribution','persistence','writer_callee_memory_side_effects',
    'receiver_lifetime_after_writer_calls','writer_calls_may_not_return_normally',
    'context_lifetime_after_calls','alternate_branch_paths_not_analyzed'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bounded_json(path, limit):
    require(path.is_file() and not path.is_symlink(),'Expected regular JSON file')
    with path.open('rb') as stream:
        raw=stream.read(limit+1)
    require(len(raw)<=limit,'JSON file exceeds gate budget')
    return json.loads(raw),raw


def validate_manifest(value):
    require(isinstance(value,dict) and set(value)=={'schema','positive','negative'} and value['schema']==SCHEMA,'Invalid gate manifest')
    require(isinstance(value['positive'],dict) and set(value['positive'])==set(ROLES),'Four positive roles required')
    require(isinstance(value['negative'],dict) and set(value['negative'])==set(CASES),'Both negative controls required')
    entries=list(value['positive'].values())+list(value['negative'].values())
    jobs=set();identity=None
    fields={'arch','container_file_offset','end_va','image_id','policy','program_sha256','project_id',
            'range_sha256','requested_bytes','slice_file_offset','slice_sha256','start_va'}
    for e in entries:
        require(isinstance(e,dict) and set(e)=={'job_id','range','receipt_sha256','selection'},'Invalid receipt pin')
        require(isinstance(e['job_id'],str) and JOB.fullmatch(e['job_id']) and e['job_id'] not in jobs,'Job IDs must be distinct canonical IDs')
        jobs.add(e['job_id'])
        require(isinstance(e['receipt_sha256'],str) and DIGEST.fullmatch(e['receipt_sha256']),'Invalid receipt digest')
        s=e['selection']
        require(isinstance(s,dict) and set(s)==fields,'Invalid selection binding')
        require(s['arch']=='arm64' and s['policy']=='macscope-import-disasm/1','Unsupported selection policy')
        for key in ('container_file_offset','end_va','slice_file_offset','start_va'):
            require(isinstance(s[key],str) and HEX.fullmatch(s[key]) and hex(int(s[key],16))==s[key],'Noncanonical selection address')
        start,end=int(s['start_va'],16),int(s['end_va'],16)
        require(start%4==end%4==0 and 0<end-start<=4096,'Selection outside gate bounds')
        require(type(s['requested_bytes']) is int and s['requested_bytes']==end-start,'Incorrect selected byte count')
        require(e['range']==s['start_va']+':'+s['end_va'],'Range disagrees with selection')
        for key in ('image_id','program_sha256','range_sha256','slice_sha256'):
            require(isinstance(s[key],str) and DIGEST.fullmatch(s[key]),'Invalid selection digest')
        require(isinstance(s['project_id'],str) and JOB.fullmatch(s['project_id']),'Invalid project identity')
        current=tuple(s[k] for k in ('arch','image_id','program_sha256','project_id','slice_sha256'))
        require(identity is None or current==identity,'Controls must share exact image/import/project identity')
        identity=current
    ranges={(e['selection']['start_va'],e['selection']['end_va']) for e in (value['positive']['assignment'],*value['negative'].values())}
    require(len(ranges)==3,'Assignment controls must use distinct ranges')
    return value


def job_snapshot(project):
    result={}
    total=0
    observed_total=0
    for path in (project/'jobs').rglob('*'):
        require(not path.is_symlink(),'Symlink in gate job tree')
        if not path.is_file():
            continue
        size=path.stat().st_size
        total+=size
        require(len(result)<MAX_JOB_FILES and size<=MAX_JOB_FILE and total<=MAX_JOB_BYTES,'Job snapshot exceeds gate budget')
        digest=hashlib.sha256()
        observed=0
        with path.open('rb') as stream:
            for chunk in iter(lambda:stream.read(65536),b''):
                observed+=len(chunk);observed_total+=len(chunk)
                require(observed<=MAX_JOB_FILE and observed_total<=MAX_JOB_BYTES,'Streamed job snapshot exceeds gate budget')
                digest.update(chunk)
        require(observed==size,'Job changed during snapshot')
        result[str(path.relative_to(project))]=digest.hexdigest()
    return result


def verify_receipts(project,manifest):
    expected_envelopes={}
    for e in (*manifest['positive'].values(),*manifest['negative'].values()):
        response,raw=bounded_json(project/'jobs'/e['job_id']/'disasm-result.json',MAX_RECEIPT)
        require(hashlib.sha256(raw).hexdigest()==e['receipt_sha256'],'Receipt digest mismatch')
        require(response.get('data',{}).get('selection')==e['selection'],'Receipt selection mismatch')
        canonical=json.dumps(response,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('utf-8')
        expected_envelopes[e['job_id']]=hashlib.sha256(canonical).hexdigest()
    return expected_envelopes


def check_result(manifest,name,response,expected_envelopes):
    comp=response['data']['callback_evidence']['composition']
    require(comp['status']=='inconclusive','Composition must remain inconclusive')
    for key in ('application_writer_attribution','runtime_execution','persistence'):
        require(comp['destination_effects'][key]=='unknown','Application/runtime attribution was promoted')
    for key in REQUIRED_UNKNOWNS:
        require(key in comp['unknowns'],'Required unknown disappeared')
    assignment=manifest['positive']['assignment'] if name=='positive' else manifest['negative'][name]
    pins=dict(manifest['positive'],assignment=assignment)
    for role in ROLES:
        require(comp['role_identities'][role]['selection']==pins[role]['selection'],'Output role identity mismatch')
    def inside(address,role):
        e=pins[role]['selection']
        return isinstance(address,str) and HEX.fullmatch(address) and int(e['start_va'],16)<=int(address,16)<int(e['end_va'],16)
    for role in ROLES:
        source=comp['role_identities'][role].get('source_envelope_sha256')
        require(isinstance(source,str) and DIGEST.fullmatch(source),'Role source-envelope identity missing')
        require(source==expected_envelopes[pins[role]['job_id']],'Output envelope identity differs from pinned receipt')
    proof=comp['writer_call_evidence']
    for key in ('application_writer_attribution','runtime_execution','persistence'):
        require(proof[key]=='unknown','Writer attribution was promoted')
    paths=comp['path_obligations']
    require(len(paths)==1,'Expected one scoped invocation path obligation')
    path=paths[0];branch=path.get('evidence',{})
    require(path.get('role')=='invocation' and path.get('source_envelope_sha256')==comp['role_identities']['invocation']['source_envelope_sha256'],'Path obligation scope mismatch')
    require(branch.get('kind')=='conditional_branch' and inside(branch.get('instruction_va'),'invocation')
            and branch.get('fallthrough_predicate')=='nonzero' and branch.get('taken_path')=='not_analyzed','Native branch obligation missing')
    calls=comp['call_obligations']
    require(len(calls)==2 and {c.get('role') for c in calls}=={'invocation','writer'},'Expected scoped invocation and writer call obligations')
    for call in calls:
        role=call['role'];evidence=call.get('evidence',{})
        require(call.get('source_envelope_sha256')==comp['role_identities'][role]['source_envelope_sha256']
                and evidence.get('kind')=='direct_call' and inside(evidence.get('instruction_va'),role),'Call obligation scope mismatch')
        require(call.get('memory_effects')=='unknown' and {'normal_return','AAPCS64_callee_preservation'}<=set(call.get('requires',[])),'Call assumptions/side effects missing')
    if name=='positive':
        require(comp['candidate_status']=='conditional_candidate','Positive control did not compose')
        require(comp['writer_call_evidence']['status']=='conditional_obligations','Positive writer obligations missing')
        require(proof['post_call_stores'] and all(s['status']=='conditional_operands' for s in proof['post_call_stores']),'Positive writer store relations missing')
    else:
        require(comp['candidate_status']=='gap','Negative control incorrectly composed')
        require({'reason':'unique_paired_assignment_not_proven'} in comp['gaps'],'Expected target-mismatch gap missing')
        report=comp['independent_evidence']['assignment']
        require(report['selection']==assignment['selection'],'Independent assignment scope mismatch')
        require(not report['gaps'] and report['stop_reason']=='selected_prefix_end','Negative must retain a decoded assignment, not vacuous decoder failure')
        stores=[s for s in report['sites'] if s['kind']=='memory_store']
        require(len(stores)==2 and [s.get('lane') for s in stores]==[0,1],'Native paired assignment evidence missing')
        require(stores[0]['instruction_va']==stores[1]['instruction_va'] and inside(stores[0]['instruction_va'],'assignment'),'Store pair instruction identity mismatch')
        target=stores[0]['value']
        if name=='overwritten_target':
            require(target['kind']=='address' and target['value']!=manifest['positive']['thunk']['selection']['start_va'],'Overwrite target mismatch not evidenced')
        else:
            require(target['kind']=='range_input_register' and target.get('selection_start_va')==assignment['selection']['start_va']
                    and target.get('source_envelope_sha256')==comp['role_identities']['assignment']['source_envelope_sha256'],'Unknown target must retain selected-input provenance')
    return comp


def run(project,manifest):
    manifest=validate_manifest(manifest)
    before=job_snapshot(project)
    expected_envelopes=verify_receipts(project,manifest)
    common=[sys.executable,'-m','macscope','disasm','--project',str(project),'--from-import',
            '--range',manifest['positive']['thunk']['range'],'--receipt',manifest['positive']['thunk']['job_id'],
            '--callback-evidence','--callback-provenance','--callback-abi','aapcs64',
            '--callback-target-receipt',manifest['positive']['writer']['job_id'],
            '--callback-invocation-receipt',manifest['positive']['invocation']['job_id'],
            '--callback-context-register','x20','--callback-invocation-fallthrough','--callback-writer-call-obligations',
            '--ghidra','/nonexistent/ghidra','--java-home','/nonexistent/java','--format','json']
    for name in ('positive',*CASES):
        e=manifest['positive']['assignment'] if name=='positive' else manifest['negative'][name]
        args=common+['--callback-assignment-receipt',e['job_id']]
        first=subprocess.run(args,capture_output=True,text=True,check=True,timeout=60)
        second=subprocess.run(args,capture_output=True,text=True,check=True,timeout=60)
        require(first.stdout==second.stdout,'Replay was not deterministic')
        check_result(manifest,name,json.loads(first.stdout),expected_envelopes)
    require(job_snapshot(project)==before,'Replay changed job files')
    print('PASS: actual owned native positive plus overwritten/unknown-target controls; deterministic, engine-free, identities and unknowns retained')


if __name__=='__main__':
    run(Path(sys.argv[1]).resolve(),bounded_json(Path(sys.argv[2]),MAX_MANIFEST)[0])
