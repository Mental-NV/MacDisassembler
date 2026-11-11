"""Pinned native focused pseudocode replay, without an engine or input execution."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import integration_native_callback_counterexamples as gate

RECEIPT_SHA='a210afeb015a2dbdb025afdf2174d9feceb68ecffcf44d22af5158d9e2667d2a'


def snapshot(project):
    result={};total=0
    for path in project.rglob('*'):
        gate.require(not path.is_symlink(),'Symlink in portable project')
        if not path.is_file():continue
        gate.require(len(result)<256,'File budget exceeded')
        with path.open('rb') as stream:raw=stream.read(16*1024*1024+1)
        total+=len(raw)
        gate.require(len(raw)<=16*1024*1024 and total<=64*1024*1024,'Snapshot byte budget exceeded')
        result[str(path.relative_to(project))]=hashlib.sha256(raw).hexdigest()
    return result


def run(project,manifest):
    gate.require(manifest.get('schema')=='macscope-owned-terminal-focused/1','Wrong manifest')
    job=manifest['job_id'];gate.require(isinstance(job,str) and gate.JOB.fullmatch(job),'Invalid job ID')
    gate.require(manifest['query_receipt_sha256']==RECEIPT_SHA and manifest['entry']=='0xd78' and manifest['end']=='0xd7c','Unexpected native pin')
    before=snapshot(project)
    wrapper,raw=gate.bounded_json(project/'jobs'/job/'query-result.json',gate.MAX_RECEIPT)
    gate.require(hashlib.sha256(raw).hexdigest()==RECEIPT_SHA,'Native receipt digest changed')
    original=wrapper['result'];captured=original['data']
    args=[sys.executable,'-m','macscope','jobs','resume',job,'--project',str(project),
          '--ghidra','/nonexistent/ghidra','--java-home','/nonexistent/java','--format','json']
    outputs=[subprocess.run(args,capture_output=True,text=True,check=True,timeout=60,stdin=subprocess.DEVNULL).stdout for _ in range(2)]
    gate.require(outputs[0]==outputs[1],'Nondeterministic saved replay')
    replay=json.loads(outputs[0]);data=replay['data']
    normalized=copy.deepcopy(data)
    gate.require(normalized.pop('resumed_from')==job and normalized.pop('reused_restart') is True,'Replay did not reuse saved result')
    gate.require(normalized==captured,'Captured semantic evidence changed')
    proof=data['origin']['extent']
    gate.require(proof['policy']=='macscope-focused-import/4' and proof['boundary']==manifest['boundary'],'Terminal boundary proof changed')
    gate.require(proof['entry_va']=='0xd78' and proof['end_va_exclusive']=='0xd7c' and proof['length']==4,'Selected extent changed')
    gate.require(data['image_id']==manifest['image_id'] and data['slice_sha256']==manifest['binary_sha256'],'Input identity changed')
    gate.require(data['decompile_status']=='complete' and data['instruction_count']==1 and data['decoded_bytes']==4,'Selected decompile incomplete')
    instruction,=data['instructions']
    gate.require(instruction['addr']=='0xd78' and instruction['bytes']=='8effff17' and instruction['flow']=='CALL_TERMINATOR','Native terminal word mismatch')
    gate.require('func_0x00000bb0();' in data['pseudocode'] and not data['pseudocode_truncated'],'Expected owned forwarder pseudocode missing')
    scope=data['native_scope']
    gate.require(scope['status']=='complete' and not scope['operations_truncated'] and scope['outside_body_operations']==0 and scope['outside_body_addresses']==[],'Native scope changed')
    recovery=data['tail_call_recovery']
    gate.require(recovery['decisions']==[{'outcome':'applied','source_va':'0xd78'}],'Tail-call proof changed')
    gate.require(snapshot(project)==before,'Replay changed portable project files')
    print('PASS: actual native terminal-thunk pseudocode replays identically offline; scope/identity/proof and all project bytes preserved')


if __name__=='__main__':
    run(Path(sys.argv[1]).resolve(),gate.bounded_json(Path(sys.argv[2]),gate.MAX_MANIFEST)[0])
