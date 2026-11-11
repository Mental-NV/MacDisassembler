"""Replay one independently captured owned writer, without native dependencies."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import integration_native_callback_counterexamples as gate

RECEIPT_SHA='d267f18e52531dce3ce6dd73fd0dafa44b0cae74d967ba1089e2612880e98224'


def run(project, manifest):
    gate.require(manifest.get('schema')=='macscope-owned-overflow-writer/1','Wrong manifest')
    pin=manifest['writer']
    gate.require(isinstance(pin.get('job_id'),str) and gate.JOB.fullmatch(pin['job_id']),'Invalid job ID')
    gate.require(pin['range']=='0xa90:0xad4' and pin['receipt_sha256']==RECEIPT_SHA,'Unexpected native pin')
    before=gate.job_snapshot(project)
    saved,raw=gate.bounded_json(project/'jobs'/pin['job_id']/'disasm-result.json',gate.MAX_RECEIPT)
    gate.require(hashlib.sha256(raw).hexdigest()==RECEIPT_SHA,'Receipt digest mismatch')
    gate.require(saved['data']['selection']==pin['selection'],'Selection mismatch')
    digest=hashlib.sha256(json.dumps(saved,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    args=[sys.executable,'-m','macscope','disasm','--project',str(project),'--from-import',
          '--range',pin['range'],'--receipt',pin['job_id'],'--callback-evidence','--callback-abi','aapcs64',
          '--ghidra','/nonexistent/ghidra','--java-home','/nonexistent/java','--format','json']
    for enabled in (False,True):
        command=args+(['--callback-checked-add-fallthrough'] if enabled else [])
        outputs=[subprocess.run(command,capture_output=True,text=True,check=True,timeout=60).stdout for _ in range(2)]
        gate.require(outputs[0]==outputs[1],'Nondeterministic projection')
        r=json.loads(outputs[0])['data']['callback_evidence']
        gate.require(r['source_envelope_sha256']==digest and r['selection']==pin['selection'],'Projection identity mismatch')
        gate.require(r['status']=='inconclusive','Upgraded static evidence')
        stores=[s for s in r['sites'] if s['kind']=='memory_store' and s['instruction_va']=='0xabc']
        if not enabled:
            gate.require(r['stop_reason']=='unsupported_instruction_boundary' and r['interpreted_end_va']=='0xaa0' and not stores,'Default barrier changed')
            continue
        gate.require(r['stop_reason']=='return_boundary' and len(stores)==1,'Owned store not reached')
        store=stores[0]
        gate.require(store['conditional_on_branches']==['0xaa4'] and store['conditional_on_calls']==['0xab8'],'Store lost path/call conditions')
        gate.require(store['value']['kind']=='checked_add_result' and store['value']['origin_va']=='0xaa0' and store['value']['source_envelope_sha256']==digest,'Arithmetic provenance lost')
        guard,=r['path_obligations']
        gate.require(guard['target_va']=='0xad0' and guard['fallthrough_predicate']=='no_signed_overflow' and guard['predicate_status']=='unverified' and guard['taken_path']=='not_analyzed','Guard incorrectly upgraded')
        gate.require('alternate_branch_paths_not_analyzed' in r['missing_evidence'] and any('arbitrary memory effects' in a for a in r['assumptions']),'Required unknowns missing')
    gate.require(gate.job_snapshot(project)==before,'Replay mutated jobs')
    print('PASS: actual owned overflow writer store exposed conditionally; default barrier, scoped identity and immutable engine-free replay retained')


if __name__=='__main__':
    run(Path(sys.argv[1]).resolve(),gate.bounded_json(Path(sys.argv[2]),gate.MAX_MANIFEST)[0])
