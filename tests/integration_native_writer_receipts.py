"""Replay externally supplied OWNED native receipts; never capture or execute code.

Run using the installed package outside the checkout:
  python integration_native_writer_receipts.py PROJECT RECEIPT_MANIFEST
The manifest belongs to the documented owned Swift fixture capture. Do not pass
third-party application data to this generic repository validation script.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    project=Path(sys.argv[1]).resolve()
    manifest=json.loads(Path(sys.argv[2]).read_text())
    def saved():
        return {str(p.relative_to(project)):p.read_bytes() for p in (project/'jobs').rglob('*') if p.is_file()}
    before=saved()
    for role in ('assignment','invocation','thunk','writer'):
        item=manifest[role]
        path=project/'jobs'/item['job_id']/'disasm-result.json'
        assert hashlib.sha256(path.read_bytes()).hexdigest()==item['receipt_sha256']
    args=[sys.executable,'-m','macscope','disasm','--project',str(project),'--from-import',
          '--range',manifest['thunk']['range'],'--receipt',manifest['thunk']['job_id'],
          '--callback-evidence','--callback-provenance','--callback-abi','aapcs64',
          '--callback-target-receipt',manifest['writer']['job_id'],
          '--callback-assignment-receipt',manifest['assignment']['job_id'],
          '--callback-invocation-receipt',manifest['invocation']['job_id'],
          '--callback-context-register','x20','--callback-invocation-fallthrough',
          '--ghidra','/nonexistent/ghidra','--java-home','/nonexistent/java','--format','json']
    default=subprocess.run(args,capture_output=True,text=True,check=True)
    baseline=json.loads(default.stdout)['data']['callback_evidence']['composition']
    assert baseline['candidate_status']=='gap'
    assert {'reason':'writer_intervening_call'} in baseline['gaps']
    args.append('--callback-writer-call-obligations')
    first=subprocess.run(args,capture_output=True,text=True,check=True)
    second=subprocess.run(args,capture_output=True,text=True,check=True)
    assert first.stdout==second.stdout
    c=json.loads(first.stdout)['data']['callback_evidence']['composition']
    assert c['candidate_status']=='conditional_candidate',c['gaps']
    assert c['status']=='inconclusive'
    proof=c['writer_call_evidence']
    assert proof['status']=='conditional_obligations'
    store,=proof['post_call_stores']
    assert store['evidence']['instruction_va']=='0x918'
    assert store['evidence']['conditional_on_calls']==['0x914']
    assert store['base_basis']==store['value_basis']=='matched_input_register'
    assert {(x['role'],x['evidence']['instruction_va']) for x in c['call_obligations']}=={('writer','0x914'),('invocation','0xc94')}
    assert c['path_obligations'][0]['evidence']['fallthrough_predicate']=='nonzero'
    assert c['destination_effects']['application_writer_attribution']=='unknown'
    assert c['destination_effects']['counts']['unresolved_destination']==1
    for key in ('runtime_execution','persistence'):
        assert proof[key]=='unknown'
    for unknown in ('runtime_invoked_code_identity','receiver_lifetime_after_writer_calls','intervening_memory_unchanged'):
        assert unknown in c['unknowns']
    assert saved()==before
    print('PASS: actual owned native four-role receipts replay conditionally; immutable, engine-free, runtime/app attribution unknown')


if __name__=='__main__':
    main()
