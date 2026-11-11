"""Actual owned two-thunk route; replay only, no native engine or app execution."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import integration_native_callback_counterexamples as gate

PINS={'outer_thunk':('0xd78:0xd7c','7072540be2e0e395a7efe5a3ee23c5e6470f54233d36b28550f0b363a82499ff'),
      'inner_thunk':('0xbb0:0xbb4','b358096611b42ac8093f3666c9acd38a657a4c83cb6b785328cffdca5b5ea29c'),
      'writer':('0xa90:0xad4','d267f18e52531dce3ce6dd73fd0dafa44b0cae74d967ba1089e2612880e98224')}


def run(project,manifest):
    gate.require(manifest.get('schema')=='macscope-owned-twohop/1','Wrong manifest')
    before=gate.job_snapshot(project);digests={}
    for role,(range_,sha) in PINS.items():
        pin=manifest[role]
        gate.require(isinstance(pin.get('job_id'),str) and gate.JOB.fullmatch(pin['job_id']),'Invalid receipt ID')
        gate.require(pin['range']==range_ and pin['receipt_sha256']==sha,'Wrong native pin')
        saved,raw=gate.bounded_json(project/'jobs'/pin['job_id']/'disasm-result.json',gate.MAX_RECEIPT)
        gate.require(hashlib.sha256(raw).hexdigest()==sha and saved['data']['selection']==pin['selection'],'Stale receipt')
        digests[role]=hashlib.sha256(json.dumps(saved,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    args=[sys.executable,'-m','macscope','disasm','--project',str(project),'--from-import',
          '--range',manifest['outer_thunk']['range'],'--receipt',manifest['outer_thunk']['job_id'],
          '--callback-via-receipt',manifest['inner_thunk']['job_id'],'--callback-target-receipt',manifest['writer']['job_id'],
          '--callback-evidence','--callback-abi','aapcs64','--ghidra','/nonexistent/ghidra','--java-home','/nonexistent/java']
    for enabled in (False,True):
        base=args+(['--callback-destination-checked-add-fallthrough'] if enabled else [])
        results={}
        for format_ in ('json','text'):
            outputs=[subprocess.run(base+['--format',format_],capture_output=True,text=True,check=True,timeout=60).stdout for _ in range(2)]
            gate.require(outputs[0]==outputs[1],'Nondeterministic two-hop replay');results[format_]=outputs[0]
        c=json.loads(results['json'])['data']['callback_evidence']['two_hop_chain']
        gate.require(c['status']=='inconclusive' and c['link_status']=='verified_two_hop_entry_links' and not c['gaps'],'Native edges not verified')
        gate.require(c['source_extent']=='not_proven_selected_bytes_only','Invented source extent')
        for role,key in (('outer','outer_thunk'),('inner','inner_thunk'),('destination','writer')):
            identity=c['role_identities'][role]
            gate.require(identity['selection']==manifest[key]['selection'] and identity['source_envelope_sha256']==digests[key],'Role identity changed')
        gate.require([e['transfer']['target_va'] for e in c['edges']]==['0xbb0','0xa90'],'Incorrect edge targets')
        gate.require(all(e['status']=='verified_direct_entry_link' for e in c['edges']),'Unverified edge')
        final=c['edges'][1]['destination_evidence']
        stores=[s for s in final['sites'] if s['instruction_va']=='0xabc' and s['kind']=='memory_store']
        if enabled:
            gate.require(len(stores)==1 and c['destination_stop_reason']=='return_boundary','Guarded store missing')
            gate.require(stores[0]['conditional_on_branches']==['0xaa4'] and stores[0]['conditional_on_calls']==['0xab8'],'Lost store hypotheses')
            relation=next(s for s in c['edges'][1]['store_relations'] if s['instruction_va']=='0xabc')
            effect=next(s for s in c['destination_effects']['observed_stores'] if s['instruction_va']=='0xabc')
            for projected in (relation,effect):
                gate.require(projected['destination_branch_conditions']==['0xaa4'] and projected['destination_call_conditions']==['0xab8'],'Derived store lost guard/call conditions')
            for projected in (c['edges'][1],c['destination_effects']):
                path,=projected['destination_path_obligations']
                gate.require(path['source_envelope_sha256']==digests['writer'] and path['evidence']['instruction_va']=='0xaa4','Missing scoped path lookup')
            guard,=c['path_obligations'];call,=c['call_obligations']
            gate.require(guard['evidence']['fallthrough_predicate']=='no_signed_overflow' and guard['evidence']['predicate_status']=='unverified','Lost unresolved guard')
            gate.require(call['memory_effects']=='unknown' and call['source_envelope_sha256']==digests['writer'],'Lost scoped call uncertainty')
        else:
            gate.require(not stores and c['destination_stop_reason']=='unsupported_instruction_boundary','Default barrier lost')
        gate.require(all(c['destination_effects'][key]=='unknown' for key in ('application_writer_attribution','runtime_execution','persistence')),'Upgraded destination claims')
        gate.require('transitive_register_correspondence_not_applied' in c['unknowns'],'Invented transitive values')
        text=results['text'];summary=text[text.index('Callback evidence (bounded summary'):]
        gate.require('Two-hop links: verified_two_hop_entry_links' in summary and 'not_proven_selected_bytes_only' in summary,'Text lost chain limits')
        gate.require(len(summary.encode())<=16384 and len(summary.splitlines())<=64,'Text budget exceeded')
    gate.require(gate.job_snapshot(project)==before,'Mutated receipts/jobs')
    print('PASS: actual owned independently pinned two-hop edges and conditional destination store; strict defaults, scoped identities and immutable replay')


if __name__=='__main__':
    run(Path(sys.argv[1]).resolve(),gate.bounded_json(Path(sys.argv[2]),gate.MAX_MANIFEST)[0])
