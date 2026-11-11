"""Owned saved five-role route; no capture, engine, or input execution."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import integration_native_callback_counterexamples as gate
from integration_native_terminal_thunk import snapshot

PINS={
 '72700d85bbc34118a93bbef7beba3184':'7072540be2e0e395a7efe5a3ee23c5e6470f54233d36b28550f0b363a82499ff',
 '32c7de9813b2493db1226113990b0da5':'b358096611b42ac8093f3666c9acd38a657a4c83cb6b785328cffdca5b5ea29c',
 'b75c44061b24447fb5f57bc9cbc9c8ce':'d267f18e52531dce3ce6dd73fd0dafa44b0cae74d967ba1089e2612880e98224',
 'c79a2073891046198183344ef64edbc6':'f88ef64a33114721685fc730756a9be90fb5293728231d152e527791dfd4d1ee',
 '4d4ee41aec4b44558c92435faf2167ef':'0c15225154c2ebe398d7eb6cdd83857d3536fd7bfb5ee5f42e14573068bb53ea',
 '2c837d82908a4a81a86f1b0cd5dd6a07':'05f846b857908c240756bdcd1c05f6bf6dd4061429c6658e05d978cb347dbd57',
 '944e12b38d314fa7b5d3addc17e6b27c':'0125f9c80d9ac9cd7f5fed298e82a79a9d63c5c6b69096cc6f1308d1704fa38d'}


def run(project):
    before=snapshot(project)
    for job,digest in PINS.items():
        _,raw=gate.bounded_json(project/'jobs'/job/'disasm-result.json',gate.MAX_RECEIPT)
        gate.require(hashlib.sha256(raw).hexdigest()==digest,'Native receipt changed')
    base=[sys.executable,'-m','macscope','disasm','--project',str(project),'--from-import',
          '--range','0xd78:0xd7c','--receipt','72700d85bbc34118a93bbef7beba3184',
          '--callback-via-receipt','32c7de9813b2493db1226113990b0da5',
          '--callback-target-receipt','b75c44061b24447fb5f57bc9cbc9c8ce',
          '--callback-invocation-receipt','4d4ee41aec4b44558c92435faf2167ef',
          '--callback-evidence','--callback-abi','aapcs64','--callback-context-register','x20',
          '--ghidra','/nonexistent/ghidra','--java-home','/nonexistent/java']
    options=['--callback-invocation-fallthrough','--callback-destination-checked-add-fallthrough','--callback-writer-call-obligations']
    cases=[('c79a2073891046198183344ef64edbc6',options,True),
           ('2c837d82908a4a81a86f1b0cd5dd6a07',options,False),
           ('944e12b38d314fa7b5d3addc17e6b27c',options,False)]
    cases += [('c79a2073891046198183344ef64edbc6',[o for o in options if o!=missing],False) for missing in options]
    for assignment,flags,positive in cases:
        command=base+['--callback-assignment-receipt',assignment]+flags
        outputs=[subprocess.run(command+['--format','json'],capture_output=True,text=True,check=True,stdin=subprocess.DEVNULL,timeout=60).stdout for _ in range(2)]
        gate.require(outputs[0]==outputs[1],'Nondeterministic replay')
        e=json.loads(outputs[0])['data']['callback_evidence'];c=e['composition']
        gate.require(c['policy']=='macscope-callback-composition/4' and c['route_kind']=='two_exact_B_thunks','Wrong composition policy')
        gate.require(c['status']=='inconclusive','Runtime status overclaimed')
        gate.require((c['candidate_status']=='conditional_candidate')==positive,'Incorrect candidate decision')
        gate.require(set(c['role_identities'])=={'assignment','invocation','thunk','inner_thunk','writer'},'Missing scoped role')
        gate.require('direct_destination' not in c['facts'],'Fabricated direct writer edge')
        gate.require(gate.REQUIRED_UNKNOWNS-{'writer_callee_memory_side_effects','receiver_lifetime_after_writer_calls','writer_calls_may_not_return_normally','context_lifetime_after_calls','alternate_branch_paths_not_analyzed'} <= set(c['unknowns']),'Dropped runtime unknown')
        if positive:
            gate.require(len(c['conditional_writer_entry_bindings'])==19,'Incomplete entry bindings')
            binding=next(b for b in c['conditional_writer_entry_bindings'] if b['destination']['register']=='x20')
            gate.require(binding['destination']['selection_start_va']=='0xa90' and binding['via_static_forwarding']['source']['selection_start_va']=='0xd78','Wrong scoped chain')
            gate.require(binding['source']['value']['kind']=='memory_read' and binding['source']['value']['origin_va']=='0xc88','Context origin lost')
            gate.require('0xc84' in binding['requires_branch_conditions'] and '0xc94' in binding['requires_call_conditions'],'Invocation conditions dropped')
            writer=c['writer_call_evidence'];store,=writer['post_call_stores']
            gate.require(writer['status']=='conditional_obligations' and store['value_basis']=='scoped_checked_add_computation','Writer arithmetic lost')
            gate.require(store['evidence']['conditional_on_branches']==['0xaa4'] and store['evidence']['conditional_on_calls']==['0xab8'],'Writer hypotheses dropped')
        else:
            gate.require(not c['conditional_writer_entry_bindings'],'Gap exposed composition bindings')
        text=subprocess.run(command+['--format','text'],capture_output=True,text=True,check=True,timeout=60,stdin=subprocess.DEVNULL).stdout
        gate.require('Composition candidate: '+c['candidate_status'] in text,'Missing visible decision')
    gate.require(snapshot(project)==before,'Replay changed project bytes')
    print('PASS: actual owned five-role conditional route, wrong/unknown assignments and missing-opt-in negatives; immutable offline replay')


if __name__=='__main__':run(Path(sys.argv[1]).resolve())
