"""Owned native negative controls. No inferred pseudocode or product receipts."""
import argparse
import json
from hashlib import sha256
from pathlib import Path

SCHEMA='macscope-owned-native-controls/1'
POSITIVE='53345f8f9ae61fb42d41136fdf1d1733c9bdd7bf6410bbe676ebb03a09e5eaa0'
REFUSALS={'prep_digest':'Program extent bytes differ from the verified slice',
          'prep_rollback':'Invalid tail-call source or destination',
          'ast_scope':'Native operation outside independently pinned extent'}


def validate(report, control, request, request_digest, snapshots):
    def need(ok):
        if not ok: raise ValueError('Native control identity/refusal/preservation mismatch')
    fields={'schema','control','image_sha256','request_sha256','caller','callee','refusal',
            'status','before_sha256','after_sha256','commit_calls','inference_attempted',
            'preparation_report_absent','positive_scope_checks','rejected_scope_check_appended',
            'injected_operation_present','injected_address','native_graph_exported','positive_scope_evidence',
            'ghidra_version','headless_analysis_enabled','java_runtime','stage_sha256'}
    need(control in REFUSALS and isinstance(report,dict) and set(report)==fields)
    need(report['schema']==SCHEMA and report['control']==control and report['status']=='expected_refusal'
         and report['image_sha256']==POSITIVE==request['image_sha256']
         and report['request_sha256']==request_digest and report['caller']==request['caller']
         and report['callee']==request['callee'] and report['refusal']==REFUSALS[control])
    need(report['ghidra_version']=='12.2' and report['headless_analysis_enabled'] is False
         and isinstance(report['java_runtime'],dict))
    need(isinstance(snapshots,dict) and set(snapshots)=={'before','after'}
         and isinstance(snapshots['before'],str) and len(snapshots['before'].encode())<=4*1024*1024
         and snapshots['before']==snapshots['after'])
    try:
        inventory=json.loads(snapshots['before'])
        need(isinstance(inventory,dict) and set(inventory)=={'schema','blocks','kinds','units','functions','memory'}
             and inventory['schema']=='macscope-owned-control-inventory/2')
        memory=inventory['memory'];need(isinstance(memory,dict) and set(memory)=={'caller','callee'})
        for name in ('caller','callee'):
            proof=request[name];row=memory[name]
            need(isinstance(row,dict) and set(row)=={'entry_va','bytes'} and row['entry_va']==proof['entry_va']
                 and isinstance(row['bytes'],str))
            data=bytes.fromhex(row['bytes'])
            need(data.hex()==row['bytes'] and type(proof['length']) is int and len(data)==proof['length']
                 and 0<len(data)<=8192 and int(proof['end_va_exclusive'],16)-int(proof['entry_va'],16)==len(data)
                 and sha256(data).hexdigest()==proof['extent_sha256'])
        def integer(value):
            need(type(value) is int and 0<=value<2**63)
            return value
        blocks=inventory['blocks'];kinds=inventory['kinds'];units=inventory['units'];functions=inventory['functions']
        need(isinstance(blocks,list) and 1<=len(blocks)<=4096 and isinstance(kinds,list) and 1<=len(kinds)<=4096
             and isinstance(units,list) and 1<=len(units)<=100000 and isinstance(functions,list) and len(functions)<=4096)
        keys=[]
        for block in blocks:
            need(isinstance(block,dict) and set(block)=={'name','space','start','end','initialized','mapped'}
                 and all(isinstance(block[k],str) and block[k] for k in ('name','space'))
                 and type(block['initialized']) is bool and block['mapped'] is False)
            need(integer(block['start'])<=integer(block['end']))
            keys.append((block['space'],block['start'],block['end'],block['name']))
        need(keys==sorted(set(keys)))
        need(all(isinstance(k,str) and k for k in kinds) and kinds==sorted(set(kinds)))
        used_blocks=set();used_kinds=set();previous=None
        for row in units:
            need(isinstance(row,list) and len(row)==7)
            space,start,length,ki,bi,raw,flow=row
            need(isinstance(space,str) and space and isinstance(flow,str))
            integer(start);integer(length);integer(ki);integer(bi)
            need(0<length<=4*1024*1024 and start+length-1<2**63 and ki<len(kinds) and bi<len(blocks))
            end=start+length-1;block=blocks[bi]
            need(space==block['space'] and block['start']<=start<=end<=block['end'])
            if previous is not None:
                oldspace,oldend=previous
                need(space>oldspace or space==oldspace and start>oldend)
            previous=(space,end);used_blocks.add(bi);used_kinds.add(ki)
            if block['initialized']:
                need(isinstance(raw,str));data=bytes.fromhex(raw)
                need(data.hex()==raw and len(data)==length)
            else: need(raw is None)
        need(used_blocks==set(range(len(blocks))) and used_kinds==set(range(len(kinds))))
        need(all(isinstance(row,str) and row.startswith('function:') and len(row.split(':'))>=9 for row in functions)
             and functions==sorted(set(functions)))
        if control=='ast_scope': need(len(functions)>=2)
    except (KeyError,TypeError,ValueError,json.JSONDecodeError) as error:
        raise ValueError('Malformed or unbound native snapshot') from error
    before=report['before_sha256']
    need(isinstance(before,str) and len(before)==64 and all(c in '0123456789abcdef' for c in before)
         and report['after_sha256']==before and sha256(snapshots['before'].encode()).hexdigest()==before)
    need(type(report['commit_calls']) is int and report['commit_calls']==0
         and report['inference_attempted'] is False and report['native_graph_exported'] is False
         and report['rejected_scope_check_appended'] is False)
    evidence=report['positive_scope_evidence']
    need(isinstance(evidence,list) and len(evidence)<=16)
    for row in evidence:
        need(isinstance(row,dict) and set(row)=={'entry_va','extent_sha256','operations_scanned','phase','status'}
             and row['entry_va']==request['callee']['entry_va'] and row['extent_sha256']==request['callee']['extent_sha256']
             and row['phase']=='before_commit' and row['status']=='complete'
             and type(row['operations_scanned']) is int and 1<=row['operations_scanned']<=100000)
    need(len(evidence)==report['positive_scope_checks'])
    if control=='ast_scope':
        need(report['preparation_report_absent'] is False and report['injected_operation_present'] is True
             and type(report['positive_scope_checks']) is int and 1<=report['positive_scope_checks']<=16
             and report['injected_address']==request['callee']['end_va_exclusive'])
    else:
        need(report['preparation_report_absent'] is True and report['injected_operation_present'] is False
             and type(report['positive_scope_checks']) is int and report['positive_scope_checks']==0
             and report['injected_address'] is None)
    return report


def validate_stage(stage, report, snapshots, stage_digest, control_digest):
    def need(ok):
        if not ok: raise ValueError('Pending native stage differs from final result')
    need(isinstance(stage,dict) and set(stage)=={'schema','status','control_request_sha256','before','observation'})
    need(stage['schema']=='macscope-owned-native-control-stage/1' and stage['status']=='refusal_observed'
         and stage['control_request_sha256']==control_digest and stage['before']==snapshots['before']
         and report['stage_sha256']==stage_digest)
    expected=dict(report);expected.pop('stage_sha256');expected.pop('after_sha256');expected['status']='refusal_observed'
    need(stage['observation']==expected)


def main():
    import harness
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project',type=Path);parser.add_argument('control',choices=sorted(REFUSALS))
    parser.add_argument('--ghidra',required=True);parser.add_argument('--java-home',required=True)
    parser.add_argument('--trust-owned-input',action='store_true');parser.add_argument('--disposable-import-clone',action='store_true')
    args=parser.parse_args();args.arm='prepared'
    print(harness.run(args))

if __name__=='__main__':main()
