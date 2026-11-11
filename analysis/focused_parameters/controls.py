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
        rows=json.loads(snapshots['before'])
        need(isinstance(rows,list) and 1<=len(rows)<=108194 and all(isinstance(row,str) and row for row in rows))
        need(rows==sorted(set(rows)))
        need(all(row.startswith(('unit:','function:','memory:','block:')) for row in rows))
        memory=[row for row in rows if row.startswith('memory:')]
        need(len(memory)==2)
        for name in ('caller','callee'):
            proof=request[name]
            matches=[row for row in memory if row.startswith('memory:'+name+':')]
            need(len(matches)==1)
            parts=matches[0].split(':')
            need(len(parts)==4 and parts[2]==proof['entry_va'])
            data=bytes.fromhex(parts[3])
            need(data.hex()==parts[3] and type(proof['length']) is int and len(data)==proof['length']
                 and 0<len(data)<=8192 and int(proof['end_va_exclusive'],16)-int(proof['entry_va'],16)==len(data)
                 and sha256(data).hexdigest()==proof['extent_sha256'])
        def address(value):
            need(isinstance(value,str) and value.startswith('0x'))
            number=int(value,16);need(0<=number<2**63 and hex(number)==value)
            return number
        blocks=[]
        for row in rows:
            if row.startswith('block:'):
                block=json.loads(row[6:])
                need(isinstance(block,dict) and set(block)=={'name','start','end','initialized','mapped'}
                     and isinstance(block['name'],str) and bool(block['name'])
                     and type(block['initialized']) is bool and block['mapped'] is False)
                need(address(block['start'])<=address(block['end']))
                need(block not in blocks);blocks.append(block)
        need(1<=len(blocks)<=4096)
        unit_count=function_count=0
        for row in rows:
            if row.startswith('unit:'):
                unit_count+=1;unit=json.loads(row[5:])
                need(isinstance(unit,dict) and set(unit)=={'start','end','length','kind','block','byte_state','bytes','flow'})
                need(unit['block'] in blocks and isinstance(unit['kind'],str) and bool(unit['kind']) and isinstance(unit['flow'],str))
                lo,hi=address(unit['start']),address(unit['end']);block=unit['block']
                need(type(unit['length']) is int and 0<unit['length']<=4*1024*1024 and hi-lo+1==unit['length']
                     and address(block['start'])<=lo<=hi<=address(block['end']))
                if block['initialized']:
                    need(unit['byte_state']=='read' and isinstance(unit['bytes'],str))
                    data=bytes.fromhex(unit['bytes'])
                    need(data.hex()==unit['bytes'] and len(data)==unit['length'])
                else:
                    need(unit['byte_state']=='uninitialized' and unit['bytes'] is None)
            elif row.startswith('function:'):
                function_count+=1;need(len(row.split(':'))>=9)
        need(1<=unit_count<=100000 and function_count<=4096)
        if control=='ast_scope': need(function_count>=2)
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
