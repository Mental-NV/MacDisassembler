"""Actual saved native reference navigation with no engine or analysis snapshot."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from integration_native_terminal_thunk import snapshot
import integration_native_callback_counterexamples as gate

CASES=[('883e5bf9a82944b9b73d7cc1174800e7','0xa90','68e46e45d926d9b13422de266956aedd56c3523370b834aefe56fa33e7783f1f',
        [('0xaa4','0xad0','CONDITIONAL_JUMP'),('0xab8','0xd94','UNCONDITIONAL_CALL')]),
       ('bcba2294518b4a04acdd5d6a5b84d553','0xd78','a210afeb015a2dbdb025afdf2174d9feceb68ecffcf44d22af5158d9e2667d2a',
        [('0xd78','0xbb0','UNCONDITIONAL_CALL')])]


def run(projects):
    gate.require(len(projects)==2,"Writer and terminal projects required")
    for project,(job,entry,digest,expected) in zip(projects,CASES):
        before=snapshot(project)
        _,raw=gate.bounded_json(project/'jobs'/job/'query-result.json',gate.MAX_RECEIPT)
        gate.require(hashlib.sha256(raw).hexdigest()==digest,'Changed native receipt')
        base=[sys.executable,'-m','macscope','xrefs','--project',str(project),'--query-job',job,'--address',entry]
        for direction in ('from','to','both'):
            for format_ in ('json','text'):
                results=[subprocess.run(base+['--direction',direction,'--format',format_],capture_output=True,text=True,timeout=60,stdin=subprocess.DEVNULL) for _ in range(2)]
                gate.require(results[0].stdout==results[1].stdout,'Nondeterministic replay')
                gate.require(results[0].returncode==(0 if direction=='from' else 6),'Incorrect selected/global coverage exit')
                if format_=='json':
                    result=json.loads(results[0].stdout);data=result['data']
                    gate.require(data['publication_job_id']==job and data['entry_va']==entry and data['source_query_status']=='complete','Lost origin')
                    if direction in ('from','both'):
                        gate.require([(r['from'],r['to'],r['type']) for r in data['from_body']]==expected,'Changed or invented reference')
                    if direction in ('to','both'):
                        gate.require('incoming_scope_not_global' in data['gaps'] and result['coverage']['known_total'] is None,'Overclaimed callers')
                else:
                    gate.require('recorded_selected_function_only' in results[0].stdout and job in results[0].stdout,'Missing text provenance')
        # Paging only the captured outgoing rows, not a graph traversal.
        first=subprocess.run(base+['--direction','from','--limit','1','--format','json'],capture_output=True,text=True,timeout=60,stdin=subprocess.DEVNULL)
        result=json.loads(first.stdout);collected=result['data']['from_body']
        while cursor:=result['coverage']['next_cursor']:
            second=subprocess.run(base+['--direction','from','--limit','1','--cursor',cursor,'--format','json'],capture_output=True,text=True,timeout=60,stdin=subprocess.DEVNULL)
            result=json.loads(second.stdout);collected+=result['data']['from_body']
        gate.require([(r['from'],r['to'],r['type']) for r in collected]==expected,'Pagination changed evidence')
        gate.require(snapshot(project)==before,'Reference navigation modified project')
    print('PASS: actual native writer/thunk reference navigation, explicit incoming limits, bound pagination and immutable offline replay')


if __name__=='__main__':run([Path(p).resolve() for p in sys.argv[1:3]])
