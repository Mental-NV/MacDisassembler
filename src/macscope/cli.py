"""Narrow phase-2 CLI. Completed snapshot queries never start a JVM."""
import argparse
import base64
from collections import Counter
import hashlib
import json
import os
import re
from pathlib import Path
import sys
from . import __version__, SCHEMA_VERSION
from .errors import Error
from .macho import inspect_path, read_regular
from .storage import Project, atomic, canonical, identity, write_json
from . import engine
from .schema import validate_envelope, validate_function


def coverage(scope='requested command', count=1, total=1, partial=False, cursor=None, reason=None):
    return {'scope':scope,'status':'partial' if partial else 'complete','returned_count':count,'known_total':total,'next_cursor':cursor,'truncation_reason':reason}


def envelope(command, data=None, aid=None, status='complete', cov=None, diagnostics=None):
    return {'schema_version':SCHEMA_VERSION,'command':command,'status':status,'analysis_id':aid,'data':data,'diagnostics':diagnostics or [],'coverage':cov or coverage()}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Error('usage', message, 2)


def parser():
    p = Parser(prog='macscope', description='Local Mach-O evidence CLI. Engine commands are experimental for explicitly trusted owned fixtures only.')
    p.add_argument('--version', action='version', version='macscope '+__version__)
    sub = p.add_subparsers(dest='command',required=True)
    def common(s, formats=('text','json','jsonl')):
        s.add_argument('--format',choices=formats,default='text')
        s.add_argument('--json',dest='format',action='store_const',const='json')
        s.add_argument('--output')
        s.add_argument('--force',action='store_true')
    def project(s):
        s.add_argument('--project',required=True)
        s.add_argument('--image')
        s.add_argument('--arch',choices=('arm64','x86_64'))
    def selector(s, required=True, all_option=False):
        g=s.add_mutually_exclusive_group(required=required)
        g.add_argument('--function-id')
        g.add_argument('--address')
        g.add_argument('--name')
        if all_option:g.add_argument('--all',action='store_true')
    def pagination(s):
        s.add_argument('--limit',type=int,default=100)
        s.add_argument('--cursor')
    def budgets(s):
        s.add_argument('--timeout',type=int,default=300,help='Total worker wall seconds (1..3600)')
        s.add_argument('--function-timeout',type=int,default=15,help='Per-function decompiler seconds (1..120)')
        s.add_argument('--startup-timeout',type=int)
        s.add_argument('--max-memory-mib',type=int,help='Unsupported hard process cap, rejected explicitly')
        s.add_argument('--heap-mib',type=int,default=1024,help='Java heap only, not process memory (256..4096)')
        s.add_argument('--max-functions',type=int,default=1000,help='Maximum enumerated functions (1..10000)')
        s.add_argument('--jobs',type=int,default=1)
        s.add_argument('--experimental-trusted-input',action='store_true')
        s.add_argument('--ghidra')
        s.add_argument('--java-home')
    for c in ('version','doctor'):
        s=sub.add_parser(c);common(s)
        if c=='doctor':s.add_argument('--ghidra');s.add_argument('--java-home');s.add_argument('--full-digest',action='store_true')
    s=sub.add_parser('inspect');s.add_argument('input');common(s)
    s=sub.add_parser('project');ss=s.add_subparsers(dest='action',required=True)
    s=ss.add_parser('create');s.add_argument('path');common(s)
    s=sub.add_parser('import');s.add_argument('input');s.add_argument('--project',required=True);s.add_argument('--arch',choices=('arm64','x86_64','all'));common(s);budgets(s)
    s=sub.add_parser('analyze');project(s);s.add_argument('--profile',choices=('baseline','deep'),default='baseline');common(s);budgets(s)
    s=sub.add_parser('status');project(s);common(s)
    s=sub.add_parser('functions');ss=s.add_subparsers(dest='action',required=True)
    for c in ('list','show'):
        s=ss.add_parser(c);project(s);common(s)
        if c=='show':selector(s)
        else:s.add_argument('--name-contains');pagination(s)
    for c in ('disasm','decompile','xrefs','cfg'):
        s=sub.add_parser(c);project(s);common(s,('text','json','dot') if c=='cfg' else ('text','json','jsonl'));selector(s,all_option=c=='decompile')
        if c=='decompile':pagination(s)
        if c=='xrefs':s.add_argument('--direction',choices=('to','from','both'),default='both')
    s=sub.add_parser('export');project(s);common(s,('text','json','jsonl'))
    return p


def limits(args):
    for key, low, high in [('timeout',1,3600),('function_timeout',1,120),('heap_mib',256,4096),('max_functions',1,10000),('limit',1,1000)]:
        v=getattr(args,key,None)
        if v is not None and not low<=v<=high:
            raise Error('argument_limit', key+' must be '+str(low)+'..'+str(high),2)
    if getattr(args,'output',None):
        target=Path(args.output)
        if target.exists() and not args.force:
            raise Error('output_exists','Output exists; use --force',8)


def normalize(raw, image, deps, manifest):
    analysis_key={'image':image['image_id'],'slice_sha256':image['sha256'],'profile':'baseline/1','engine':{k:v for k,v in deps.items() if k not in ('ghidra_path','java_home','host_os')},'language_id':raw['language_id'],'compiler_spec_id':raw['compiler_spec_id'],'options':raw.get('effective_analysis_options',{}),'limits':manifest['limits'],'auxiliary_inputs':[],'import_baseline_sha256':image.get('engine_baseline_sha256')}
    aid=identity(analysis_key)
    def location(value):
        loc={'image_id':image['image_id'],'arch':image['arch'],'address_space':value.partition(':')[0] if not value.startswith('0x') else 'ram','va':None,'rva':None,'slice_file_offset':None,'container_file_offset':None}
        if value.startswith('0x'):
            va=int(value,16);loc['va']=hex(va)
            loc['rva']=hex(va-int(raw['image_base'],16)) if va>=int(raw['image_base'],16) else None
            for section in image['sections']:
                start=int(section['va'],16)
                if section['file_offset'] is not None and start<=va<start+int(section['size'],16):
                    off=int(section['file_offset'],16)+va-start
                    loc.update(slice_file_offset=hex(off),container_file_offset=hex(int(image['offset'],16)+off))
                    break
        return loc
    functions=[]
    for f in raw.get('functions',[]):
        f=dict(f)
        engine_entry=f['entry_va']
        va=hex(int(engine_entry,16)) if engine_entry.startswith('0x') else None
        space='ram' if va is not None else engine_entry.partition(':')[0]
        fid=identity({'analysis_id':aid,'image_id':image['image_id'],'entry_va':va,'address_space':space,'engine_entry':engine_entry})
        f.update(function_id=fid,image_id=image['image_id'],arch=image['arch'],entry_va=va,address_space=space,engine_entry=engine_entry,analysis_id=aid,names=[{'name':f['name'],'origin':'ghidra'}],address_spans=[],origin={'engine':'Ghidra','version':'12.2','evidence':'decoded/inferred'})
        f['entry_address']=location(engine_entry)
        for ins in f['instructions']:
            ins['location']=location(ins['addr'])
        f['instruction_bytes_sha256']=hashlib.sha256(bytes.fromhex(''.join(ins['bytes'] for ins in f['instructions']))).hexdigest()
        f['facets']={key:{'available': key in ('instructions','blocks') or f.get(key) is not None and key != 'address_spans', 'reason': None if key in ('instructions','blocks') or f.get(key) else 'No output from engine; token-address spans are not yet exported' if key=='address_spans' else f.get('decompile_error') or 'Empty or unavailable engine facet'} for key in ('pseudocode','instructions','blocks','address_spans')}
        validate_function(f)
        functions.append(f)
    functions.sort(key=lambda f:(f['entry_va'] is None,f['address_space'],int(f['entry_va'],16) if f['entry_va'] is not None else 0,f['function_id']))
    value = {'analysis_id':aid,'image':{k:v for k,v in image.items() if k not in ('active_analysis','imported','import_dependencies')},'identity':analysis_key,'status':raw['status'],'functions':functions,'engine':{k:v for k,v in raw.items() if k not in ('functions','input_name','program_info_options')},'limitations':['C-like pseudocode is inferred, not original source or a semantic-equivalence proof.','No token-to-address spans, annotations, rich ObjC/Swift metadata views or phase-3 features.','Function discovery and every facet are bounded; inspect facet coverage.','Only explicitly trusted owned fixtures are supported by this experimental worker mode.']}
    def redact(v):
        if isinstance(v,str):return re.sub(r'/Users/[^/\s\"\']+', '$HOME', v)
        if isinstance(v,list):return [redact(x) for x in v]
        if isinstance(v,dict):return {k:redact(x) for k,x in v.items()}
        return v
    return redact(value)


def select_function(functions,args):
    if args.address:
        try:
            if not args.address.startswith('0x'):raise ValueError()
            address=int(args.address,16)
            if not 0<=address<2**64:raise ValueError()
        except ValueError:
            raise Error('address','Address must be an unslid hexadecimal VA',2) from None
        rows=[f for f in functions if f['entry_va'] is not None and int(f['entry_va'],16)==address]
    elif args.function_id:
        rows=[f for f in functions if f['function_id']==args.function_id]
    else:
        rows=[f for f in functions if any(n['name']==args.name for n in f['names'])]
    if len(rows)!=1:
        raise Error('function_selector','Function selector must match exactly one entry; use --function-id or --address',2,partial=[{'function_id':f['function_id'],'entry_va':f['entry_va'],'names':f['names']} for f in rows])
    return rows[0]


def page(rows,args,aid,project_id,filters):
    binding=identity({'analysis':aid,'project':project_id,'filters':filters,'order':'entry-va/function-id/v1'})
    start=0
    if args.cursor:
        try:
            cursor=json.loads(base64.urlsafe_b64decode(args.cursor+'='*(-len(args.cursor)%4)))
            if set(cursor)!= {'binding','offset'} or cursor['binding']!=binding or type(cursor['offset']) is not int or not 0<=cursor['offset']<len(rows):raise ValueError()
            start=cursor['offset']
        except (ValueError,TypeError,KeyError):
            raise Error('stale_cursor','Cursor is malformed, stale, or belongs to another query/project',2) from None
    selected=rows[start:start+args.limit]
    end=start+len(selected)
    nxt=base64.urlsafe_b64encode(canonical({'binding':binding,'offset':end})).rstrip(b'=').decode() if end<len(rows) else None
    return selected,coverage('selected image function collection',len(selected),len(rows),bool(nxt),nxt,'page_limit' if nxt else None)


def execute(a):
    limits(a)
    command=a.command+(' '+a.action if hasattr(a,'action') else '')
    if a.command=='version':
        return envelope(command,{'cli_version':__version__,'schema_version':SCHEMA_VERSION,'bridge_version':'1.0.0','backend':'full Ghidra headless','required_engine':'12.2','required_jdk':'25.0.5.0.3','python':sys.version.split()[0],'runtime_dependencies':[],'dependency_status':'not probed; use doctor'})
    if a.command=='doctor':
        deps=engine.dependencies(a.ghidra,a.java_home,full=a.full_digest)
        deps['capabilities']={'cached_queries':True,'engine_operations':'experimental --experimental-trusted-input only','hard_process_memory_limit':False,'startup_deadline':False,'automatic_dependency_install':False}
        return envelope(command,deps)
    if a.command=='inspect':
        data,_=inspect_path(a.input)
        return envelope(command,data)
    if a.command=='project':
        p=Project.create(a.path)
        return envelope(command,{'project_id':p.project_id,'schema_version':'1.0'})
    p=Project(a.project)
    if a.command=='status':
        images=p.images()
        jobs=[]
        for path in sorted((p.path/'jobs').glob('*/job.json'))[-100:]:
            job=json.loads(read_regular(path,1024*1024))
            state=job['status']
            if state in ('running','starting'):
                # No stale PID-based signal or process ownership claim.
                state='unknown_after_disconnect'
            jobs.append({k:v for k,v in job.items() if k in ('job_id','mode','image_id','elapsed_seconds','error','returncode')}|{'status':state})
        return envelope(command,{'project_id':p.project_id,'images':images,'jobs':jobs,'job_history_limit':100},cov=coverage('project status',len(images),len(images)))
    if a.command in ('import','analyze'):
        # All budget validation occurs before importing or mutating workspace.
        if not a.experimental_trusted_input:raise Error('isolation_required','Engine operations require explicit --experimental-trusted-input for trusted user-owned fixtures only',3)
        if a.jobs!=1 or a.max_memory_mib is not None or a.startup_timeout is not None:raise Error('unsupported_budget','Only jobs=1, total --timeout and Java-only --heap-mib are supported; hard process-memory/startup budgets are rejected',3)
        if a.command=='analyze' and a.profile!='baseline':raise Error('unsupported_profile','Only versioned baseline/1 is implemented; deep is not an alias',3)
        deps=engine.dependencies(a.ghidra,a.java_home,full=True)
        with p.writer():
            if a.command=='import':
                meta,original=inspect_path(a.input)
                if len(meta['slices'])>1 and a.arch is None:raise Error('arch_required','Universal input requires explicit --arch arm64|x86_64|all',2)
                selected=[s for s in meta['slices'] if a.arch in (None,'all',s['arch'])]
                if not selected:raise Error('arch_missing','Requested architecture is not present',2)
                result=[]
                existing={r['image_id']:r for r in p.images()}
                for s in selected:
                    image=dict(s,artifact_sha256=meta['artifact_sha256'],input_name=meta['input_name'])
                    if image['image_id'] in existing and existing[image['image_id']]['imported']:
                        result.append({'image_id':image['image_id'],'arch':image['arch'],'status':'already_imported'});continue
                    artifact=p.path/'inputs'/(meta['artifact_sha256']+'.artifact')
                    if not artifact.exists():atomic(artifact,original,mode=0o400)
                    elif hashlib.sha256(read_regular(artifact)).hexdigest()!=meta['artifact_sha256']:raise Error('input_integrity','Existing immutable artifact is corrupt')
                    snap=p.path/'inputs'/(image['image_id']+'.macho')
                    content=original[int(s['offset'],16):int(s['offset'],16)+int(s['size'],16)]
                    if not snap.exists():atomic(snap,content,mode=0o400)
                    elif hashlib.sha256(read_regular(snap)).hexdigest()!=s['sha256']:raise Error('input_integrity','Existing immutable slice is corrupt')
                    raw,job=engine.run(p,image,'import',a,deps)
                    if raw.get('validation',{}).get('headless_analysis_enabled') is not False:raise Error('import_analysis','Import did not disable autoanalysis',10)
                    image['loader_evidence']={k:raw[k] for k in ('executable_format','language_id','compiler_spec_id','executable_sha256')}
                    image['import_dependencies']=deps
                    image['engine_baseline_sha256']=engine.tree_digest(p.path/'engine'/image['image_id'])
                    with p.db(False) as db:db.execute('INSERT OR REPLACE INTO images(id,arch,metadata,imported) VALUES(?,?,?,1)',(image['image_id'],image['arch'],canonical(image).decode()))
                    result.append({'image_id':image['image_id'],'arch':image['arch'],'status':'imported','job_id':job['job_id']})
                return envelope(command,result,cov=coverage('explicitly selected slices',len(result),len(selected)))
            image=p.select(a.image,a.arch)
            if hashlib.sha256(read_regular(p.path/'inputs'/(image['image_id']+'.macho'))).hexdigest()!=image['sha256']:raise Error('input_integrity','Immutable slice digest mismatch')
            if engine.tree_digest(p.path/'engine'/image['image_id'])!=image['engine_baseline_sha256']:raise Error('baseline_integrity','Saved import Program DB changed; create a fresh project')
            raw,job=engine.run(p,image,'analyze',a,deps)
            normalized=normalize(raw,image,deps,job)
            aid=normalized['analysis_id']
            out=p.path/'snapshots'/(aid+'.json')
            payload=canonical(normalized)+b'\n'
            if out.exists():
                if read_regular(out,64*1024*1024)!=payload:raise Error('nondeterministic_snapshot','Identical analysis identity produced different output; previous snapshot retained',5)
            else:atomic(out,payload,mode=0o400)
            record={'snapshot_sha256':hashlib.sha256(payload).hexdigest(),'job_id':job['job_id']}
            with p.db(False) as db:
                db.execute('INSERT OR IGNORE INTO analyses(id,image_id,payload) VALUES(?,?,?)',(aid,image['image_id'],canonical(record).decode()))
                db.execute('UPDATE images SET active_analysis=? WHERE id=?',(aid,image['image_id']))
            return envelope(command,{'image_id':image['image_id'],'function_count':len(normalized['functions']),'job_id':job['job_id'],'decompile_summary':raw.get('decompile_summary'),'limitations':normalized['limitations']},aid,raw['status'],coverage('selected image analysis',len(normalized['functions']),raw.get('function_count_total_reported_by_engine'),raw['status']!='complete',reason='engine_or_facet_partial' if raw['status']!='complete' else None))
    image=p.select(a.image,a.arch)
    snapshot,record=p.snapshot(image)
    aid=snapshot['analysis_id']
    functions=snapshot['functions']
    if a.command=='export':
        return envelope(command,snapshot,aid,snapshot['status'],coverage('committed normalized image export',len(functions),snapshot['engine'].get('function_count_total_reported_by_engine'),snapshot['status']!='complete'),['Private recovered code/strings may be sensitive. Absolute host paths and volatile job timings are omitted.'])
    if a.command=='functions' and a.action=='list':
        rows=[f for f in functions if not a.name_contains or any(a.name_contains in n['name'] for n in f['names'])]
        rows,cov=page(rows,a,aid,p.project_id,{'name_contains':a.name_contains})
        if snapshot['engine'].get('functions_truncated'):
            cov.update(status='partial',known_total=None,truncation_reason='discovery_limit'+(';page_limit' if cov['next_cursor'] else ''))
        return envelope(command,[{k:f[k] for k in ('function_id','image_id','arch','entry_va','address_space','engine_entry','body_ranges','names','signature','is_thunk','is_external','decompile_status')} for f in rows],aid,cov=cov)
    if a.command=='decompile' and a.all:
        rows,cov=page(functions,a,aid,p.project_id,{'decompile':'all'})
        if snapshot['engine'].get('functions_truncated'):
            cov.update(status='partial',known_total=snapshot['engine'].get('function_count_total_reported_by_engine'),truncation_reason='discovery_limit')
        states=Counter(f['decompile_status'] for f in rows)
        partial=any(k not in ('complete','not_requested') for k in states)
        return envelope(command,{'functions':rows,'summary':dict(states)},aid,'partial' if partial else 'complete',cov)
    f=select_function(functions,a)
    if a.command=='functions':return envelope(command,f,aid)
    if a.command=='disasm':
        data={'function_id':f['function_id'],'instructions':f['instructions']}
        partial=bool(f.get('instructions_truncated') or f.get('instructions_error'))
        count=len(f['instructions'])
    elif a.command=='decompile':
        data=f
        partial=f['decompile_status'] not in ('complete','not_requested') or f.get('pseudocode_truncated',False)
        count=1
    elif a.command=='cfg':
        data={'function_id':f['function_id'],'blocks':f['blocks']}
        partial=bool(f.get('blocks_truncated') or f.get('cfg_error') or f.get('edges_truncated'))
        count=len(f['blocks'])
    else:
        data={'function_id':f['function_id']}
        if a.direction in ('to','both'):data['to_entry']=f['xrefs_to_entry']
        if a.direction in ('from','both'):data['from_body']=f['xrefs_from_sample']
        partial=bool(f.get('xrefs_to_entry_truncated') or f.get('xrefs_from_truncated') or f.get('xrefs_to_entry_error') or f.get('xrefs_from_error'))
        count=sum(len(v) for v in data.values() if isinstance(v,list))
    return envelope(command,data,aid,'partial' if partial else 'complete',coverage('selected function '+a.command,count,None,partial,reason='facet_incomplete' if partial else None))


def render(result,fmt):
    if fmt=='dot':
        rows=['digraph cfg {']
        for b in result['data']['blocks']:
            rows.append('  '+json.dumps(b['min'])+' [label='+json.dumps(b['min']+'..'+b['max'])+'];')
            for edge in b['dsts']:rows.append('  '+json.dumps(b['min'])+' -> '+json.dumps(edge['to'])+' [label='+json.dumps(edge['flow'])+'];')
        rows.append('}')
        return ('\n'.join(rows)+'\n').encode()
    if fmt=='jsonl':
        data=result['data']
        if not isinstance(data,list):return canonical(result)+b'\n'
        return b''.join(canonical(dict(result,data=row,coverage=dict(result['coverage'],returned_count=1)))+b'\n' for row in data) or canonical(result)+b'\n'
    if fmt=='json':return canonical(result)+b'\n'
    # ASCII JSON escaping prevents terminal-control injection in binary strings.
    return (json.dumps(result,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()


def main(argv=None):
    os.umask(0o077)
    args=None
    try:
        args=parser().parse_args(argv)
        result=execute(args)
        code=6 if result['status']=='partial' else 0
    except Error as e:
        command=getattr(args,'command','unknown') if args else 'unknown'
        result=envelope(command,None,status='failed',cov=coverage('requested command',0,None,True,reason=e.code),diagnostics=[str(e)])
        result['error']={'code':e.code,'message':str(e),'affected_object':getattr(args,'image',None) if args else None,'retryable':e.retryable,'partial_results':e.partial}
        code=e.exit_code
    except KeyboardInterrupt:
        result=envelope('unknown',None,status='cancelled',diagnostics=['Interrupted'])
        code=130
    except (OSError,ValueError,KeyError,TypeError) as e:
        result=envelope(getattr(args,'command','unknown'),None,status='failed',cov=coverage('requested command',0,None,True,reason='internal_failure'),diagnostics=[str(e)])
        result['error']={'code':'internal_failure','message':str(e),'affected_object':None,'retryable':False,'partial_results':None}
        code=10
    fmt=getattr(args,'format','json') if args else 'json'
    validate_envelope(result)
    output=render(result,fmt if not result.get('error') else 'json')
    try:
        if getattr(args,'output',None) and code in (0,6):atomic(args.output,output,args.force)
        else:sys.stdout.buffer.write(output)
    except Error as e:
        sys.stderr.write(e.code+': '+str(e)+'\n')
        return e.exit_code
    if code not in (0,6):sys.stderr.write(result.get('error',{}).get('message','Command failed')+'\n')
    return code
