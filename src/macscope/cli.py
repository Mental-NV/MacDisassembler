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
from .macho import inspect_bytes, inspect_path, read_regular
from .pseudocode import address_spans
from .storage import MAX_SNAPSHOT_BYTES, Project, atomic, canonical, identity, write_json
from . import annotation_transfer, annotations, bundle, calls, dyld, engine, export_trie, flow_evidence, metadata, objc, search, swift_symbols
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
    s=sub.add_parser('bundle');ss=s.add_subparsers(dest='action',required=True)
    s=ss.add_parser('list');s.add_argument('path');common(s);pagination(s)
    s.add_argument('--kind',choices=('all','images','resources'),default='all')
    s=sub.add_parser('project');ss=s.add_subparsers(dest='action',required=True)
    s=ss.add_parser('create');s.add_argument('path');common(s)
    s=sub.add_parser('import');s.add_argument('input');s.add_argument('--project',required=True);s.add_argument('--arch',choices=('arm64','x86_64','all'));common(s);budgets(s)
    s.add_argument('--include-images',action='append',metavar='PATH|all',
                   help='Include an exact bundle-relative executable path in addition to the main image')
    s=sub.add_parser('analyze');project(s);s.add_argument('--profile',choices=('baseline','parameter-inference','deep'),default='baseline',help='baseline is unchanged; parameter-inference is an explicit experimental binary-only profile');common(s);budgets(s)
    s=sub.add_parser('status');project(s);common(s)
    s=sub.add_parser('headers');project(s);common(s)
    s=sub.add_parser('fixups');project(s);common(s);pagination(s)
    s.add_argument('--kind',choices=('all','bind','rebase'),default='all')
    s=sub.add_parser('objc');ss=s.add_subparsers(dest='action',required=True)
    for c in ('classes','methods','selectors'):
        s=ss.add_parser(c);project(s);common(s);pagination(s);s.add_argument('--name-contains')
    s=sub.add_parser('swift');ss=s.add_subparsers(dest='action',required=True)
    s=ss.add_parser('symbols');project(s);common(s);pagination(s);s.add_argument('--name-contains')
    s.add_argument('--demangle',action='store_true');s.add_argument('--experimental-trusted-input',action='store_true')
    s=sub.add_parser('demangle');common(s);s.add_argument('name')
    s.add_argument('--experimental-trusted-input',action='store_true')
    s=sub.add_parser('bytes');project(s);common(s)
    s.add_argument('--address',required=True)
    s.add_argument('--length',type=int,required=True,dest='byte_length')
    for c in (*metadata.PREFLIGHT_LISTS,*metadata.ENGINE_LISTS):
        s=sub.add_parser(c);project(s);common(s);pagination(s)
        if c=='exports':
            s.add_argument('--source',choices=('ghidra','dyld'),default='ghidra')
        if c=='strings':
            s.add_argument('--contains')
            s.add_argument('--min-length',type=int,default=0)
        else:s.add_argument('--name-contains')
    s=sub.add_parser('functions');ss=s.add_subparsers(dest='action',required=True)
    for c in ('list','show'):
        s=ss.add_parser(c);project(s);common(s)
        if c=='show':selector(s)
        else:s.add_argument('--name-contains');pagination(s)
    for c in ('disasm','decompile','xrefs','cfg'):
        s=sub.add_parser(c);project(s);common(s,('text','json','dot') if c=='cfg' else ('text','json','jsonl'));selector(s,all_option=c=='decompile')
        if c=='decompile':
            pagination(s);budgets(s)
            s.add_argument('--fresh',action='store_true',help='Reopen the saved Program and decompile one function')
            s.add_argument('--with-type-hints',action='store_true',help='Apply accepted return hints in the fresh query copy')
        if c=='xrefs':s.add_argument('--direction',choices=('to','from','both'),default='both')
    s=sub.add_parser('search');project(s);common(s);pagination(s)
    s.add_argument('query')
    s.add_argument('--in',dest='search_scope',choices=(*search.SCOPES,'all'),default='all')
    s=sub.add_parser('calls');project(s);common(s);selector(s)
    s.add_argument('--direction',choices=('callers','callees','both'),default='both')
    s.add_argument('--depth',type=int,default=1)
    s.add_argument('--max-edges',type=int,default=500)
    s=sub.add_parser('rename');project(s);common(s);selector(s)
    s.add_argument('label',nargs='?')
    s.add_argument('--clear',action='store_true')
    s.add_argument('--author',default='local')
    s=sub.add_parser('comment');ss=s.add_subparsers(dest='action',required=True)
    for action in ('set','remove','list'):
        s=ss.add_parser(action);project(s);common(s);selector(s,required=action!='list')
        if action=='list':
            pagination(s)
        else:
            s.add_argument('--instruction')
            s.add_argument('--author',default='local')
        if action=='set':s.add_argument('text')
    s=sub.add_parser('annotations');ss=s.add_subparsers(dest='action',required=True)
    s=ss.add_parser('history');project(s);common(s);selector(s,required=False);pagination(s)
    s=ss.add_parser('export');project(s);common(s,('text','json'))
    s=ss.add_parser('import');project(s);common(s)
    s.add_argument('path');s.add_argument('--accept-type-hints',action='store_true')
    s=sub.add_parser('type');ss=s.add_subparsers(dest='action',required=True)
    for action in ('set','clear','list'):
        s=ss.add_parser(action);project(s);common(s);selector(s,required=action!='list')
        if action=='list':
            pagination(s)
        else:
            s.add_argument('--accept',action='store_true')
            s.add_argument('--author',default='local')
        if action=='set':s.add_argument('--return-type',required=True)
    s=sub.add_parser('export');project(s);common(s,('text','json','jsonl'))
    s.add_argument('--include-annotations',action='store_true')
    return p


def limits(args):
    for key, low, high in [('timeout',1,3600),('function_timeout',1,120),('heap_mib',256,4096),('max_functions',1,10000),('limit',1,1000),('depth',1,8),('max_edges',1,2000),('byte_length',1,4096),('min_length',0,1048576)]:
        v=getattr(args,key,None)
        if v is not None and not low<=v<=high:
            raise Error('argument_limit', key+' must be '+str(low)+'..'+str(high),2)
    if getattr(args,'output',None):
        target=Path(args.output)
        if target.exists() and not args.force:
            raise Error('output_exists','Output exists; use --force',8)


def redact(value):
    if isinstance(value,str):return re.sub(r'/Users/[^/\s\"\']+', '$HOME', value)
    if isinstance(value,list):return [redact(item) for item in value]
    if isinstance(value,dict):return {key:redact(item) for key,item in value.items()}
    return value


def normalize(raw, image, deps, manifest):
    selected_profile = manifest['analysis_profile']
    engine.validate_analysis_profile(raw, selected_profile, 'analyze')
    analysis_key={'image':image['image_id'],'slice_sha256':image['sha256'],'profile':selected_profile['identity'],'profile_configuration':selected_profile,'engine':{k:v for k,v in deps.items() if k not in ('ghidra_path','java_home','host_os')},'language_id':raw['language_id'],'compiler_spec_id':raw['compiler_spec_id'],'options':raw.get('effective_analysis_options',{}),'limits':manifest['limits'],'auxiliary_inputs':[],'import_baseline_sha256':image.get('engine_baseline_sha256')}
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
        # Ghidra reference iteration order can differ between identical runs.
        # Normalize unordered collections without dropping duplicate evidence.
        for key in ('xrefs_to_entry', 'xrefs_from_sample'):
            if key in f:
                f[key] = sorted(f[key], key=canonical)
        engine_entry=f['entry_va']
        va=hex(int(engine_entry,16)) if engine_entry.startswith('0x') else None
        space='ram' if va is not None else engine_entry.partition(':')[0]
        fid=identity({'analysis_id':aid,'image_id':image['image_id'],'entry_va':va,'address_space':space,'engine_entry':engine_entry})
        f.update(function_id=fid,image_id=image['image_id'],arch=image['arch'],entry_va=va,address_space=space,engine_entry=engine_entry,analysis_id=aid,names=[{'name':f['name'],'origin':'ghidra'}],origin={'engine':'Ghidra','version':'12.2','evidence':'decoded/inferred'})
        f['entry_address']=location(engine_entry)
        for ins in f['instructions']:
            ins['location']=location(ins['addr'])
        f['instruction_bytes_sha256']=hashlib.sha256(bytes.fromhex(''.join(ins['bytes'] for ins in f['instructions']))).hexdigest()
        f['facets']={key:{'available': key in ('instructions','blocks') or f.get(key) is not None, 'reason': None if key in ('instructions','blocks') or f.get(key) else f.get('decompile_error') or 'Empty or unavailable engine facet'} for key in ('pseudocode','instructions','blocks')}
        displayed = redact(f.get('pseudocode'))
        f['address_spans'], f['facets']['address_spans'] = address_spans(f, displayed)
        if displayed != f.get('pseudocode') and 'address_spans' in f.get('coverage', {}):
            f['coverage'] = dict(f['coverage'], address_spans={
                'status': 'unavailable', 'emitted': 0, 'total': None, 'truncated': False, 'error': None,
                'reason': f['facets']['address_spans']['reason'],
            })
        validate_function(f)
        functions.append(f)
    functions.sort(key=lambda f:(f['entry_va'] is None,f['address_space'],int(f['entry_va'],16) if f['entry_va'] is not None else 0,f['engine_entry'],f['function_id']))
    value = {'analysis_id':aid,'image':{k:v for k,v in image.items() if k not in ('active_analysis','imported','import_dependencies')},'identity':analysis_key,'analysis_profile':selected_profile,'status':raw['status'],'functions':functions,'engine':{k:v for k,v in raw.items() if k not in ('functions','input_name','program_info_options')},'limitations':['C-like pseudocode is inferred, not original source or a semantic-equivalence proof.','Pseudocode spans cover available token addresses within the function body.','Function discovery and every facet are bounded; inspect facet coverage.','Only explicitly trusted owned fixtures are supported by this experimental worker mode.'] + (['Whole-program parameter inference is opt-in and binary-derived; inferred signatures and calling conventions may be wrong. No semantic-equivalence validation was performed.'] if selected_profile['parameter_inference'] else [])}
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


def page(rows,args,aid,project_id,filters,*,order='entry-va/function-id/v1'):
    binding=identity({'analysis':aid,'project':project_id,'filters':filters,'order':order})
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


def check_engine_access(args, project):
    if not args.experimental_trusted_input:
        raise Error('isolation_required','Engine operations require explicit --experimental-trusted-input for trusted user-owned fixtures only',3)
    if args.jobs != 1 or args.max_memory_mib is not None or args.startup_timeout is not None:
        raise Error('unsupported_budget','Only jobs=1, total --timeout and Java-only --heap-mib are supported; hard process-memory/startup budgets are rejected',3)
    if args.command == 'analyze':
        engine.analysis_profile(args.profile)
    if any(c in str(project.path) for c in ('"', '\\', '\n', '\r')):
        raise Error('worker_path_unsupported','Engine workspace paths containing quotes, backslashes or line breaks are not supported',3)


def fresh_decompile(args, project, image, function, aid, hints=None):
    if function['entry_va'] is None or function['is_external'] or function['is_thunk']:
        raise Error('fresh_function_unsupported','Fresh decompilation requires a non-thunk function in this image',3)
    deps = engine.dependencies(args.ghidra,args.java_home,full=True)
    result, job = engine.run(project,image,'query',args,deps,entry=function['entry_va'],hints=hints)
    fresh = flow_evidence.review(result['functions'][0], blocks=function.get('blocks', ()))
    facet = fresh['coverage']['pseudocode']
    complete = facet['status'] == 'complete' and bool(fresh['pseudocode'])
    spans, span_facet = address_spans(fresh, redact(fresh['pseudocode']))
    data = {
        'function_id': function['function_id'], 'image_id': image['image_id'], 'arch': image['arch'],
        'entry_va': function['entry_va'], 'names': function['names'],
        'pseudocode': fresh['pseudocode'], 'decompile_status': fresh['decompile_status'],
        'pseudocode_truncated': fresh['pseudocode_truncated'],
        'address_spans': spans, 'address_span_coverage': span_facet,
        'origin': {'mode': 'fresh_readonly', 'job_id': job['job_id'],
                   'analysis_profile': job['analysis_profile'], 'bridge_version': result['bridge_version']},
    }
    if hints is not None:
        data['origin'].update(type_hint_view_id=job['type_hint_view_id'],
                              applied_type_hints=result['applied_type_hints'])
    for field in ('control_flow_review', 'control_flow_gaps', 'engine_decompile_status'):
        if field in fresh:
            data[field] = fresh[field]
    diagnostics = [fresh['decompile_error']] if fresh.get('decompile_error') else []
    reason = 'unresolved_control_flow' if 'control_flow_gaps' in fresh else 'pseudocode_incomplete'
    return envelope('decompile',redact(data),aid,'complete' if complete else 'partial',
                    coverage('fresh selected function pseudocode',int(bool(fresh['pseudocode'])),1,
                             not complete,reason=None if complete else reason),
                    redact(diagnostics))


def revise_annotation(args, project, command):
    if args.command == 'rename':
        if (args.label is not None) == args.clear:
            raise Error('annotation_value','Supply a user label or --clear',2)
        kind = 'name'
        value = None if args.clear else annotations.valid_text(args.label,'label',256)
    elif args.command == 'type':
        if not args.accept:
            raise Error('type_hint_acceptance','Pass --accept to change a user-supplied type hint',2)
        kind = 'return_type'
        value = annotations.return_type(args.return_type) if args.action == 'set' else None
    else:
        kind = 'comment'
        value = annotations.valid_text(args.text,'comment',4096,multiline=True) if args.action == 'set' else None
    author = annotations.valid_text(args.author,'author',128)
    with project.writer():
        image = project.select(args.image,args.arch)
        snapshot,_ = project.snapshot(image)
        _,rows = annotations.read(project,image['image_id'])
        try:
            function = select_function(annotations.with_labels(snapshot['functions'],rows),args)
            entry = function['engine_entry']
        except Error as error:
            if kind != 'return_type' or value is not None or not args.address or error.code != 'function_selector':
                raise
            entry = hex(int(args.address,16))
            if not any(row['kind']=='return_type' and row['engine_entry']==entry for row in rows):
                raise
            function = None
        if kind == 'return_type' and value is not None:
            if function['entry_va'] is None or function['is_external'] or function['is_thunk']:
                raise Error('type_hint_function','Return hints require a non-thunk function in the image',3)
            entries = {row['engine_entry'] for row in rows if row['kind']=='return_type'}
            if len(entries)>=annotations.MAX_TYPE_HINTS and function['engine_entry'] not in entries:
                raise Error('type_hint_limit','Image return-type hint limit reached',7)
        prior = rows if getattr(args,'action',None) == 'remove' else ()
        instruction = annotations.instruction_at(function,getattr(args,'instruction',None),prior=prior)
        row,changed = annotations.revise(project,image['image_id'],snapshot['analysis_id'],
                                         entry,instruction,kind,value,author)
    return envelope(command,{'revision':row,'changed':changed},snapshot['analysis_id'])


def import_annotations(args, project):
    bundle = annotation_transfer.load(args.path)
    with project.writer():
        image = project.select(args.image, args.arch)
        snapshot, _ = project.snapshot(image)
        metadata.verified_slice(project, image)
        added = annotation_transfer.apply(project, image, snapshot, bundle, args.accept_type_hints)
    return envelope('annotations import', {'image_id': image['image_id'], 'appended_revisions': added},
                    snapshot['analysis_id'], cov=coverage('appended image annotation history', added, added))


def import_slice(project, image, original, args, deps):
    artifact = project.path/'inputs'/(image['artifact_sha256']+'.artifact')
    if not artifact.exists():
        atomic(artifact,original,mode=0o400)
    elif hashlib.sha256(read_regular(artifact)).hexdigest()!=image['artifact_sha256']:
        raise Error('input_integrity','Existing immutable artifact is corrupt')
    snap = project.path/'inputs'/(image['image_id']+'.macho')
    start, size = int(image['offset'],16), int(image['size'],16)
    if not snap.exists():
        atomic(snap,original[start:start+size],mode=0o400)
    elif hashlib.sha256(read_regular(snap)).hexdigest()!=image['sha256']:
        raise Error('input_integrity','Existing immutable slice is corrupt')
    raw,job = engine.run(project,image,'import',args,deps)
    if raw.get('validation',{}).get('headless_analysis_enabled') is not False:
        raise Error('import_analysis','Import did not disable autoanalysis',10)
    image['loader_evidence'] = {k:raw[k] for k in ('executable_format','language_id','compiler_spec_id','executable_sha256')}
    image['import_dependencies'] = deps
    image['engine_baseline_sha256'] = engine.tree_digest(project.path/'engine'/image['image_id'])
    with project.db(False) as db:
        db.execute('INSERT OR REPLACE INTO images(id,arch,metadata,imported) VALUES(?,?,?,1)',
                   (image['image_id'],image['arch'],canonical(image).decode()))
    return job['job_id']


def import_inputs(args, project, deps):
    bundled = bool(args.include_images)
    targets = bundle.select_images(args.input,args.include_images) if bundled else [(args.input,None,None)]
    existing = {row['image_id'] for row in project.images() if row['imported']}
    scope = 'explicitly selected bundle slices' if bundled else 'explicitly selected slices'
    result = []
    size_total = 0
    known_total = None
    failed_slice = None
    relative = None
    try:
        for index,(path,relative,expected_sha) in enumerate(targets):
            failed_slice = None
            if bundled:
                original = read_regular(path)
                size_total += len(original)
                if size_total > bundle.MAX_HASH_BYTES:
                    raise Error('bundle_input_limit','Selected bundle images exceed the 512 MiB aggregate limit',7)
                meta = dict(inspect_bytes(original),input_name=path.name)
                if expected_sha and meta['artifact_sha256'] != expected_sha:
                    raise Error('bundle_image_changed','Bundle image changed after inventory',5)
            else:
                meta,original = inspect_path(path)
            if len(meta['slices'])>1 and args.arch is None:
                raise Error('arch_required','Universal input requires explicit --arch arm64|x86_64|all',2)
            selected = [s for s in meta['slices'] if args.arch in (None,'all',s['arch'])]
            if not selected:
                raise Error('arch_missing','Requested architecture is not present',2)
            if index == len(targets)-1:
                known_total = len(result)+len(selected)
            for slice_meta in selected:
                image = dict(slice_meta,artifact_sha256=meta['artifact_sha256'],input_name=meta['input_name'])
                failed_slice = image['image_id']
                row = {'image_id':failed_slice,'arch':image['arch']}
                if bundled:
                    origin = {'relative_path':relative,'main_executable':index==0}
                    image['bundle_image'] = row['bundle_image'] = origin
                if failed_slice in existing:
                    row['status'] = 'already_imported'
                else:
                    row.update(status='imported',job_id=import_slice(project,image,original,args,deps))
                    existing.add(failed_slice)
                result.append(row)
    except Error as error:
        if not result:
            raise
        response = envelope('import',result,status='partial',
                            cov=coverage(scope,len(result),known_total,True,reason=error.code),
                            diagnostics=[str(error)])
        partial = {'completed_slices':result,'failed_slice':failed_slice}
        if bundled:
            partial['failed_bundle_image'] = relative
        response['error'] = {'code':error.code,'message':str(error),
                             'affected_object':failed_slice or relative,
                             'retryable':error.retryable,'partial_results':partial}
        return response
    return envelope('import',result,cov=coverage(scope,len(result),known_total))


def metadata_collection(args, project, image, snapshot=None):
    rows,filters,gap = metadata.records(args,project,image,snapshot)
    aid = snapshot['analysis_id'] if snapshot else None
    rows,cov = page(rows,args,aid or image['image_id'],project.project_id,filters,order='metadata-address/v1')
    cov['scope'] = 'selected image '+args.command
    if gap:
        reasons = [gap,*(['page_limit'] if cov['next_cursor'] else [])]
        cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
    return envelope(args.command,rows,aid,'partial' if gap else 'complete',cov)


def dyld_exports(args, project, image):
    extent, records, gaps = export_trie.exports(metadata.verified_slice(project, image), image)
    records = [row for row in records if args.name_contains is None or args.name_contains in row['name']]
    records.sort(key=lambda row: (row['name'], row['name_hex']))
    rows, cov = page(records, args, image['image_id'], project.project_id,
                     {'source': 'dyld', 'name_contains': args.name_contains}, order='dyld-export-name/v1')
    cov['scope'] = 'selected image dyld export trie'
    if gaps:
        reasons = [*gaps, *(['page_limit'] if cov['next_cursor'] else [])]
        cov.update(status='partial', known_total=None, truncation_reason=';'.join(reasons))
    data = {'image_id': image['image_id'], 'arch': image['arch'], 'extent': extent, 'records': rows}
    return envelope('exports', data, status='partial' if gaps else 'complete', cov=cov)


def swift_collection(args, project, image):
    if args.demangle and not args.experimental_trusted_input:
        raise Error('isolation_required','Native Swift demangling requires --experimental-trusted-input',3)
    info,records,gaps = swift_symbols.symbols(metadata.verified_slice(project,image))
    records = [dict(row,image_id=image['image_id'],arch=image['arch']) for row in records
               if args.name_contains is None or args.name_contains in row['mangled']]
    records.sort(key=lambda row:(row['mangled'],row['symbol_index']))
    filters = {'name_contains':args.name_contains,'demangle':args.demangle}
    rows,cov = page(records,args,image['image_id'],project.project_id,filters,order='swift-symbol/v1')
    provenance = None
    if args.demangle:
        eligible = []
        for row in rows:
            if swift_symbols.demangleable(row['mangled']):
                eligible.append(row)
            else:
                row['demangle_status'] = 'unsupported_name'
                gaps.append('unsupported_mangling')
        try:
            demangled,provenance = swift_symbols.demangle([row['mangled'] for row in eligible])
            for row,value in zip(eligible,demangled):
                row.update(value)
                if value['demangle_status']!='demangled':
                    gaps.append('unrecognized_mangling')
        except Error as error:
            for row in eligible:
                row['demangle_status'] = 'unavailable'
            gaps.append(error.code)
    cov['scope'] = 'selected image Swift symbol-table candidates'
    if gaps:
        reasons = [*sorted(set(gaps)),*(['page_limit'] if cov['next_cursor'] else [])]
        cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
    return envelope('swift symbols',dict(info,records=rows,demangler=provenance),
                    status='partial' if gaps else 'complete',cov=cov)


def execute(a):
    limits(a)
    fresh = a.command == 'decompile' and a.fresh
    with_hints = a.command == 'decompile' and a.with_type_hints
    if with_hints and not fresh:
        raise Error('type_hints_require_fresh','Type-hinted decompilation requires --fresh',3)
    if fresh and a.all:
        raise Error('fresh_selection','--fresh requires one function selector',2)
    term = search.pattern(a.query) if a.command == 'search' else None
    command=a.command+(' '+a.action if hasattr(a,'action') else '')
    if a.command=='version':
        return envelope(command,{'cli_version':__version__,'schema_version':SCHEMA_VERSION,'bridge_version':'1.4.0','backend':'full Ghidra headless','required_engine':'12.2','required_jdk':'25.0.5.0.3','python':sys.version.split()[0],'runtime_dependencies':[],'dependency_status':'not probed; use doctor'})
    if a.command=='doctor':
        deps=engine.dependencies(a.ghidra,a.java_home,full=a.full_digest)
        deps['capabilities']={'cached_queries':True,'fresh_selected_decompile':True,'engine_operations':'experimental --experimental-trusted-input only','hard_process_memory_limit':False,'startup_deadline':False,'automatic_dependency_install':False,'analysis_profiles':[engine.analysis_profile(n) for n in engine.ANALYSIS_PROFILES]}
        return envelope(command,deps)
    if a.command=='inspect':
        data,_=inspect_path(a.input)
        gaps=metadata.loader_gaps(data['slices'])
        return envelope(command,data,status='partial' if gaps else 'complete',
                        cov=coverage('Mach-O preflight',len(data['slices']),len(data['slices']),bool(gaps),
                                     reason='loader_metadata_incomplete' if gaps else None),diagnostics=gaps)
    if a.command=='bundle':
        inventory,gaps=bundle.inventory(a.path,a.kind)
        inventory_id=identity({'inventory':inventory,'gaps':gaps})
        rows,cov=page(inventory['records'],a,inventory_id,identity(os.path.abspath(a.path)),
                      {'kind':a.kind},order='bundle-relative-path/v1')
        cov['scope']='physical entries in selected bundle: '+a.kind
        if gaps:
            reasons=[*gaps,*(['page_limit'] if cov['next_cursor'] else [])]
            cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
        data=dict(inventory,inventory_id=inventory_id,records=rows)
        return envelope(command,data,status='partial' if gaps else 'complete',cov=cov)
    if a.command=='demangle':
        if not a.experimental_trusted_input:
            raise Error('isolation_required','Native Swift demangling requires --experimental-trusted-input',3)
        records,provenance=swift_symbols.demangle([a.name])
        result=records[0]
        partial=result['demangle_status']!='demangled'
        return envelope(command,dict(result,demangler=provenance),status='partial' if partial else 'complete',
                        cov=coverage('Swift name',partial=partial,reason='unrecognized_mangling' if partial else None))
    if a.command=='project':
        p=Project.create(a.path)
        return envelope(command,{'project_id':p.project_id,'schema_version':'1.0'})
    p=Project(a.project)
    if a.command == 'rename' or (a.command in ('comment','type') and a.action != 'list'):
        return revise_annotation(a,p,command)
    if a.command == 'annotations' and a.action == 'import':
        return import_annotations(a,p)
    if fresh or a.command in ('import','analyze'):
        check_engine_access(a,p)
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
        deps=engine.dependencies(a.ghidra,a.java_home,full=True)
        with p.writer():
            if a.command=='import':
                return import_inputs(a,p,deps)
            image=p.select(a.image,a.arch)
            if hashlib.sha256(read_regular(p.path/'inputs'/(image['image_id']+'.macho'))).hexdigest()!=image['sha256']:raise Error('input_integrity','Immutable slice digest mismatch')
            if engine.tree_digest(p.path/'engine'/image['image_id'])!=image['engine_baseline_sha256']:raise Error('baseline_integrity','Saved import Program DB changed; create a fresh project')
            raw,job=engine.run(p,image,'analyze',a,deps)
            normalized=normalize(raw,image,deps,job)
            aid=normalized['analysis_id']
            out=p.path/'snapshots'/(aid+'.json')
            payload=canonical(normalized)+b'\n'
            if len(payload)>MAX_SNAPSHOT_BYTES:
                raise Error('snapshot_limit','Normalized snapshot exceeds its read limit; analyze fewer functions',7)
            if out.exists():
                if read_regular(out,MAX_SNAPSHOT_BYTES)!=payload:raise Error('nondeterministic_snapshot','Identical analysis identity produced different output; previous snapshot retained',5)
            else:atomic(out,payload,mode=0o400)
            record={'snapshot_sha256':hashlib.sha256(payload).hexdigest(),'job_id':job['job_id'],'analysis_program_sha256':engine.tree_digest(p.path/'jobs'/job['job_id']/'program')}
            with p.db(False) as db:
                db.execute('INSERT OR IGNORE INTO analyses(id,image_id,payload) VALUES(?,?,?)',(aid,image['image_id'],canonical(record).decode()))
                db.execute('UPDATE images SET active_analysis=? WHERE id=?',(aid,image['image_id']))
            view = flow_evidence.snapshot_view(normalized)
            data = {'image_id': image['image_id'], 'function_count': len(normalized['functions']),
                    'job_id': job['job_id'], 'decompile_summary': raw.get('decompile_summary'),
                    'analysis_profile': job['analysis_profile'], 'limitations': normalized['limitations']}
            reasons = ['engine_or_facet_partial'] if raw['status'] != 'complete' else []
            if 'control_flow_review' in view:
                data['control_flow_review'] = view['control_flow_review']
                reasons.append('unresolved_control_flow')
            return envelope(command,data,aid,view['status'],
                            coverage('selected image analysis',len(normalized['functions']),
                                     raw.get('function_count_total_reported_by_engine'),bool(reasons),
                                     reason=';'.join(reasons) or None))
    image=p.select(a.image,a.arch)
    if a.command=='headers':
        data=metadata.headers(p,image)
        gaps=metadata.loader_gaps([data])
        return envelope(command,data,status='partial' if gaps else 'complete',
                        cov=coverage('selected image headers',partial=bool(gaps),
                                     reason='loader_metadata_incomplete' if gaps else None),diagnostics=gaps)
    if a.command=='swift':
        return swift_collection(a,p,image)
    if a.command=='bytes':
        return envelope(command,metadata.read_bytes_at(p,image,a.address,a.byte_length),
                        cov=coverage('selected image bytes',a.byte_length,a.byte_length))
    if a.command=='fixups':
        info,records,gaps=dyld.fixups(metadata.verified_slice(p,image),image)
        records=[row for row in records if a.kind=='all' or row['kind']==a.kind]
        records.sort(key=lambda row:int(row['va'],16))
        rows,cov=page(records,a,image['image_id'],p.project_id,{'kind':a.kind},order='fixup-address/v1')
        cov['scope']='selected image dyld fixups: '+a.kind
        if gaps:
            reasons=[*gaps,*(['page_limit'] if cov['next_cursor'] else [])]
            cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
        data=dict(info,image_id=image['image_id'],arch=image['arch'],records=rows)
        return envelope(command,data,status='partial' if gaps else 'complete',cov=cov)
    if a.command=='objc':
        records,gaps=objc.inventory(metadata.verified_slice(p,image),image,a.action)
        records=[dict(row,image_id=image['image_id'],arch=image['arch'])
                 for row in records if a.name_contains is None or a.name_contains in row['name']]
        records.sort(key=lambda row:(row['name'],row.get('class_name') or '',
                                    int(row.get('record_va',row.get('class_va')),16)))
        rows,cov=page(records,a,image['image_id'],p.project_id,
                      {'action':a.action,'name_contains':a.name_contains},order='objc-name/address/v1')
        cov['scope']='selected image Objective-C '+a.action
        if gaps:
            reasons=[*gaps,*(['page_limit'] if cov['next_cursor'] else [])]
            cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
        return envelope(command,rows,status='partial' if gaps else 'complete',cov=cov)
    if a.command in metadata.PREFLIGHT_LISTS:
        return metadata_collection(a,p,image)
    if a.command == 'exports' and a.source == 'dyld':
        return dyld_exports(a,p,image)
    snapshot,record=p.snapshot(image)
    if a.command in metadata.ENGINE_LISTS:
        return metadata_collection(a,p,image,snapshot)
    aid=snapshot['analysis_id']
    if a.command == 'annotations' and a.action == 'export':
        transfer = annotation_transfer.export(p,image)
        total = len(transfer['revisions'])
        return envelope(command,transfer,aid,cov=coverage('portable image annotation history',total,total))
    snapshot = flow_evidence.snapshot_view(snapshot)
    functions = snapshot['functions']
    if a.command == 'export' and not a.include_annotations:
        revision, annotations_rows = 0, []
    else:
        revision, annotations_rows = annotations.read(p,image['image_id'],history=a.command=='annotations')
    functions = annotations.with_labels(functions,annotations_rows)
    if a.command in ('comment','type','annotations'):
        function = select_function(functions,a) if any((a.address,a.function_id,a.name)) else None
        entry = function['engine_entry'] if function else None
        kind = {'comment':'comment','type':'return_type'}.get(a.command)
        rows = [row for row in annotations_rows
                if (entry is None or row['engine_entry'] == entry)
                and (kind is None or row['kind'] == kind)]
        rows,cov = page(rows,a,aid,p.project_id,{'annotation_revision':revision,'entry':entry,'command':command},
                        order='annotation-revision/v1')
        cov['scope'] = {'annotations':'image annotation revisions','comment':'current image comments',
                        'type':'accepted image return-type hints'}[a.command]
        return envelope(command,rows,aid,cov=cov)
    if a.command == 'search':
        view = dict(snapshot,functions=functions)
        hits, gaps = search.snapshot_matches(view,term,a.search_scope,comments=annotations_rows)
        filters={'query':a.query,'scope':a.search_scope}
        if revision and a.search_scope in ('names','comments','all'):filters['annotation_revision']=revision
        rows, cov = page(hits,a,aid,p.project_id,filters,order='search-kind/address/v1')
        cov['scope'] = 'committed image search: ' + a.search_scope
        if gaps:
            reasons = [*gaps, *(['page_limit'] if cov['next_cursor'] else [])]
            cov.update(status='partial', known_total=None, truncation_reason=';'.join(reasons))
        return envelope(command, rows, aid, 'partial' if gaps else 'complete', cov,
                        ['Search hits are leads from the selected committed analysis.'])
    if a.command=='export':
        if a.include_annotations:
            snapshot=dict(snapshot,annotations=redact({'revision':revision,'records':annotations_rows}))
        reason = 'unresolved_control_flow' if 'control_flow_review' in snapshot else None
        return envelope(command,snapshot,aid,snapshot['status'],coverage('committed normalized image export',len(functions),snapshot['engine'].get('function_count_total_reported_by_engine'),snapshot['status']!='complete',reason=reason),['Private recovered code/strings may be sensitive. Absolute host paths and volatile job timings are omitted.'])
    if a.command=='functions' and a.action=='list':
        rows=[f for f in functions if not a.name_contains or any(a.name_contains in n['name'] for n in f['names'])]
        filters={'name_contains':a.name_contains}
        if revision:filters['annotation_revision']=revision
        rows,cov=page(rows,a,aid,p.project_id,filters)
        if snapshot['engine'].get('functions_truncated'):
            cov.update(status='partial',known_total=None,truncation_reason='discovery_limit'+(';page_limit' if cov['next_cursor'] else ''))
        fields = ('function_id','image_id','arch','entry_va','address_space','engine_entry','body_ranges',
                  'names','signature','is_thunk','is_external','decompile_status','control_flow_review',
                  'control_flow_gaps','engine_decompile_status')
        return envelope(command,[{key: f[key] for key in fields if key in f} for f in rows],aid,cov=cov)
    if a.command=='decompile' and a.all:
        rows,cov=page(functions,a,aid,p.project_id,{'decompile':'all'})
        if snapshot['engine'].get('functions_truncated'):
            cov.update(status='partial',known_total=snapshot['engine'].get('function_count_total_reported_by_engine'),truncation_reason='discovery_limit')
        states=Counter(f['decompile_status'] for f in rows)
        partial=any(k not in ('complete','not_requested') for k in states)
        if partial:
            reason = ('unresolved_control_flow' if any('control_flow_gaps' in row for row in rows)
                      else 'pseudocode_incomplete')
            cov.update(status='partial', truncation_reason=';'.join(filter(None, (cov['truncation_reason'], reason))))
        return envelope(command,{'functions':rows,'summary':dict(states)},aid,'partial' if partial else 'complete',cov)
    f=select_function(functions,a)
    if fresh:
        hints=annotations.type_hints(annotations_rows,functions) if with_hints else None
        return fresh_decompile(a,p,image,f,aid,hints)
    if a.command=='calls':
        data,gaps=calls.graph(dict(snapshot,functions=functions),f,a.direction,a.depth,a.max_edges)
        count=len(data['edges'])
        return envelope(command,data,aid,'partial' if gaps else 'complete',
                        coverage('recorded call edges within requested depth',count,None if gaps else count,
                                 bool(gaps),reason=';'.join(gaps) or None))
    if a.command=='functions':
        notes=[row for row in annotations_rows if row['engine_entry']==f['engine_entry']]
        if notes:f=dict(f,annotations=notes)
        unresolved = 'control_flow_gaps' in f
        incomplete = unresolved or any(c.get('truncated') or c.get('error') for c in f.get('coverage',{}).values())
        reason = 'unresolved_control_flow' if unresolved else 'facet_incomplete' if incomplete else None
        return envelope(command,f,aid,'partial' if incomplete else 'complete',coverage('selected function evidence',1,1,incomplete,reason=reason))
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
        partial=bool((a.direction in ('to','both') and (f.get('xrefs_to_entry_truncated') or f.get('xrefs_to_entry_error'))) or (a.direction in ('from','both') and (f.get('xrefs_from_truncated') or f.get('xrefs_from_error'))))
        count=sum(len(v) for v in data.values() if isinstance(v,list))
    unresolved = 'control_flow_gaps' in f and (a.command != 'xrefs' or a.direction != 'to')
    if unresolved and a.command != 'decompile':
        data.update(control_flow_gaps=f['control_flow_gaps'], control_flow_review=f['control_flow_review'])
    partial = partial or unresolved
    reason = 'unresolved_control_flow' if unresolved else 'facet_incomplete' if partial else None
    return envelope(command,data,aid,'partial' if partial else 'complete',coverage('selected function '+a.command,count,None,partial,reason=reason))


def render(result,fmt):
    if fmt=='dot':
        rows=['digraph cfg {','  // status: '+result['status']+'; bounded static evidence, not exhaustive runtime flow']
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
