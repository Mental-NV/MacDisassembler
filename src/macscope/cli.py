"""Narrow phase-2 CLI. Completed snapshot queries never start a JVM."""
import argparse
import base64
from collections import Counter
import hashlib
import json
import os
import re
from pathlib import Path
import sqlite3
import sys
import tempfile
from unicodedata import normalize as normalize_unicode
from . import __version__, SCHEMA_VERSION
from .errors import Error
from . import trust
from .macho import inspect_bytes, inspect_path, read_regular, thin
from .pseudocode import address_spans
from .storage import (MAX_SNAPSHOT_BYTES, WORKSPACE_RESERVED, Project, atomic, atomic_chunks,
                      canonical, canonical_chunks, check_json_nesting, identity, is_digest, json_object,
                      program_history, validate_snapshot_functions, write_json)
from . import address_xrefs, annotation_transfer, annotations, binary_diff, bundle, callee_parameters, calls, direct_signatures, disassembly, dispatch_returns, doctor_probe, dyld, engine, export_trie, flow_boundaries, flow_evidence, forwarded_returns, import_state, jobs, metadata, objc, objc_types, scalar_signatures, search, swift_symbols, switch_tables
from . import import_disasm, callback_evidence, callback_links
from . import body_ownership, engine_checks, evidence, flow_gap_evidence, saved_flow_gap_evidence, focused, handoff_diff, html_export, macho_symbols, macho_unwind, manual_boundaries, pseudocode, resource_nib, resource_strings, string_evidence, terminal
from .schema import validate_envelope, validate_function

STATUS_SNAPSHOT_LIMIT = 8
STATUS_PROGRAM_LIMIT = 8


def coverage(scope='requested command', count=1, total=1, partial=False, cursor=None, reason=None):
    return {'scope':scope,'status':'partial' if partial else 'complete','returned_count':count,'known_total':total,'next_cursor':cursor,'truncation_reason':reason}


def envelope(command, data=None, aid=None, status='complete', cov=None, diagnostics=None):
    return {'schema_version':SCHEMA_VERSION,'command':command,'status':status,'analysis_id':aid,'data':data,'diagnostics':diagnostics or [],'coverage':cov or coverage()}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Error('usage', message, 2)


def parser():
    p = Parser(prog='macscope', description='Local Mach-O evidence CLI. Engine commands are experimental for explicitly trusted inputs only.')
    p.add_argument('--version', action='version', version='macscope '+__version__)
    sub = p.add_subparsers(dest='command',required=True)
    def common(s, formats=('text','json','jsonl')):
        s.add_argument('--format',choices=formats)
        s.add_argument('--json',dest='format',action='store_const',const='json')
        s.add_argument('--output')
        s.add_argument('--force',action='store_true')
    def project(s):
        s.add_argument('--project',required=True)
        s.add_argument('--image')
        s.add_argument('--arch',choices=('arm64','x86_64'))
    def address_options(s,g):
        g.add_argument('--address',help='Unslid hexadecimal virtual address')
        g.add_argument('--rva',help='Hexadecimal offset from the preferred Mach-O image base')
        g.add_argument('--file-offset',help='Hexadecimal offset within the selected Mach-O slice')
        g.add_argument('--runtime-address',help='Runtime hexadecimal virtual address with --load-slide')
        s.add_argument('--load-slide',help='Runtime VA minus unslid VA (use --load-slide=-0x... for negative slides)')
    def selector(s, required=True, all_option=False):
        g=s.add_mutually_exclusive_group(required=required)
        g.add_argument('--function-id')
        address_options(s,g)
        g.add_argument('--name')
        if all_option:g.add_argument('--all',action='store_true')
        return g
    def pagination(s):
        s.add_argument('--limit',type=int,default=100)
        s.add_argument('--cursor')
    def budgets(s):
        s.add_argument('--timeout',type=int,default=300,help='Total worker wall seconds (1..3600)')
        s.add_argument('--function-timeout',type=int,default=15,help='Per-function decompiler seconds (1..120)')
        s.add_argument('--startup-timeout',type=int,default=engine.STARTUP_TIMEOUT_SECONDS,
                       help='Seconds for headless initialization (1..3600, default 300)')
        s.add_argument('--max-memory-mib',type=int,help='Unsupported hard process cap, rejected explicitly')
        s.add_argument('--heap-mib',type=int,default=1024,help='Java heap only, not process memory (256..4096)')
        s.add_argument('--max-functions',type=int,default=1000,help='Maximum enumerated functions (1..10000)')
        s.add_argument('--jobs',type=int,default=1)
        s.add_argument('--trust-input','--experimental-trusted-input',dest='experimental_trusted_input',action='store_true',help='Confirm trust for this invocation; native processing is not a hostile-input sandbox')
        s.add_argument('--ghidra')
        s.add_argument('--java-home')
    for c in ('version','doctor'):
        s=sub.add_parser(c);common(s)
        if c=='doctor':
            s.add_argument('--ghidra')
            s.add_argument('--java-home')
            s.add_argument('--full-digest',action='store_true')
            checks=s.add_mutually_exclusive_group()
            checks.add_argument('--verify-worker',action='store_true',help='Run a full headless probe on a generated Mach-O')
            checks.add_argument('--host-only',action='store_true',help='Report host capabilities without reading dependencies or starting processes')
            checks.add_argument('--static',dest='static_runtime',action='store_true',help='Check native dependency files without executing Java or Ghidra')
            s.add_argument('--trust-input','--experimental-trusted-input',dest='experimental_trusted_input',action='store_true',help='Confirm trust for this invocation; native processing is not a hostile-input sandbox')
    s=sub.add_parser('inspect');s.add_argument('input');common(s)
    s=sub.add_parser('bundle');ss=s.add_subparsers(dest='action',required=True)
    s=ss.add_parser('list');s.add_argument('path');common(s);pagination(s)
    s.add_argument('--kind',choices=('all','images','resources'),default='all')
    s=sub.add_parser('resources');ss=s.add_subparsers(dest='action',required=True)
    s=ss.add_parser('list');s.add_argument('path');common(s);pagination(s)
    s.add_argument('--type',dest='resource_type',type=str.lower,
                   help='Match a filename extension without the dot, or file for extensionless resources')
    s.add_argument('--under',dest='resource_directory',metavar='DIRECTORY',
                   help='Start at an exact physical bundle-relative directory')
    s=ss.add_parser('strings',help='Decode one physical bundle-relative .strings resource')
    s.add_argument('path');common(s,('text','json'));pagination(s)
    s.add_argument('--file',required=True,help='Exact bundle-relative .strings file')
    s.add_argument('--key',help='Select one exact localization key')
    s=ss.add_parser('nib',help='Read archived AppKit connections and button labels as data')
    s.add_argument('path');common(s,('text','json'));pagination(s)
    s.add_argument('--file',required=True,help='Exact bundle-relative .nib file')
    s.add_argument('--kind',choices=('all','connections','labels'),default='all')
    s=sub.add_parser('project');ss=s.add_subparsers(dest='action',required=True)
    s=ss.add_parser('create');s.add_argument('path');common(s)
    s=sub.add_parser('import');s.add_argument('input');s.add_argument('--project',required=True);s.add_argument('--arch',choices=('arm64','x86_64','all'));common(s);budgets(s)
    s.add_argument('--repair',action='store_true',help='Rebuild an unavailable Program for an exact committed import')
    s.add_argument('--include-images',action='append',metavar='PATH|all',
                   help='Include an exact bundle-relative executable path in addition to the main image')
    s=sub.add_parser('analyze');project(s);s.add_argument('--profile',choices=tuple(engine.ANALYSIS_PROFILES),default='baseline',help='select baseline, binary-derived parameter inference, or deep analysis with additional address-table discovery');common(s);budgets(s)
    boundaries=s.add_mutually_exclusive_group()
    boundaries.add_argument('--repair-split-boundaries',action='store_true',help='Apply guarded linker-derived function joins to this analysis copy')
    boundaries.add_argument('--with-boundary-edits',action='store_true',help='Apply explicitly accepted function bodies to this analysis copy')
    s=sub.add_parser('status');project(s);common(s)
    s.add_argument('--verify-programs',action='store_true',
                   help='Check saved import and analysis Program digests without starting Ghidra')
    s=sub.add_parser('jobs');ss=s.add_subparsers(dest='action',required=True)
    for action in ('list','show','cancel','resume'):
        s=ss.add_parser(action);s.add_argument('--project',required=True);common(s)
        if action=='list':
            pagination(s)
        else:
            s.add_argument('job_id')
        if action=='resume':
            s.add_argument('--trust-input','--experimental-trusted-input',dest='experimental_trusted_input',action='store_true',help='Confirm trust for this invocation; native processing is not a hostile-input sandbox')
            s.add_argument('--ghidra')
            s.add_argument('--java-home')
    s=sub.add_parser('headers');project(s);common(s)
    s=sub.add_parser('unwind');project(s);common(s);pagination(s)
    s.add_argument('--source',choices=('compact','dwarf'),default='compact')
    s=sub.add_parser('fixups');common(s);pagination(s)
    source=s.add_mutually_exclusive_group(required=True)
    source.add_argument('--project')
    source.add_argument('--input',help='Read an owned Mach-O directly without starting Ghidra')
    s.add_argument('--image')
    s.add_argument('--arch',choices=('arm64','arm64e','x86_64'))
    s.add_argument('--kind',choices=('all','bind','rebase','non-weak-definition'),default='all',
                   help='Use non-weak-definition for declarations in the legacy weak-bind stream')
    s.add_argument('--address',help='Look up fixups at one exact unslid pointer slot')
    s=sub.add_parser('objc');ss=s.add_subparsers(dest='action',required=True)
    for c in ('classes','methods','selectors','properties','ivars'):
        s=ss.add_parser(c);project(s);common(s);pagination(s);s.add_argument('--name-contains')
        if c in ('methods','ivars'):
            s.add_argument('--class-slot',help='Select one unslid __objc_classlist or __objc_nlclslist pointer slot')
        if c in ('methods','ivars'):
            s.add_argument('--decode-types',action='store_true',help='Present recorded types without applying them to pseudocode')
    s=sub.add_parser('swift');ss=s.add_subparsers(dest='action',required=True)
    s=ss.add_parser('symbols');project(s);common(s);pagination(s);s.add_argument('--name-contains')
    s.add_argument('--demangle',action='store_true');s.add_argument('--trust-input','--experimental-trusted-input',dest='experimental_trusted_input',action='store_true',help='Confirm trust for this invocation; native processing is not a hostile-input sandbox')
    s=sub.add_parser('demangle');common(s);s.add_argument('name')
    s.add_argument('--trust-input','--experimental-trusted-input',dest='experimental_trusted_input',action='store_true',help='Confirm trust for this invocation; native processing is not a hostile-input sandbox')
    s=sub.add_parser('bytes');project(s);common(s)
    address_options(s,s.add_mutually_exclusive_group(required=True))
    s.add_argument('--length',type=int,required=True,dest='byte_length')
    for c in (*metadata.PREFLIGHT_LISTS,*metadata.ENGINE_LISTS):
        s=sub.add_parser(c);project(s);common(s);pagination(s)
        if c=='exports':
            s.add_argument('--source',choices=('ghidra','dyld'),default='ghidra')
        if c=='symbols':
            s.add_argument('--source',choices=('ghidra','macho','indirect'),default='ghidra')
        if c=='strings':
            s.add_argument('--contains')
            s.add_argument('--min-length',type=int,default=0)
            s.add_argument('--encoding',choices=('ascii','utf8','utf16le','auto'),default='auto')
        else:s.add_argument('--name-contains')
    s=sub.add_parser('functions');ss=s.add_subparsers(dest='action',required=True)
    for c in ('list','show'):
        s=ss.add_parser(c);project(s);common(s)
        if c=='show':selector(s)
        else:s.add_argument('--name-contains');pagination(s)
    for c in ('disasm','decompile','xrefs','cfg'):
        s=sub.add_parser(c);project(s);common(s,('text','json','dot') if c=='cfg' else ('text','json','jsonl'))
        selections=selector(s,all_option=c=='decompile')
        if c=='disasm':
            budgets(s)
            s.add_argument('--from-import',action='store_true',help='Linearly decode a bounded --range from the saved no-analysis import')
            s.add_argument('--receipt',help='Replay one saved import-disassembly job for the same range')
            s.add_argument('--callback-evidence',action='store_true',help='Add conservative arm64 callback-site byte facts; not a target or writer proof')
            s.add_argument('--callback-provenance',action='store_true',help='Track symbolic input registers without preserving values across calls')
            s.add_argument('--callback-abi',choices=('aapcs64',),help='Explicit conditional call-preservation hypothesis; requires --callback-evidence')
            s.add_argument('--callback-target-receipt',help='Link exactly one saved destination receipt; requires --callback-evidence')
            selections.add_argument('--range',dest='va_range',metavar='START:END',
                                    help='Show saved instructions in an unslid VA range (exclusive end)')
        if c=='decompile':
            pagination(s);budgets(s)
            source = s.add_mutually_exclusive_group()
            source.add_argument('--fresh',action='store_true',help='Reopen the saved analyzed Program and decompile one function')
            source.add_argument('--from-import',action='store_true',
                                help='Disassemble and decompile one exact --address from the saved no-analysis import')
            s.add_argument('--with-type-hints',action='store_true',help='Apply accepted type hints in the fresh query copy')
            s.add_argument('--recover-dispatch-return',action='store_true',
                           help='Use verified x86_64 dispatch return evidence in a fresh query')
            s.add_argument('--recover-direct-signatures',action='store_true',
                           help='Use verified x86_64 direct callee signatures in a fresh query')
            s.add_argument('--recover-scalar-call-signatures',action='store_true',
                           help='Use verified scalar call signatures in a fresh query')
            s.add_argument('--recover-callee-parameters',action='store_true',
                           help='Infer parameters along verified direct calls in a fresh query')
            s.add_argument('--recover-forwarded-return',action='store_true',
                           help='Recover an observed integer result forwarded through a direct call')
            s.add_argument('--recover-switch-table',action='store_true',
                           help='Recover a verified guarded switch in a fresh query')
        if c=='xrefs':
            selections.add_argument('--to',dest='xref_to',metavar='VA',help='Show references to this unslid address')
            selections.add_argument('--from',dest='xref_from',metavar='VA',help='Show references from this unslid address')
            s.add_argument('--direction',choices=('to','from','both'),help='Direction for function selectors (default both)')
            s.add_argument('--limit',type=int,help='Page size (address selectors default to 100)')
            s.add_argument('--cursor',help='Continue a reference query')
    s=sub.add_parser('search');project(s);common(s);pagination(s)
    s.add_argument('query')
    s.add_argument('--regex',action='store_true',help='Use a case-insensitive regular expression with a matching deadline')
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
    s.add_argument('--accept-boundary-edits',action='store_true')
    s=sub.add_parser('boundary');ss=s.add_subparsers(dest='action',required=True)
    for action in ('set','clear','list'):
        s=ss.add_parser(action);project(s);common(s)
        s.add_argument('--address',required=action!='list',help='Unslid hexadecimal entry VA')
        if action=='list':
            pagination(s)
        else:
            s.add_argument('--accept',action='store_true');s.add_argument('--author',default='local')
        if action=='set':
            change=s.add_mutually_exclusive_group(required=True)
            change.add_argument('--body',help='Inclusive START:END ranges separated by commas')
            change.add_argument('--remove',action='store_true',help='Remove the function at this entry')
    s=sub.add_parser('type');ss=s.add_subparsers(dest='action',required=True)
    for action in ('set','clear','list'):
        s=ss.add_parser(action);project(s);common(s);selector(s,required=action!='list')
        if action=='list':
            pagination(s)
        else:
            s.add_argument('--accept',action='store_true')
            s.add_argument('--author',default='local')
        if action=='set':
            hints=s.add_mutually_exclusive_group(required=True)
            hints.add_argument('--return-type')
            hints.add_argument('--parameters',help='Comma-separated fixed parameter types, or void for zero parameters')
        if action=='clear':
            s.add_argument('--parameters',action='store_true',help='Clear the parameter list hint')
    s=sub.add_parser('export');project(s);common(s,('text','json','jsonl','html'))
    s.add_argument('--include-annotations',action='store_true')
    s=sub.add_parser('evidence',help='Export a private handoff for pinned leads from committed evidence')
    common(s,('json','html'));s.add_argument('--project',required=True);s.add_argument('--leads',required=True)
    s.add_argument('--link-imports',action='store_true',help='Verify declared calls into pinned embedded libraries')
    s.add_argument('--link-focused',action='store_true',help='Verify direct calls between selected focused receipts')
    s=sub.add_parser('diff');common(s);pagination(s)
    s.add_argument('left',help='Left JSON export or evidence handoff')
    s.add_argument('right',help='Right JSON export or evidence handoff')
    s.add_argument('--scope',choices=('metadata','functions','pseudocode','evidence'),required=True)
    return p


def output_relative_to(target, protected):
    """Identify an output at or below a protected path, including filesystem aliases."""
    protected = Path(os.path.abspath(protected))
    if target.is_relative_to(protected):
        return target.relative_to(protected).parts
    try:
        source = protected.stat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    for candidate in (target, *target.parents):
        try:
            same = os.path.samestat(source, candidate.stat())
        except (FileNotFoundError, NotADirectoryError):
            continue
        if same:
            return target.parts[len(candidate.parts):]
    return None


def protect_output(args, target):
    inputs = [getattr(args, name, None) for name in ('input', 'left', 'right', 'leads')]
    if args.command in ('bundle','resources') or (args.command == 'annotations' and args.action == 'import'):
        inputs.append(args.path)
    for source in inputs:
        if source is not None and output_relative_to(target, source) is not None:
            raise Error('output_input_conflict', 'Output must be separate from the selected input', 8)
    workspace = args.path if args.command == 'project' else getattr(args, 'project', None)
    if workspace is not None:
        relative = output_relative_to(target, workspace)
        if relative is None and args.command == 'project':
            # The workspace may not exist yet. Check its future name against the
            # destination under the same parent, including case and Unicode aliases.
            folder = Path(os.path.abspath(workspace))
            sibling = output_relative_to(target, folder.parent)
            if sibling and (normalize_unicode('NFD', sibling[0]).casefold()
                            == normalize_unicode('NFD', folder.name).casefold()):
                relative = sibling[1:]
        if relative == () or (relative and relative[0].casefold() in WORKSPACE_RESERVED):
            raise Error('output_workspace_conflict', 'Output must be outside managed workspace storage', 8)


def limits(args):
    for key, low, high in [('timeout',1,3600),('startup_timeout',1,3600),('function_timeout',1,120),('heap_mib',256,4096),('max_functions',1,10000),('limit',1,1000),('depth',1,8),('max_edges',1,2000),('byte_length',1,4096),('min_length',0,1048576)]:
        v=getattr(args,key,None)
        if v is not None and not low<=v<=high:
            raise Error('argument_limit', key+' must be '+str(low)+'..'+str(high),2)
    if getattr(args,'output',None):
        target=Path(os.path.abspath(args.output))
        protect_output(args, target)
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
    if 'boundary_recovery' in manifest:
        analysis_key['boundary_recovery'] = manifest['boundary_recovery']
    if 'manual_boundaries' in manifest:
        analysis_key['manual_boundaries'] = manifest['manual_boundaries']
    ownership = body_ownership.find(raw.get('functions',()))
    if any(ownership):
        analysis_key['body_ownership_policy'] = body_ownership.POLICY
    aid=identity(analysis_key)
    raw = dict(raw)
    if 'strings' in raw:
        raw['strings'] = [string_evidence.omit_redacted_bytes(row, redact) for row in raw['strings']]
    for key in (address_xrefs.REFERENCES,address_xrefs.COMPUTED):
        if key in raw:
            raw[key] = sorted(raw[key],key=canonical)
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
        labels = sorted(f.pop('entry_labels',[]),key=canonical)
        names = [{'name':f['name'],'origin':'ghidra'},
                 *(dict(label,origin='ghidra_entry_label') for label in labels)]
        f.update(function_id=fid,image_id=image['image_id'],arch=image['arch'],entry_va=va,address_space=space,engine_entry=engine_entry,analysis_id=aid,names=names,origin={'engine':'Ghidra','version':'12.2','evidence':'decoded/inferred'})
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
    validate_snapshot_functions(functions,image,aid)
    entries = {f['engine_entry']:f['function_id'] for f in functions}
    for f in functions:
        if target := f.get('thunk_target'):
            entry = target['engine_entry']
            f['thunk_target'] = dict(target,address=location(entry),function_id=entries.get(entry),
                                     origin='ghidra_immediate_thunk_target')
    functions.sort(key=lambda f:(f['entry_va'] is None,f['address_space'],int(f['entry_va'],16) if f['entry_va'] is not None else 0,f['engine_entry'],f['function_id']))
    image_state = {'active_analysis','imported','import_dependencies','engine_baseline_job_id','previous_program_sha256'}
    value = {'analysis_id':aid,'image':{k:v for k,v in image.items() if k not in image_state},'identity':analysis_key,'analysis_profile':selected_profile,'status':raw['status'],'functions':functions,'engine':{k:v for k,v in raw.items() if k not in ('functions','input_name','program_info_options')},'limitations':['C-like pseudocode is inferred, not original source or a semantic-equivalence proof.','Pseudocode spans cover available token addresses within the function body.','Function discovery and every facet are bounded; inspect facet coverage.','Only explicitly trusted inputs are supported by this experimental worker mode; hostile-input isolation is not validated.'] + (['Whole-program parameter inference is opt-in and binary-derived; inferred signatures and calling conventions may be wrong. No semantic-equivalence validation was performed.'] if selected_profile['parameter_inference'] else [])}
    if selected_profile['name'] == 'deep':
        value['limitations'].append('Address-table references are inferred from binary evidence and do not establish indirect control-flow targets.')
    return redact(body_ownership.snapshot_view(value,ownership))


def resolve_selector(args, project, image, snapshot):
    rva, file_offset = getattr(args,'rva',None), getattr(args,'file_offset',None)
    if rva is None and file_offset is None:
        return args
    analyzed_base = snapshot['engine'].get('image_base')
    base = metadata.preferred_base(project,image) if rva is not None or analyzed_base is not None else None
    if rva is not None:
        address = metadata.rva_to_va(metadata.hex_address(rva,'RVA'),base)
    else:
        offset = metadata.hex_address(file_offset,'Slice file offset')
        address = metadata.mapped_location(image,offset,1,from_file=True)
        if address is None:
            raise Error('file_offset_unmapped','File offset has no unambiguous Mach-O section address',2)
    if base is not None and analyzed_base is not None and (
            not metadata.VA.fullmatch(analyzed_base) or int(analyzed_base,16) != base):
        code = 'rva_base_mismatch' if rva is not None else 'file_offset_base_mismatch'
        raise Error(code,'Ghidra and the Mach-O disagree on the image base. Use --function-id or --address.',3)
    return argparse.Namespace(**dict(vars(args),address=hex(address)))


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
    trust.require(args)
    if args.jobs != 1 or args.max_memory_mib is not None:
        raise Error('unsupported_budget','Only jobs=1 is supported. Use --heap-mib for the Java heap; hard process-memory budgets are rejected',3)
    if args.command == 'analyze':
        engine.analysis_profile(args.profile)
    if any(c in str(project.path) for c in ('"', '\\', '\n', '\r')):
        raise Error('worker_path_unsupported','Engine workspace paths containing quotes, backslashes or line breaks are not supported',3)


def fresh_decompile(args, project, image, function, source, revision, hints=None, *,
                    deps=None, resumed_from=None, signature_plan=None, address_selection=None):
    if function['entry_va'] is None or function['is_external'] or function['is_thunk']:
        raise Error('fresh_function_unsupported','Fresh decompilation requires a non-thunk function in this image',3)
    if deps is None:
        deps = engine.dependencies(args.ghidra,args.java_home,full=True)
    recovery = engine.signature_request(signature_plan) if signature_plan is not None else None
    gap_policy = None if recovery and recovery[0] == 'switch_table_recovery' else saved_flow_gap_evidence.POLICY
    if resumed_from is not None:
        original = jobs.restart_request(jobs.get(project,resumed_from)[1])
        gap_policy = (original or {}).get('flow_gap_policy')
    request = jobs.query_request(project,image,function,source,revision,hints,signature_recovery=recovery,
                                 address_selection=address_selection,flow_gap_policy=gap_policy)
    options = {} if signature_plan is None else {'signature_plan': signature_plan}
    result, job = engine.run(project,image,'query',args,deps,entry=function['entry_va'],hints=hints,
                             query_request=request,resumed_from=resumed_from,**options)
    blocks = switch_tables.reviewed_blocks(function.get('blocks', ()), result.get('switch_table_recovery'))
    fresh = flow_evidence.review(result['functions'][0], blocks=blocks, arch=image['arch'],
                                 instructions=function.get('instructions', ()))
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
        if 'aggregate_type_layouts' in result:
            data['origin']['aggregate_type_layouts'] = result['aggregate_type_layouts']
    if 'boundary_recovery' in job:
        data['origin']['boundary_recovery'] = job['boundary_recovery']
    if 'manual_boundaries' in job:
        data['origin']['manual_boundaries'] = job['manual_boundaries']
    if recovery is not None:
        data['origin'][recovery[0]] = result[recovery[0]]
    for field in ('control_flow_review', 'control_flow_gaps', 'control_flow_traps', 'engine_decompile_status', 'native_scope'):
        if field in fresh:
            data[field] = fresh[field]
    diagnostics = [fresh['decompile_error']] if fresh.get('decompile_error') else []
    reason = 'unresolved_control_flow' if 'control_flow_gaps' in fresh else 'pseudocode_incomplete'
    response = envelope('decompile',redact(data),image['active_analysis'],'complete' if complete else 'partial',
                        coverage('fresh selected function pseudocode',int(bool(fresh['pseudocode'])),1,
                                 not complete,reason=None if complete else reason),
                        redact(diagnostics))
    if address_selection is not None:
        response['address_selection'] = address_selection
    assisted = 'switch_table_recovery' in data['origin']
    if not assisted:
        response = flow_evidence.query_view(response,function)
        raw_snapshot, _ = project.snapshot(image)
        response = saved_flow_gap_evidence.annotate_query(project,image,raw_snapshot,source,response,request)
    with jobs.result_publication('query',job['job_id'],resumed_from):
        response = jobs.publish_query(project,resumed_from or job['job_id'],request,response)
    return flow_evidence.query_view(response,function) if assisted else response


def imported_disassembly(args, project, image, start, end):
    raw_slice = metadata.verified_slice(project,image)
    proof,payload = import_disasm.selection(raw_slice,image,start,end)
    def annotate(response):
        if not getattr(args,'callback_evidence',False):
            return response
        abi = getattr(args,'callback_abi',None)
        provenance = getattr(args,'callback_provenance',False)
        response = callback_evidence.project(response,abi=abi,provenance=provenance)
        target = getattr(args,'callback_target_receipt',None)
        return callback_links.attach(project,image,raw_slice,response,target,abi=abi,provenance=provenance) if target else response
    if args.receipt:
        response = import_disasm.replay(project,image,proof,payload,args.receipt)
        return annotate(response)
    with project.writer():
        jobs.verify_engine_writer_stopped(project)
        deps = engine.dependencies(args.ghidra,args.java_home,full=True)
        raw,job = import_disasm.run(project,image,args,deps,proof,payload)
        covered = import_disasm.validate_rows(raw,proof,payload)
        data = {'selection':import_disasm.binding(project,image,proof),'covered_bytes':covered,
                'instructions':raw['instructions'],'gaps':raw['gaps'],
                'origin':{'mode':'bounded_import_disassembly','job_id':job['job_id'],
                          **{key:deps[key] for key in ('ghidra_version','ghidra_tree_sha256','bridge_sha256')}}}
        partial = bool(raw['gaps'])
        response = envelope('disasm',data,status='partial' if partial else 'complete',
                            cov=coverage('selected bytes, linear decoding only',covered,len(payload),partial,
                                         reason='undecoded_range' if partial else None),
                            diagnostics=['Linear decoding does not prove function boundaries, reachability or runtime behavior.'])
        response = import_disasm.publish(project,job,response)
        return annotate(response)


def focused_decompile(args, project, image, *, entry=None, deps=None, resumed_from=None):
    if entry is None:
        entry = hex(metadata.hex_address(args.address, 'Unslid function entry'))
    if deps is None:
        deps = engine.dependencies(args.ghidra,args.java_home,full=True)
    result, job = engine.run(project,image,'query',args,deps,entry=entry,from_import=True,resumed_from=resumed_from)
    proof = job['focused_import']
    function = flow_evidence.review(result['functions'][0], arch=image['arch'], focused_extent=proof)
    request = job['focused_request']
    decoded_bytes = sum(len(row['bytes']) // 2 for row in function['instructions'])
    reasons = []
    if not function.get('pseudocode') or function['coverage']['pseudocode']['status'] != 'complete':
        reasons.append('unresolved_control_flow' if 'control_flow_gaps' in function else 'pseudocode_incomplete')
    if decoded_bytes != proof['length']:
        reasons.append('linker_extent_bytes_undecoded')
    spans, span_coverage = address_spans(function,redact(function['pseudocode']))
    data = dict(function, image_id=image['image_id'], arch=image['arch'], slice_sha256=image['sha256'],
                function_id=request['function_id'], address_space='ram', engine_entry=entry,
                names=[{'name':function['name'],'origin':'ghidra'}],
                instruction_bytes_sha256=hashlib.sha256(bytes.fromhex(''.join(
                    row['bytes'] for row in function['instructions']))).hexdigest(),
                facets={key:{'available':bool(function.get(key))} for key in ('pseudocode','instructions','blocks')},
                decoded_bytes=decoded_bytes, address_spans=spans, address_span_coverage=span_coverage,
                origin={'mode':'focused_readonly_import','job_id':job['job_id'],
                        'bridge_version':result['bridge_version'],'extent':proof,
                        **{key:deps[key] for key in ('ghidra_version','ghidra_tree_sha256','bridge_sha256')}})
    for key in ('xrefs_to_entry','xrefs_from_sample'):
        data[key] = sorted(data[key],key=canonical)
    data = flow_gap_evidence.annotate(data)
    diagnostics = [function['decompile_error']] if function.get('decompile_error') else []
    response = envelope('decompile',redact(data),status='partial' if reasons else 'complete',
                        cov=coverage('one selected linker extent from the saved import',1,1,bool(reasons),
                                     reason=';'.join(reasons) or None),diagnostics=redact(diagnostics))
    with jobs.result_publication('query',job['job_id'],resumed_from):
        return jobs.publish_query(project,resumed_from or job['job_id'],request,response)


def revise_annotation(args, project, command, address_selection):
    if args.command == 'rename':
        if (args.label is not None) == args.clear:
            raise Error('annotation_value','Supply a user label or --clear',2)
        kind = 'name'
        value = None if args.clear else annotations.valid_text(args.label,'label',256)
    elif args.command == 'type':
        if not args.accept:
            raise Error('type_hint_acceptance','Pass --accept to change a user-supplied type hint',2)
        if args.action == 'set':
            if args.parameters is None:
                kind, value = 'return_type', annotations.return_type(args.return_type)
            else:
                kind, value = 'parameter_types', annotations.encode_parameters(args.parameters)
        else:
            kind = 'parameter_types' if args.parameters else 'return_type'
            value = None
    else:
        kind = 'comment'
        value = annotations.valid_text(args.text,'comment',4096,multiline=True) if args.action == 'set' else None
    author = annotations.valid_text(args.author,'author',128)
    with project.writer():
        image = project.select(args.image,args.arch)
        if address_selection is not None:
            address_selection.update(image_id=image['image_id'],arch=image['arch'])
        snapshot,_ = project.snapshot(image)
        args = resolve_selector(args,project,image,snapshot)
        _,rows = annotations.read(project,image['image_id'])
        try:
            function = select_function(annotations.with_labels(snapshot['functions'],rows),args)
            entry = function['engine_entry']
        except Error as error:
            if kind not in annotations.TYPE_HINT_KINDS or value is not None or not args.address or error.code != 'function_selector':
                raise
            entry = hex(int(args.address,16))
            if not any(row['kind']==kind and row['engine_entry']==entry for row in rows):
                raise
            function = None
        if kind in annotations.TYPE_HINT_KINDS and value is not None:
            if function['entry_va'] is None or function['is_external'] or function['is_thunk']:
                raise Error('type_hint_function','Type hints require a non-thunk function in the image',3)
            scopes = {(row['engine_entry'],row['kind']) for row in rows if row['kind'] in annotations.TYPE_HINT_KINDS}
            if len(scopes)>=annotations.MAX_TYPE_HINTS and (entry,kind) not in scopes:
                raise Error('type_hint_limit','Image type hint limit reached',7)
            remaining = [row for row in rows if (row['engine_entry'],row['kind']) != (entry,kind)]
            annotations.check_structures([*remaining,{'kind':kind,'value':value}])
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
        added = annotation_transfer.apply(project,image,snapshot,bundle,args.accept_type_hints,
                                          accept_boundary_edits=args.accept_boundary_edits)
    return envelope('annotations import', {'image_id': image['image_id'], 'appended_revisions': added},
                    snapshot['analysis_id'], cov=coverage('appended image annotation history', added, added))


def boundary_command(args, project, command):
    entry = manual_boundaries.address(args.address) if args.address is not None else None
    kind = manual_boundaries.KIND
    if args.action == 'list':
        image = project.select(args.image,args.arch)
        revision, rows = annotations.read(project,image['image_id'],kind=kind,engine_entry=entry)
        rows,cov = page(rows,args,image['active_analysis'],project.project_id,
                        {'image':image['image_id'],'revision':revision,'kind':kind,'entry':entry},
                        order='annotation-revision/v1')
        cov['scope'] = 'accepted image function boundary edits'
        return envelope(command,rows,image['active_analysis'],cov=cov)
    if not args.accept:
        raise Error('boundary_edit_acceptance','Pass --accept to change a function boundary edit',2)
    author = annotations.valid_text(args.author,'author',128)
    with project.writer():
        image = project.select(args.image,args.arch)
        snapshot,_ = project.snapshot(image)
        value = None
        if args.action == 'set':
            _, rows = annotations.read(project,image['image_id'],kind=kind)
            if len(rows)>=manual_boundaries.MAX_EDITS and all(row['engine_entry']!=entry for row in rows):
                raise Error('boundary_edit_limit','At most 32 active function boundary edits are supported',7)
            before = manual_boundaries.saved_body(snapshot,entry)
            body = None if args.remove else manual_boundaries.parse_body(args.body,entry)
            value = manual_boundaries.value(before,body)
        row,changed = annotations.revise(project,image['image_id'],snapshot['analysis_id'],entry,None,kind,value,author)
    return envelope(command,{'revision':row,'changed':changed},snapshot['analysis_id'])


def job_command(args, project, command):
    if args.action == 'resume':
        return resume_job(args,project,command)
    if args.action != 'list':
        path, record = jobs.get(project,args.job_id)
        data = jobs.request_cancel(path,record) if args.action == 'cancel' else jobs.view(path,record,detail=True)
        if args.action == 'show':
            mode = record.get('mode')
            request = jobs.restart_request(record) or jobs.focused_record(record)
            receipt = None
            if mode == 'query' and request is not None:
                if 'address_selection' in request:
                    data['address_selection'] = request['address_selection']
                result = jobs.query_receipt(project,record.get('resumed_from',args.job_id),request)
                receipt = ({'job_id':result['data']['origin']['job_id'],'analysis_id':result['analysis_id']}
                           if result else None)
            elif mode in ('analyze','import'):
                receipt = jobs.publication(project,args.job_id,mode)
            if receipt:
                data['publication'] = receipt
                data['publication_status'] = ('published' if receipt['job_id'] == args.job_id
                                              else 'published_by_other_attempt')
            else:
                data['publication_status'] = 'not_published' if request is not None else 'unknown'
        return envelope(command,redact(data))
    rows, gaps = jobs.recent(project)
    rows, cov = page(rows,args,identity(rows),project.project_id,{},order='recent-worker-jobs/v1')
    cov['scope'] = 'recent workspace worker jobs'
    if gaps:
        reasons = [*gaps,*(['page_limit'] if cov['next_cursor'] else [])]
        cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
    return envelope(command,redact(rows),status='partial' if gaps else 'complete',cov=cov)


IMAGE_COVERAGE_FACETS = (
    'address_references', 'computed_flow_sites', 'effective_analysis_options', 'exports', 'functions',
    'imports', 'program_info_options', 'sections', 'strings', 'symbols',
)
FUNCTION_COVERAGE_FACETS = (
    'address_spans', 'body_ranges', 'cfg', 'entry_labels', 'instructions', 'pseudocode',
    'xrefs_from', 'xrefs_to_entry',
)


def facet_gap(facet):
    if not isinstance(facet, dict):
        return None
    if facet.get('truncated'):
        return 'limit'
    if facet.get('error') or facet.get('status') in ('partial','error','failed','timeout','unsupported','unknown'):
        return 'incomplete'
    return None


def analysis_coverage_reasons(snapshot):
    if snapshot['status'] == 'complete':
        return []
    raw = snapshot['engine']
    reasons = [reason for flag, reason in (
        ('analysis_timed_out', 'analysis_timeout'), ('functions_truncated', 'discovery_limit'),
        ('output_budget_reached', 'engine_output_limit'), ('strings_or_names_truncated', 'engine_text_limit'),
    ) if raw.get(flag)]
    image_facets = raw.get('coverage')
    if isinstance(image_facets, dict):
        for name in IMAGE_COVERAGE_FACETS:
            gap = facet_gap(image_facets.get(name))
            if gap and (name, gap) != ('functions', 'limit'):
                reasons.append(f'image_{name}_{gap}')
            elif gap and 'discovery_limit' not in reasons:
                reasons.append('discovery_limit')
    function_reasons = set()
    for function in snapshot['functions']:
        facets = function.get('coverage')
        if not isinstance(facets, dict):
            continue
        for name in FUNCTION_COVERAGE_FACETS:
            facet = facets.get(name)
            gap = facet_gap(facet)
            if gap and not (name == 'pseudocode' and facet.get('reason') == 'unresolved_control_flow'):
                function_reasons.add(f'function_{name}_{gap}')
    reasons.extend(sorted(function_reasons))
    recovery = raw.get('boundary_recovery')
    if isinstance(recovery, dict) and recovery.get('status') == 'partial':
        reasons.append('boundary_recovery_incomplete')
    if 'control_flow_review' in snapshot:
        reasons.append('unresolved_control_flow')
    reasons.extend(body_ownership.reasons(snapshot.get('body_ownership',{})))
    return reasons or ['engine_or_facet_partial']


def analysis_status(snapshot, record, pins):
    view = flow_evidence.snapshot_view(snapshot)
    raw = snapshot['engine']
    analysis_identity = snapshot.get('identity')
    saved = analysis_identity.get('engine') if isinstance(analysis_identity, dict) else None
    saved = saved if isinstance(saved, dict) else {}
    versions = {key: value if isinstance(value, str) else None for key, value in {
        'ghidra_version': saved.get('ghidra_version', raw.get('ghidra_version')),
        'bridge_version': raw.get('bridge_version'),
        'bridge_sha256': saved.get('bridge_sha256'),
        'ghidra_tree_sha256': saved.get('ghidra_tree_sha256'),
        'jdk_version': saved.get('jdk_version'),
    }.items()}
    changed = [key for key, expected in pins.items() if versions[key] is not None and versions[key] != expected]
    missing = [key for key in pins if versions[key] is None]
    freshness = 'stale' if changed else 'unknown' if missing else 'current'
    facets = raw.get('coverage')
    gaps = None
    if isinstance(facets, dict):
        gaps = sorted(name for name, facet in facets.items() if isinstance(facet, dict)
                      and (facet.get('status') in ('partial','unknown','failed','timeout','unsupported')
                           or facet.get('truncated') or facet.get('error')))
    total = raw.get('function_count_total_reported_by_engine')
    summary = raw.get('decompile_summary')
    return {'status':view['status'], 'analysis_id':snapshot['analysis_id'], 'job_id':record.get('job_id'),
            'function_count':len(snapshot['functions']),
            'function_total':total if type(total) is int and total >= 0 else None,
            'decompile_summary':summary if isinstance(summary, dict) else None,
            'analysis_profile':snapshot.get('analysis_profile'),
            'coverage_gaps':gaps, 'coverage_reasons':analysis_coverage_reasons(view), 'versions':versions,
            'freshness':{'status':freshness,'scope':'packaged_worker','changed':changed,'missing':missing}}


def program_status(check, *args):
    try:
        check(*args)
    except Error as error:
        return {'status':'unavailable','error':error.code}
    return {'status':'verified'}


def project_status(args, project):
    images = [row for row in project.images() if (args.image is None or row['image_id'] == args.image)
              and (args.arch is None or row['arch'] == args.arch)]
    if not images and (args.image is not None or args.arch is not None):
        raise Error('image_selector','No image matches the status selection',2)
    pins = {'ghidra_version':engine_checks.GHIDRA_VERSION,'bridge_version':engine.BRIDGE_VERSION,
            'bridge_sha256':engine.bridge_digest()}
    gaps, checked, programs_checked = set(), 0, 0
    for row in images:
        aid = row['active_analysis']
        record = None
        if aid is None:
            row['analysis'] = {'status':'not_analyzed','analysis_id':None}
        elif checked == STATUS_SNAPSHOT_LIMIT:
            row['analysis'] = {'status':'unverified','analysis_id':aid,'reason':'snapshot_check_limit'}
            gaps.add('snapshot_check_limit')
        else:
            checked += 1
            try:
                snapshot, record = project.snapshot(row)
                row['analysis'] = redact(analysis_status(snapshot,record,pins))
            except (Error, OSError) as error:
                code = error.code if isinstance(error, Error) else 'snapshot_unavailable'
                row['analysis'] = {'status':'unavailable','analysis_id':aid,'error':code}
                gaps.add('snapshot_unavailable')
        if not args.verify_programs:
            continue
        programs = {'import':{'status':'not_imported'}, 'analysis':{'status':'not_analyzed'}}
        row['programs'] = programs
        if not row['imported'] and aid is None:
            continue
        if programs_checked == STATUS_PROGRAM_LIMIT:
            limited = {'status':'unverified','reason':'program_check_limit'}
            if row['imported']:
                programs['import'] = limited
            if aid is not None:
                programs['analysis'] = limited
            gaps.add('program_check_limit')
            continue
        programs_checked += 1
        if row['imported']:
            programs['import'] = program_status(engine.imported_program,project,row)
        if record is not None:
            programs['analysis'] = program_status(engine.analyzed_program,project,record)
        elif aid is not None:
            reason = row['analysis'].get('reason','snapshot_unavailable')
            programs['analysis'] = {'status':'unverified','reason':reason}
        if any(value['status'] == 'unavailable' for value in programs.values()):
            gaps.add('program_unavailable')
    job_rows, job_gaps = jobs.recent(project)
    data = {'project_id':project.project_id,'images':images,'jobs':redact(job_rows),
            'job_history_limit':jobs.RECENT,'job_history_gaps':job_gaps}
    return envelope('status',data,status='partial' if gaps else 'complete',diagnostics=sorted(gaps),
                    cov=coverage('project status',len(images),len(images),bool(gaps),
                                 reason=';'.join(sorted(gaps)) if gaps else None))


def analysis_response(command, snapshot, job_id, *, resumed_from=None, reused=False):
    view = flow_evidence.snapshot_view(snapshot)
    data = {'image_id': snapshot['image']['image_id'], 'function_count': len(snapshot['functions']),
            'job_id': job_id, 'decompile_summary': snapshot['engine'].get('decompile_summary'),
            'analysis_profile': snapshot['analysis_profile'], 'limitations': snapshot['limitations']}
    if resumed_from is not None:
        data.update(resumed_from=resumed_from,reused_restart=reused)
    recovery = snapshot['engine'].get('boundary_recovery')
    if recovery is not None:
        data['boundary_recovery'] = recovery
    if 'manual_boundaries' in snapshot['engine']:
        data['manual_boundaries'] = snapshot['engine']['manual_boundaries']
    if 'control_flow_review' in view:
        data['control_flow_review'] = view['control_flow_review']
    if 'body_ownership' in view:
        data['body_ownership'] = view['body_ownership']
    reasons = analysis_coverage_reasons(view)
    return envelope(command,data,snapshot['analysis_id'],view['status'],
                    coverage('selected image analysis',len(snapshot['functions']),
                             snapshot['engine'].get('function_count_total_reported_by_engine'),bool(reasons),
                             reason=';'.join(reasons) or None))


def boundary_edit_request(project, image, *, at_revision=None):
    _, history = annotations.read(project,image['image_id'],kind=manual_boundaries.KIND,
                                  history=True,at_revision=at_revision)
    return manual_boundaries.request(history,image)


def analyze_image(project, image, args, deps, command, *, resumed_from=None, manual_plan=None):
    """Run analysis and publish its snapshot and receipt under the project writer lock."""
    data = metadata.verified_slice(project,image)
    thin(data, for_engine=True)
    boundary_request = recovery = None
    if getattr(args,'repair_split_boundaries',False):
        boundary_request = flow_boundaries.recovery_request(data,image)
        recovery = flow_boundaries.recovery_identity(boundary_request)
    if getattr(args,'with_boundary_edits',False):
        manual_plan = boundary_edit_request(project,image)
    options = {}
    if manual_plan is not None:
        options['manual_request'] = manual_plan
    edit_identity = manual_boundaries.request_identity(manual_plan) if manual_plan is not None else None
    baseline = engine.import_program_path(project,image)
    if (baseline.parent.is_symlink() or baseline.is_symlink() or not baseline.is_dir()
            or engine.tree_digest(baseline) != image['engine_baseline_sha256']):
        raise Error('baseline_integrity','Saved import Program DB changed; create a fresh project')
    raw,job=engine.run(project,image,'analyze',args,deps,boundary_request=boundary_request,
                       analysis_request=jobs.analysis_request(project,image,recovery,edit_identity),
                       resumed_from=resumed_from,**options)
    with jobs.result_publication('analysis',job['job_id'],resumed_from):
        return publish_analysis(project,image,deps,command,raw,job,resumed_from)


def publish_analysis(project, image, deps, command, raw, job, resumed_from):
    worker_dir=project.path/'jobs'/job['job_id']
    try:
        normalized=normalize(raw,image,deps,job)
        payload=canonical(normalized)+b'\n'
        if len(payload)>MAX_SNAPSHOT_BYTES and address_xrefs.omit_for_snapshot_budget(normalized):
            payload=canonical(normalized)+b'\n'
        if len(payload)<=MAX_SNAPSHOT_BYTES:
            check_json_nesting(payload)
    except (Error, AttributeError, KeyError, TypeError, ValueError, RecursionError) as error:
        failure = error if isinstance(error,Error) else Error('snapshot_format','Worker evidence could not be normalized')
        jobs.fail(worker_dir/'job.json',job,failure)
        if failure is error:
            raise
        raise failure from error
    aid=normalized['analysis_id']
    out=project.path/'snapshots'/(aid+'.json')
    if len(payload)>MAX_SNAPSHOT_BYTES:
        raise Error('snapshot_limit','Normalized snapshot exceeds its read limit; analyze fewer functions',7)
    try:
        program_digest=engine.saved_program_digest(worker_dir/'program','analysis_program_integrity')
    except Error as error:
        jobs.fail(worker_dir/'job.json',job,error)
        raise
    if out.exists():
        if read_regular(out,MAX_SNAPSHOT_BYTES)!=payload:
            raise Error('nondeterministic_snapshot','Identical analysis identity produced different output; previous snapshot retained',5)
    else:
        atomic(out,payload,mode=0o400)
    record={'snapshot_sha256':hashlib.sha256(payload).hexdigest(),'job_id':job['job_id'],
            'analysis_program_sha256':program_digest}
    try:
        with project.db(False) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute(jobs.PUBLISH)
            save_analysis_record(db,project,image['image_id'],aid,record)
            db.execute('UPDATE images SET active_analysis=? WHERE id=?',(aid,image['image_id']))
            db.execute('INSERT INTO analysis_publications(job_id,analysis_id,resumed_from) VALUES(?,?,?)',
                       (job['job_id'],aid,resumed_from))
    except sqlite3.Error as error:
        raise Error('analysis_publication','Could not commit the analysis and job receipt',8,retryable=True) from error
    return analysis_response(command,normalized,job['job_id'],resumed_from=resumed_from)


def save_analysis_record(db, project, image_id, aid, record):
    existing = db.execute('SELECT image_id,payload FROM analyses WHERE id=?',(aid,)).fetchone()
    if existing is None:
        db.execute('INSERT INTO analyses(id,image_id,payload) VALUES(?,?,?)',(aid,image_id,canonical(record).decode()))
        return
    previous = json_object(existing[1], 'snapshot_record', 'Invalid saved analysis record')
    if existing[0] != image_id or previous.get('snapshot_sha256') != record['snapshot_sha256']:
        raise Error('snapshot_record', 'Saved analysis record differs from the regenerated snapshot')
    history = program_history(previous,'analysis_program_sha256')
    try:
        engine.analyzed_program(project,previous)
    except Error:
        old_digest = previous.get('analysis_program_sha256')
        new_digest = record['analysis_program_sha256']
        history = [digest for digest in history if digest != new_digest]
        if is_digest(old_digest) and old_digest != new_digest:
            history.append(old_digest)
        if history:
            record['previous_program_sha256'] = history
        program_history(record,'analysis_program_sha256')
        db.execute('UPDATE analyses SET payload=? WHERE id=?',(canonical(record).decode(),aid))


def resume_job(args, project, command):
    with project.writer():
        path,record = jobs.get(project,args.job_id)
        record = jobs.record_for_resume(path,record)
        mode = record.get('mode')
        request = jobs.restart_request(record) or jobs.focused_record(record)
        if request is None:
            raise Error('job_resume_unsupported','The job has no supported recorded restart request',3)
        if 'resumed_from' in record:
            receipt = jobs.publication(project,args.job_id,mode) if mode != 'query' else None
            if receipt is None:
                raise Error('job_resume_conflict','Resume the original job to retry this attempt',8,
                            partial={'job_id':record['resumed_from']})
        else:
            jobs.verify_restart_stopped(project,path,record)
        if mode == 'import':
            return resume_import(args,project,command,record,request)
        if mode == 'query':
            if request['schema'] == jobs.FOCUSED_REQUEST:
                return resume_focused(args,project,command,record,request)
            return resume_query(args,project,command,record,request)
        return resume_analysis(args,project,command,record,request)


def replay_worker_request(args, project, record, *, query_profile=None):
    trust.require(args)
    mode, budgets, policy = record['mode'], record.get('limits'), record.get('analysis_profile')
    fields = {'timeout':'timeout_seconds','function_timeout':'function_timeout_seconds',
              'max_functions':'max_functions','heap_mib':'java_heap_mib'}
    if isinstance(budgets,dict) and 'startup_timeout_seconds' in budgets:
        fields['startup_timeout'] = 'startup_timeout_seconds'
    if not isinstance(budgets,dict) or any(type(budgets.get(key)) is not int for key in fields.values()):
        raise Error('job_manifest','Invalid recorded worker limits')
    profile = None
    if mode == 'analyze':
        if not isinstance(policy,dict) or not isinstance(policy.get('name'),str):
            raise Error('job_manifest','Invalid recorded analysis profile')
        profile = policy['name']
    replay = argparse.Namespace(command=mode,profile=profile,jobs=1,max_memory_mib=None,
                                experimental_trusted_input=True,
                                **{arg:budgets[key] for arg,key in fields.items()})
    replay.startup_timeout = getattr(replay,'startup_timeout',None)
    limits(replay)
    check_engine_access(replay,project)
    expected_profile = engine.analysis_profile(profile) if profile else query_profile
    if (expected_profile != policy
            or engine.worker_limits(replay,replay.max_functions) != budgets):
        raise Error('job_resume_policy','The recorded profile or worker limits differ from the supported policy',3)
    deps = engine.dependencies(args.ghidra,args.java_home,full=True)
    staged_image_id = record.get('image_id') if mode == 'import' else None
    if (not engine.dependencies_match(deps, record.get('dependencies'))
            or not engine.job_sandbox_matches(project, deps, record.get('job_id'), record.get('sandbox_sha256'),
                                              staged_image_id=staged_image_id, read_only_program=mode == 'query')):
        raise Error('job_resume_engine','Restart requires the recorded engine and JDK and a recognized worker policy',4)
    return replay,deps


def verify_replay_artifact(project, image):
    artifact = read_regular(project.path/'inputs'/(image['artifact_sha256']+'.artifact'))
    if hashlib.sha256(artifact).hexdigest()!=image['artifact_sha256']:
        raise Error('input_integrity','Immutable artifact digest differs from the recorded request')


def resume_focused(args, project, command, record, request):
    image_id, entry = request.get('image_id'), request.get('entry_va')
    if not is_digest(image_id) or not isinstance(entry,str) or not re.fullmatch(r'0x[0-9a-f]{1,16}',entry):
        raise Error('job_manifest','Invalid recorded focused query identity')
    if (request.get('project_id') != project.project_id or record.get('image_id') != image_id
            or record.get('source_analysis_id') is not None or record.get('selected_entry') != entry):
        raise Error('job_resume_inputs','The recorded focused query belongs to different inputs',8)
    image = project.select(image_id)
    baseline = request.get('source_program_sha256')
    if not image['imported'] or not jobs.matches_program(image,baseline,'engine_baseline_sha256'):
        raise Error('job_resume_inputs','The committed import identity is unavailable',8)
    extent, payload = focused.select(project,image,entry,policy=request.get("extent", {}).get("policy"))
    proof = dict(extent, program_sha256=baseline)
    if record.get('focused_import') != proof or jobs.focused_request(project,image,proof) != request:
        raise Error('job_resume_inputs','The focused request differs from its saved import or extent',8)
    response = jobs.query_receipt(project,args.job_id,request)
    reused = response is not None
    if reused:
        focused.verify_instructions(extent,payload,response['data'])
    else:
        if extent['policy'] not in focused.RESUMABLE_POLICIES:
            raise Error('job_resume_policy','An unfinished legacy focused query needs a new capture under the current policy',3)
        if baseline != image['engine_baseline_sha256']:
            raise Error('baseline_integrity','The original import Program is unavailable for this unfinished query')
        replay,deps = replay_worker_request(args,project,record)
        if replay.max_functions != 1:
            raise Error('job_manifest','A recorded focused query requires max_functions=1')
        verify_replay_artifact(project,image)
        response = focused_decompile(replay,project,image,entry=entry,deps=deps,resumed_from=args.job_id)
    data = response['data']
    reused = reused or data['origin']['job_id'] == args.job_id
    return dict(response,command=command,data=dict(data,resumed_from=args.job_id,reused_restart=reused))


def resume_query(args, project, command, record, request):
    image_id, aid = request.get('image_id'), request.get('source_analysis_id')
    function_id, entry = request.get('function_id'), request.get('entry_va')
    revision = request.get('annotation_revision')
    digests = (image_id, aid, function_id)
    if (not all(isinstance(value,str) and re.fullmatch(r'[0-9a-f]{64}',value) for value in digests)
            or not isinstance(entry,str) or not re.fullmatch(r'0x[0-9a-f]{1,16}',entry)
            or type(revision) is not int or revision < 0):
        raise Error('job_manifest','Invalid recorded fresh query identity')
    if (request.get('project_id') != project.project_id or record.get('image_id') != image_id
            or record.get('source_analysis_id') != aid or record.get('selected_entry') != entry):
        raise Error('job_resume_inputs','The recorded fresh query belongs to different inputs',8)
    image = dict(project.select(image_id),active_analysis=aid)
    address_selection = request.get('address_selection')
    if address_selection is not None:
        try:
            observed = metadata.runtime_selection(address_selection['runtime_va'],address_selection['load_slide'])
        except (Error, KeyError, TypeError) as error:
            raise Error('job_manifest','Invalid recorded runtime address selection') from error
        if (observed is None or dict(observed,image_id=image_id,arch=image['arch']) != address_selection
                or observed['va'] != entry):
            raise Error('job_resume_inputs','The recorded runtime address differs from the selected function',8)
    snapshot,source = project.snapshot(image)
    snapshot = flow_evidence.snapshot_view(snapshot)
    observed_revision,rows = annotations.read(project,image_id,at_revision=revision)
    if observed_revision != revision:
        raise Error('job_resume_inputs','The recorded annotation revision is unavailable',8)
    functions = annotations.with_labels(snapshot['functions'],rows)
    function = select_function(functions,argparse.Namespace(address=None,function_id=function_id))
    hints = annotations.type_hints(rows,functions) if request.get('type_hint_view_id') is not None else None
    fields = [key for key in jobs.SIGNATURE_RECOVERY_FIELDS if key in request]
    signature_plan, recovery = None, None
    if fields:
        if hints is not None or len(fields) != 1:
            raise Error('job_resume_inputs','The recorded query has conflicting signature evidence',8)
        policy, _ = engine.SIGNATURE_RECOVERIES[fields[0]]
        signature_plan = policy.request(metadata.verified_slice(project,image),image,function,functions)
        recovery = engine.signature_request(signature_plan)
    program_digest = request.get('source_program_sha256')
    if not jobs.matches_program(source, program_digest, 'analysis_program_sha256'):
        raise Error('job_resume_inputs','The fresh query Program does not belong to the saved analysis',8)
    request_source = dict(source,analysis_program_sha256=program_digest)
    if (jobs.query_request(project,image,function,request_source,revision,hints,signature_recovery=recovery,
                           address_selection=address_selection,flow_gap_policy=request.get('flow_gap_policy')) != request
            or record.get('type_hint_view_id') != request['type_hint_view_id']
            or record.get('type_hints') != hints
            or any(record.get(key) != request.get(key) for key in jobs.SIGNATURE_RECOVERY_FIELDS)):
        raise Error('job_resume_inputs','The fresh query request differs from its saved analysis, hints or recovery',8)
    response = jobs.query_receipt(project,args.job_id,request)
    reused = response is not None
    if response is None:
        if program_digest != source['analysis_program_sha256']:
            raise Error('analysis_program_integrity','The original Program is unavailable for this unfinished query')
        policy = engine.profile_for_snapshot(snapshot)
        replay,deps = replay_worker_request(args,project,record,query_profile=policy)
        if replay.max_functions != 1:
            raise Error('job_manifest','A recorded selected-function query requires max_functions=1')
        metadata.verified_slice(project,image)
        verify_replay_artifact(project,image)
        response = fresh_decompile(replay,project,image,function,source,revision,hints,
                                   deps=deps,resumed_from=args.job_id,signature_plan=signature_plan,
                                   address_selection=address_selection)
    if reused and saved_flow_gap_evidence.SOURCE_FIELD not in response['data']:
        response = flow_evidence.query_view(response,function)
    data = response['data']
    reused = reused or data['origin']['job_id'] == args.job_id
    return dict(response,command=command,data=dict(data,resumed_from=args.job_id,reused_restart=reused))


def resume_analysis(args, project, command, record, request):
    image_id = request.get('image_id')
    if not isinstance(image_id,str) or not re.fullmatch(r'[0-9a-f]{64}',image_id):
        raise Error('job_manifest','Invalid recorded analysis image ID')
    if request.get('project_id') != project.project_id or record.get('image_id') != image_id:
        raise Error('job_resume_inputs','The recorded request belongs to a different project or image',8)
    image = project.select(image_id)
    recovery = None
    if 'boundary_recovery' in request:
        boundary = flow_boundaries.recovery_request(metadata.verified_slice(project,image),image)
        recovery = flow_boundaries.recovery_identity(boundary)
    manual_plan = edit_identity = None
    if 'manual_boundaries' in request:
        recorded = request['manual_boundaries']
        cutoff = recorded.get('annotation_revision') if isinstance(recorded,dict) else None
        if type(cutoff) is not int or cutoff <= 0 or recovery is not None:
            raise Error('job_manifest','Invalid recorded boundary edit revision')
        manual_plan = boundary_edit_request(project,image,at_revision=cutoff)
        edit_identity = manual_boundaries.request_identity(manual_plan)
    current = jobs.analysis_request(project,image,recovery,edit_identity)
    digest = request.get('import_baseline_sha256')
    if (not jobs.matches_program(image,digest,'engine_baseline_sha256')
            or dict(request,previous_analysis_id=image['active_analysis']) != dict(current,import_baseline_sha256=digest)):
        raise Error('job_resume_inputs','The recorded immutable inputs differ from the workspace',8)
    if record.get('boundary_recovery') != recovery or record.get('manual_boundaries') != edit_identity:
        raise Error('job_resume_policy','The recorded boundary recovery policy differs from the request',3)
    receipt = jobs.publication(project,args.job_id)
    if receipt:
        if receipt['job_id'] == args.job_id:
            raise Error('job_completed','The original job already published an analysis',8,partial=receipt)
        snapshot,_ = project.snapshot(dict(image,active_analysis=receipt['analysis_id']))
        return analysis_response(command,snapshot,receipt['job_id'],resumed_from=args.job_id,reused=True)
    if request != current:
        raise Error('job_resume_conflict','The active analysis changed since the recorded request',8)
    jobs.verify_engine_writer_stopped(project)
    replay,deps = replay_worker_request(args,project,record)
    replay.repair_split_boundaries = recovery is not None
    artifact = read_regular(project.path/'inputs'/(image['artifact_sha256']+'.artifact'))
    if hashlib.sha256(artifact).hexdigest()!=image['artifact_sha256']:
        raise Error('input_integrity','Immutable artifact digest differs from the recorded request')
    if manual_plan is not None:
        return analyze_image(project,image,replay,deps,command,resumed_from=args.job_id,manual_plan=manual_plan)
    return analyze_image(project,image,replay,deps,command,resumed_from=args.job_id)


def resume_import(args, project, command, record, request):
    receipt = jobs.publication(project,args.job_id,'import')
    image, original = import_state.restore_request(project, request, record.get('image_id'),
                                                   for_engine=receipt is None)
    repair = request.get('repair_baseline')
    if receipt:
        if receipt['resumed_from'] != args.job_id:
            raise Error('job_completed','The original job already published an import',8,partial=receipt)
        if receipt['image_id'] != image['image_id']:
            raise Error('import_publication','The import receipt refers to a different image')
        job_id = receipt['job_id']
    else:
        if repair is not None:
            image = committed_repair_image(project,image,repair)
        elif any(item['imported'] and item['image_id'] == image['image_id'] for item in project.images()):
            raise Error('job_resume_conflict','The slice was imported by a different attempt',8)
        jobs.verify_engine_writer_stopped(project)
        replay,deps = replay_worker_request(args,project,record)
        job_id = import_state.import_slice(project,image,original,replay,deps,resumed_from=args.job_id,repair=repair)
    data = {'image_id':image['image_id'],'arch':image['arch'],'job_id':job_id,
            'resumed_from':args.job_id,'reused_restart':bool(receipt)}
    if 'bundle_image' in image:
        data['bundle_image'] = image['bundle_image']
    if repair is not None:
        data['status'] = 'repaired'
    return envelope(command,data,cov=coverage('recorded slice import'))


def committed_repair_image(project, image, repair):
    current = project.select(image['image_id'])
    if (not current['imported'] or import_state.baseline_binding(current) != repair
            or import_state.request_for(project,current,repair) != import_state.request_for(project,image,repair)):
        raise Error('import_baseline_conflict','The committed import differs from the recorded repair',8)
    return current


def repair_import(project, image, committed, original, args, deps):
    if committed is None or any(committed[key] != image[key] for key in ('arch','sha256','artifact_sha256')):
        raise Error('import_repair_input','Repair requires the exact artifact and slice of a committed import',3)
    repair = import_state.baseline_binding(committed)
    if not is_digest(repair['sha256']):
        raise Error('baseline_integrity','The committed import has no valid Program digest')
    try:
        engine.imported_program(project,committed)
    except Error:
        pass
    else:
        return {'status':'already_imported'}
    job_id = import_state.import_slice(project,committed,original,args,deps,repair=repair)
    return {'status':'repaired','job_id':job_id}


def import_inputs(args, project, deps):
    bundled = bool(args.include_images)
    targets = bundle.select_images(args.input,args.include_images) if bundled else [(args.input,None,None)]
    existing = {row['image_id']:row for row in project.images() if row['imported']}
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
                meta = dict(inspect_bytes(original,allow_arm64e=True,for_engine=True),input_name=path.name)
                if expected_sha and meta['artifact_sha256'] != expected_sha:
                    raise Error('bundle_image_changed','Bundle image changed after inventory',5)
            else:
                meta,original = inspect_path(path,allow_arm64e=True,include_companion=False,for_engine=True)
            if len(meta['slices'])>1 and args.arch is None:
                raise Error('arch_required','Universal input requires explicit --arch arm64|x86_64|all',2)
            selected = [s for s in meta['slices'] if args.arch in (None,'all',s['arch'])]
            if not selected:
                raise Error('arch_missing','Requested architecture is not present',2)
            if any(s['arch']=='arm64e' for s in selected):
                raise Error('unsupported_arch','arm64e is available for data-only inspection',3)
            if index == len(targets)-1:
                known_total = len(result)+len(selected)
            for slice_meta in selected:
                image = dict(slice_meta,artifact_sha256=meta['artifact_sha256'],input_name=meta['input_name'])
                failed_slice = image['image_id']
                row = {'image_id':failed_slice,'arch':image['arch']}
                if bundled:
                    origin = {'relative_path':relative,'main_executable':index==0}
                    image['bundle_image'] = row['bundle_image'] = origin
                if args.repair:
                    row.update(repair_import(project,image,existing.get(failed_slice),original,args,deps))
                    existing[failed_slice] = project.select(failed_slice)
                elif failed_slice in existing:
                    row['status'] = 'already_imported'
                else:
                    row.update(status='imported',job_id=import_state.import_slice(project,image,original,args,deps))
                    existing[failed_slice] = image
                result.append(row)
    except Error as error:
        if not result:
            raise
        response = envelope('import',result,status='partial',
                            cov=coverage(scope,len(result),known_total,True,reason=error.code),
                            diagnostics=[str(error)])
        partial = {'completed_slices':result,'failed_slice':failed_slice}
        if isinstance(error.partial,dict) and error.partial.get('job_id'):
            partial['failed_job_id'] = error.partial['job_id']
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
    if args.command == 'strings':
        string_evidence.enrich_page(project,image,snapshot,rows)
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


def file_symbols(args, project, image):
    data = metadata.verified_slice(project, image)
    records, gaps = macho_symbols.inventory(data, args.source, int(image['offset'],16))
    origin = 'macho_symtab' if args.source == 'macho' else 'macho_indirect_symbol_table'
    records = [dict(row,image_id=image['image_id'],arch=image['arch'],origin=origin) for row in records
               if args.name_contains is None or args.name_contains in (row['name'] or '')]
    rows, cov = page(records,args,image['image_id'],project.project_id,
                     {'source':args.source,'name_contains':args.name_contains},order='macho-symbol-index/v1')
    cov['scope'] = 'selected image Mach-O '+('symbol declarations' if args.source == 'macho' else 'indirect symbol slots')
    if gaps:
        reasons = [*gaps,*(['page_limit'] if cov['next_cursor'] else [])]
        cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
    return envelope('symbols',rows,status='partial' if gaps else 'complete',cov=cov,diagnostics=gaps)


def file_unwind(args, project, image):
    info, records, gaps = macho_unwind.inventory(metadata.verified_slice(project,image),int(image['offset'],16),
                                                source=args.source)
    records = [dict(row,image_id=image['image_id'],arch=image['arch']) for row in records]
    dwarf = args.source == 'dwarf'
    order = 'eh-frame-offset/v1' if dwarf else 'compact-unwind-rva/v1'
    rows,cov = page(records,args,image['image_id'],project.project_id,{},order=order)
    cov['scope'] = 'selected image DWARF call frame records' if dwarf else 'selected image compact unwind lookup ranges'
    if gaps:
        reasons = [*gaps,*(['page_limit'] if cov['next_cursor'] else [])]
        cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
    data = dict(info,image_id=image['image_id'],arch=image['arch'],records=rows)
    return envelope('unwind',data,status='partial' if gaps else 'complete',cov=cov,diagnostics=gaps)


def fixup_collection(args, image, data, binding, *, parsed=None, artifact=None):
    definitions = args.kind == 'non-weak-definition'
    address = metadata.hex_address(args.address,'Unslid fixup slot') if args.address is not None else None
    info,records,gaps = dyld.fixups(data,image,parsed=parsed,weak_definitions=definitions,address=address)
    if definitions:
        order = 'weak-bind-opcode-offset/v1'
    else:
        records = [row for row in records if args.kind == 'all' or row['kind'] == args.kind]
        records.sort(key=lambda row:int(row['va'],16))
        order = 'fixup-address/v1'
    filters = {'kind':args.kind}
    if address is not None:
        filters['address'] = hex(address)
    rows,cov = page(records,args,image['image_id'],binding,filters,order=order)
    cov['scope'] = 'selected image dyld fixups: '+args.kind
    if address is not None:
        cov['scope'] = 'exact unslid dyld fixup slot: '+args.kind
    if gaps:
        reasons = [*gaps,*(['page_limit'] if cov['next_cursor'] else [])]
        cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
    data = dict(info,image_id=image['image_id'],arch=image['arch'],records=rows)
    if address is not None:
        data.update(address=hex(address),artifact_sha256=artifact or image['artifact_sha256'],slice_sha256=image['sha256'])
    if artifact is not None:
        data.update(artifact_sha256=artifact,slice_sha256=image['sha256'],cpu_subtype=image['cpu_subtype'])
    return envelope('fixups',data,status='partial' if gaps else 'complete',cov=cov)


def file_fixups(args):
    if args.image is not None:
        raise Error('usage','--image selects an imported project image; use --arch with --input',2)
    metadata,original = inspect_path(args.input,allow_arm64e=True,include_companion=False)
    if len(metadata['slices']) > 1 and args.arch is None:
        raise Error('arch_required','Universal input requires an explicit --arch',2)
    selected = [row for row in metadata['slices'] if args.arch in (None,row['arch'])]
    if not selected:
        raise Error('arch_missing','Requested architecture is not present',2)
    image, = selected
    start,size = int(image['offset'],16),int(image['size'],16)
    artifact = metadata['artifact_sha256']
    return fixup_collection(args,image,original[start:start+size],identity({'file':artifact}),
                            parsed=image,artifact=artifact)


def swift_collection(args, project, image):
    if args.demangle:
        trust.require(args)
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


def verify_doctor_worker(deps):
    stage = 'workspace'
    try:
        scratch = Path(tempfile.gettempdir()).resolve()
        with tempfile.TemporaryDirectory(prefix='macscope-doctor-',dir=scratch) as directory:
            root = Path(directory)
            project = Project.create(root/'project')
            fixture = root/'probe.macho'
            payload = doctor_probe.fixture()
            atomic(fixture,payload,mode=0o400)
            options = ['--project',str(project.path),'--experimental-trusted-input',
                       '--timeout','45','--function-timeout','10','--max-functions','8']
            command = parser()
            with project.writer():
                stage = 'import'
                imported = import_inputs(command.parse_args(['import',str(fixture),*options]),project,deps)
                if imported['status'] != 'complete' or len(imported['data']) != 1:
                    raise Error('doctor_probe_evidence','Probe import did not complete',4)
                stage = 'analysis'
                image = project.select()
                analyzed = analyze_image(project,image,command.parse_args(['analyze',*options]),deps,'analyze')
                if analyzed['status'] != 'complete':
                    raise Error('doctor_probe_evidence','Probe analysis did not complete',4)
            image = project.select()
            snapshot, source = project.snapshot(image)
            query = command.parse_args(['decompile','--fresh','--address',doctor_probe.ENTRY,*options])
            stage = 'saved_disassembly'
            function = select_function(snapshot['functions'],query)
            if tuple(row['bytes'] for row in function['instructions']) != doctor_probe.INSTRUCTIONS:
                raise Error('doctor_probe_evidence','Probe instruction bytes did not match',4)
            stage = 'fresh_decompile'
            fresh = fresh_decompile(query,project,image,function,source,0,deps=deps)
            code = fresh['data']['pseudocode'] or ''
            if (fresh['status'] != 'complete' or code != function['pseudocode']
                    or not re.search(r'\breturn\s+(?:0x2a|42)\s*;',code)):
                raise Error('doctor_probe_evidence','Probe did not reproduce the expected native return',4)
            return {'status':'passed','fixture_sha256':hashlib.sha256(payload).hexdigest(),
                    'target_arch':'arm64','verified_instructions':len(doctor_probe.INSTRUCTIONS),
                    'checks':['import','analysis','saved_disassembly','fresh_decompile']}
    except Error as error:
        if error.exit_code == 130:
            raise
        raise Error('doctor_worker_failed',f'Full-headless verification failed during {stage}: {error.code}',4,
                    retryable=error.retryable,partial={'stage':stage,'cause':error.code}) from error


def execute(a):
    selection = metadata.runtime_selection(getattr(a,'runtime_address',None),getattr(a,'load_slide',None))
    if selection is None:
        return execute_command(a)
    args = argparse.Namespace(**dict(vars(a),address=selection['va']))
    return dict(execute_command(args,selection),address_selection=selection)


def function_xrefs(args, project, snapshot, function):
    data = {'function_id':function['function_id']}
    sides = ('to','from') if args.direction == 'both' else (args.direction,)
    refs = address_xrefs.FunctionReferences(snapshot['engine'])
    groups, sources, gaps = {}, {}, []
    for side in sides:
        key = 'to_entry' if side == 'to' else 'from_body'
        rows, incomplete, recovered = refs.records(function,side)
        groups[key] = list(rows)
        if incomplete:
            gaps.append('xrefs_to_entry_incomplete' if side == 'to' else 'xrefs_from_incomplete')
        if recovered:
            sources[key] = 'image_reference_index'
    if sources:
        data['reference_sources'] = sources
    if 'from' in sides and 'control_flow_gaps' in function:
        gaps.append('unresolved_control_flow')
        data.update(control_flow_gaps=function['control_flow_gaps'],control_flow_review=function['control_flow_review'])

    scope = 'selected function xrefs'
    aid = snapshot['analysis_id']
    if args.limit is not None or args.cursor is not None:
        paging = argparse.Namespace(limit=args.limit or 100,cursor=args.cursor)
        combined = [(key,row) for key,rows in groups.items() for row in rows]
        selected,cov = page(combined,paging,aid,project.project_id,
                            {'function_id':function['function_id'],'direction':args.direction},
                            order='xref-function/v1')
        data.update({key:[] for key in groups})
        for key,row in selected:
            data[key].append(row)
        cov['scope'] = scope
        if gaps:
            reasons = [*gaps,*(['page_limit'] if cov['next_cursor'] else [])]
            cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
    else:
        data.update(groups)
        count = sum(map(len,groups.values()))
        cov = coverage(scope,count,count if sources and not gaps else None,bool(gaps),reason=';'.join(gaps) or None)
    return body_ownership.query_view(envelope('xrefs',data,aid,'partial' if gaps else 'complete',cov),function)


def decompile_batch(args, project, snapshot, functions):
    aid = snapshot['analysis_id']
    rows,cov = page(functions,args,aid,project.project_id,{'decompile':'all'})
    cov['scope'] = 'captured pseudocode for engine-recognized functions'
    raw = snapshot['engine']
    facet = raw.get('coverage',{}).get('functions',{})
    count = len(functions)
    truncated = raw.get('functions_truncated') or facet.get('truncated')
    incomplete = (facet.get('status','complete') != 'complete' or facet.get('error')
                  or facet.get('emitted',count) != count)
    facet_total = facet.get('total')
    reported = raw.get('function_count_total_reported_by_engine')
    reported = facet_total if reported is None else reported
    reasons = []
    if truncated:
        reasons.append('discovery_limit')
        if raw.get('output_budget_reached'):
            reasons.append('engine_output_limit')
    elif incomplete:
        reasons.append('function_capture_incomplete')
    if raw.get('analysis_timed_out'):
        reasons.append('analysis_timeout')
    if reported is None:
        total = None if reasons else count
    elif type(reported) is int and reported >= count and facet_total in (None,reported):
        total = reported
        if total > count and not truncated and not incomplete:
            reasons.append('function_capture_incomplete')
    else:
        total = None
        reasons.append('function_count_mismatch')
    if any('control_flow_gaps' in f for f in functions):
        reasons.append('unresolved_control_flow')
    if any(pseudocode.outcome(f,engine=True) not in ('complete','not_requested')
           or (f.get('decompile_status') == 'not_requested' and not (f.get('is_external') or f.get('is_thunk')))
           for f in functions):
        reasons.append('pseudocode_incomplete')
    reasons.extend(body_ownership.reasons(snapshot.get('body_ownership',{})))
    if reasons:
        all_reasons = [*reasons,*(['page_limit'] if cov['next_cursor'] else [])]
        cov.update(status='partial',truncation_reason=';'.join(all_reasons))
    cov['known_total'] = total
    data = {'functions':rows, 'summary':dict(Counter(map(pseudocode.outcome,rows))),
            'batch_summary':{'captured_functions':count, 'engine_recognized_functions':total,
                             'uncaptured_functions':None if total is None else total-count,
                             'outcomes':dict(Counter(map(pseudocode.outcome,functions)))}}
    return envelope('decompile',data,aid,'partial' if reasons else 'complete',cov)


def execute_command(a, address_selection=None):
    limits(a)
    xref_address = None
    if a.command == 'xrefs':
        target, source = getattr(a,'xref_to',None), getattr(a,'xref_from',None)
        if target is not None or source is not None:
            if a.direction is not None:
                raise Error('xref_scope','Use --direction with a function selector',2)
            direction = 'to' if target is not None else 'from'
            xref_address = hex(metadata.hex_address(target if target is not None else source,'Unslid virtual address'))
        else:
            a.direction = a.direction or 'both'
    va_range = getattr(a,'va_range',None) if a.command == 'disasm' else None
    if va_range is not None:
        va_range = disassembly.parse_range(va_range)
    import_disassembly = a.command == 'disasm' and a.from_import
    if a.command == 'disasm' and (a.receipt or import_disassembly) and (not import_disassembly or va_range is None):
        raise Error('disasm_scope','Import disassembly and receipt replay require --from-import --range START:END',2)
    if a.command == 'disasm' and a.callback_provenance and not a.callback_evidence:
        raise Error('callback_scope','Register provenance requires --callback-evidence',2)
    if a.command == 'disasm' and a.callback_abi and not a.callback_evidence:
        raise Error('callback_scope','ABI hypothesis requires --callback-evidence',2)
    if a.command == 'disasm' and a.callback_target_receipt and not a.callback_evidence:
        raise Error('callback_scope','Target receipt requires --callback-evidence',2)
    if a.command == 'disasm' and a.callback_evidence and not import_disassembly:
        raise Error('callback_scope','Callback evidence requires --from-import --range START:END',2)
    fresh = a.command == 'decompile' and a.fresh
    from_import = a.command == 'decompile' and a.from_import
    with_hints = a.command == 'decompile' and a.with_type_hints
    recover_dispatch = a.command == 'decompile' and a.recover_dispatch_return
    recover_direct = a.command == 'decompile' and a.recover_direct_signatures
    recover_scalar = a.command == 'decompile' and a.recover_scalar_call_signatures
    recover_parameters = a.command == 'decompile' and a.recover_callee_parameters
    recover_forwarded = a.command == 'decompile' and a.recover_forwarded_return
    recover_switch = a.command == 'decompile' and a.recover_switch_table
    if with_hints and not fresh:
        raise Error('type_hints_require_fresh','Type-hinted decompilation requires --fresh',3)
    if recover_dispatch and (not fresh or with_hints):
        raise Error('dispatch_return_scope','Dispatch return recovery requires --fresh without --with-type-hints',3)
    if recover_direct and (not fresh or with_hints or recover_dispatch):
        raise Error('direct_signature_scope','Direct signature recovery requires --fresh and its own query',3)
    if recover_scalar and (not fresh or with_hints or recover_dispatch or recover_direct):
        raise Error('scalar_signature_scope','Scalar signature recovery requires --fresh and its own query',3)
    if recover_parameters and (not fresh or with_hints or recover_dispatch or recover_direct or recover_scalar):
        raise Error('callee_parameter_scope','Callee parameter recovery requires --fresh and its own query',3)
    if recover_forwarded and (not fresh or with_hints or recover_dispatch or recover_direct or recover_scalar or recover_parameters):
        raise Error('forwarded_return_scope','Forwarded return recovery requires --fresh and its own query',3)
    if recover_switch and (not fresh or with_hints or recover_dispatch or recover_direct or recover_scalar
                           or recover_parameters or recover_forwarded):
        raise Error('switch_table_scope','Switch-table recovery requires --fresh and its own query',3)
    if fresh and a.all:
        raise Error('fresh_selection','--fresh requires one function selector',2)
    if from_import and (a.address is None or address_selection is not None):
        raise Error('focused_scope','--from-import requires an exact unslid --address',2)
    term = search.pattern(a.query,regex=a.regex) if a.command == 'search' else None
    command=a.command+(' '+a.action if hasattr(a,'action') else '')
    if a.command=='version':
        return envelope(command,{'cli_version':__version__,'schema_version':SCHEMA_VERSION,'bridge_version':engine.BRIDGE_VERSION,'backend':'full Ghidra headless','required_engine':'12.2','required_jdk':'25.0.5.0.3','required_jdk_scope':'macOS arm64; use doctor --host-only for host-specific readiness','python':sys.version.split()[0],'runtime_dependencies':[],'dependency_status':'not probed; use doctor'})
    if a.command=='diff':
        if a.scope=='evidence':
            data,rows,binding = handoff_diff.compare(a.left,a.right)
            rows = redact(rows)
        else:
            data,rows,binding = binary_diff.compare(a.left,a.right,a.scope)
        records,cov = page(rows,a,binding,data['policy'],{},order='export-diff/v1')
        cov['scope'] = 'observed export differences'
        if data['gaps']:
            reasons = [*data['gaps'],*(['page_limit'] if cov['next_cursor'] else [])]
            cov.update(status='partial',truncation_reason=';'.join(reasons))
        return envelope(command,dict(data,records=records),status='partial' if data['gaps'] else 'complete',cov=cov)
    if a.command=='doctor':
        if a.host_only:
            return envelope(command,engine.host_capabilities())
        if a.static_runtime:
            return envelope(command,engine.static_dependencies(a.ghidra,a.java_home,full=a.full_digest))
        if a.verify_worker:
            trust.require(a)
        deps=engine.dependencies(a.ghidra,a.java_home,full=a.full_digest or a.verify_worker)
        probe = verify_doctor_worker(deps) if a.verify_worker else {'status':'not_requested'}
        deps['verification']={'dependency_preflight':'passed','worker_probe':probe}
        deps['capabilities']={'cached_queries':True,'fresh_selected_decompile':True,'dispatch_return_recovery':dispatch_returns.POLICY,'direct_signature_recovery':direct_signatures.POLICY,'scalar_signature_recovery':scalar_signatures.POLICY,'callee_parameter_recovery':callee_parameters.POLICY,'forwarded_return_recovery':forwarded_returns.POLICY,'switch_table_recovery':switch_tables.POLICY,'engine_operations':'explicit --trust-input (alias --experimental-trusted-input) or interactive confirmation','hard_process_memory_limit':False,'startup_deadline':True,'automatic_dependency_install':False,'analysis_profiles':[engine.analysis_profile(n) for n in engine.ANALYSIS_PROFILES]}
        return envelope(command,deps)
    if a.command=='inspect':
        data,_=inspect_path(a.input,allow_arm64e=True)
        gaps=metadata.loader_gaps(data['slices'])
        reasons=['loader_metadata_incomplete'] if gaps else []
        if data.get('debug_companion',{}).get('status') == 'unavailable':
            gaps.extend(data['warnings'])
            reasons.append('debug_companion_unavailable')
        return envelope(command,data,status='partial' if gaps else 'complete',
                        cov=coverage('Mach-O preflight',len(data['slices']),len(data['slices']),bool(gaps),
                                     reason=';'.join(reasons) or None),diagnostics=gaps)
    if a.command=='resources' and a.action=='strings':
        source,values=resource_strings.read(a.path,a.file)
        records=[{'key':key,'value':values[key]} for key in sorted(values) if a.key is None or key==a.key]
        binding=identity(source)
        rows,cov=page(records,a,binding,identity(os.path.abspath(a.path)),{'key':a.key},
                      order='resource-string-key/v1')
        cov['scope']='localization keys in selected .strings file'
        return envelope(command,dict(source,key_filter=a.key,records=rows),cov=cov)
    if a.command=='resources' and a.action=='nib':
        source,records,gaps=resource_nib.read(a.path,a.file,a.kind)
        rows,cov=page(records,a,identity(source),identity(os.path.abspath(a.path)),{'kind':a.kind},
                      order='nib-connections-then-button-labels/v1')
        cov['scope']='archived AppKit '+{'all':'connections and button labels','connections':'connections',
                                        'labels':'button labels'}[a.kind]
        if gaps:
            reasons=[*gaps,*(['page_limit'] if cov['next_cursor'] else [])]
            cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
        return envelope(command,dict(source,kind=a.kind,records=rows),status='partial' if gaps else 'complete',
                        cov=cov,diagnostics=gaps)
    if a.command in ('bundle','resources'):
        resource_list = a.command == 'resources'
        kind = 'resources' if resource_list else a.kind
        resource_type = a.resource_type if resource_list else None
        resource_directory = a.resource_directory if resource_list else None
        inventory,gaps=bundle.inventory(a.path,kind,resource_type=resource_type,resource_directory=resource_directory)
        inventory_id=identity({'inventory':inventory,'gaps':gaps})
        filters = {'kind':kind}
        if resource_list:
            filters.update(command=command,resource_type=resource_type)
        if resource_directory is not None:
            filters['resource_directory'] = resource_directory
        rows,cov=page(inventory['records'],a,inventory_id,identity(os.path.abspath(a.path)),
                      filters,order='bundle-relative-path/v1')
        cov['scope']='physical entries in selected bundle: '+kind
        if resource_directory is not None:
            cov['scope']='physical resources under '+resource_directory
        if resource_type is not None:
            cov['scope'] += ' of type '+resource_type
        if gaps:
            reasons=[*gaps,*(['page_limit'] if cov['next_cursor'] else [])]
            cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
        if resource_list:
            data = [dict(row,bundle_name=inventory['bundle_name'],inventory_id=inventory_id) for row in rows]
            return envelope(command,data,status='partial' if gaps else 'complete',cov=cov,diagnostics=gaps)
        data=dict(inventory,inventory_id=inventory_id,records=rows)
        return envelope(command,data,status='partial' if gaps else 'complete',cov=cov)
    if a.command=='demangle':
        trust.require(a)
        records,provenance=swift_symbols.demangle([a.name])
        result=records[0]
        partial=result['demangle_status']!='demangled'
        return envelope(command,dict(result,demangler=provenance),status='partial' if partial else 'complete',
                        cov=coverage('Swift name',partial=partial,reason='unrecognized_mangling' if partial else None))
    if a.command=='project':
        p=Project.create(a.path)
        return envelope(command,{'project_id':p.project_id,'schema_version':'1.0'})
    if a.command=='fixups' and a.input is not None:
        return file_fixups(a)
    p=Project(a.project)
    if a.command == 'evidence':
        report = redact(evidence.export(p,evidence.load(a.leads),link_imports=a.link_imports,link_focused=a.link_focused))
        count = len(report['leads'])
        partial = any(row['status'] != 'resolved' for row in report['leads'])
        return envelope(command,report,status='partial' if partial else 'complete',
                        cov=coverage('reviewer-selected evidence leads',count,count,partial,
                                     reason='lead_evidence_incomplete' if partial else None))
    if a.command == 'jobs':
        return job_command(a,p,command)
    if a.command == 'boundary':
        return boundary_command(a,p,command)
    if a.command == 'rename' or (a.command in ('comment','type') and a.action != 'list'):
        return revise_annotation(a,p,command,address_selection)
    if a.command == 'annotations' and a.action == 'import':
        return import_annotations(a,p)
    if fresh or from_import or (import_disassembly and not a.receipt) or a.command in ('import','analyze'):
        check_engine_access(a,p)
    if a.command=='status':
        return project_status(a,p)
    if a.command in ('import','analyze'):
        with p.writer():
            jobs.verify_engine_writer_stopped(p)
            deps=engine.dependencies(a.ghidra,a.java_home,full=True)
            if a.command=='import':
                return import_inputs(a,p,deps)
            return analyze_image(p,p.select(a.image,a.arch),a,deps,command)
    image=p.select(a.image,a.arch)
    if address_selection is not None:
        address_selection.update(image_id=image['image_id'],arch=image['arch'])
    if import_disassembly:
        return imported_disassembly(a,p,image,*va_range)
    if from_import:
        return focused_decompile(a,p,image)
    if a.command=='headers':
        data=metadata.headers(p,image)
        gaps=metadata.loader_gaps([data])
        return envelope(command,data,status='partial' if gaps else 'complete',
                        cov=coverage('selected image headers',partial=bool(gaps),
                                     reason='loader_metadata_incomplete' if gaps else None),diagnostics=gaps)
    if a.command=='unwind':
        return file_unwind(a,p,image)
    if a.command=='swift':
        return swift_collection(a,p,image)
    if a.command=='bytes':
        return envelope(command,metadata.read_bytes_at(p,image,a.address,a.byte_length,rva=a.rva,file_offset=a.file_offset),
                        cov=coverage('selected image bytes',a.byte_length,a.byte_length))
    if a.command=='fixups':
        return fixup_collection(a,image,metadata.verified_slice(p,image),p.project_id)
    if a.command=='objc':
        raw = metadata.verified_slice(p,image)
        diagnostics = []
        filters = {'action':a.action,'name_contains':a.name_contains}
        if getattr(a,'decode_types',False):
            filters['type_decoding_policy'] = objc_types.POLICY
        if getattr(a,'class_slot',None) is not None:
            slot = metadata.hex_address(a.class_slot,'Objective-C class list slot')
            records,gaps = (objc.selected_ivars(raw,image,slot,diagnostics=diagnostics) if a.action == 'ivars'
                            else objc.selected_methods(raw,image,slot))
            filters['class_slot'] = hex(slot)
        else:
            records,gaps = objc.inventory(raw,image,a.action,diagnostics=diagnostics)
        unfiltered_count = len(records)
        records=[dict(row,image_id=image['image_id'],arch=image['arch'])
                 for row in records if a.name_contains is None or a.name_contains in (row['name'] or '')]
        if a.action == 'ivars' and a.name_contains is not None:
            diagnostics.append(f'Ivar name filter excluded {unfiltered_count-len(records)} captured rows; not missing metadata.')
        records.sort(key=lambda row:(row['name'] or '',row.get('class_name') or '',
                                    int(row.get('record_va',row.get('class_va')),16)))
        rows,cov=page(records,a,image['image_id'],p.project_id,filters,order='objc-name/address/v1')
        if getattr(a,'decode_types',False):
            rows = [objc_types.decode_row(row,a.action) for row in rows]
            incomplete = sum(row['decoded_types']['status'] != 'decoded' for row in rows)
            diagnostics.append('Decoded types describe recorded metadata, not verified implementation ABI or recovered source. '
                               'Method argN labels are generated; encoded offsets are not inferred register or object layouts. '
                               'Block signatures and opaque aggregate layouts remain unavailable. '
                               'Pseudocode and saved evidence are unchanged.')
            if incomplete:
                diagnostics.append(f'Type decoding incomplete for {incomplete} of {len(rows)} rows on this page; '
                                   'see decoded_types.status and diagnostics. Inventory coverage is reported separately.')
        cov['scope'] = ('selected Objective-C class declaration '+a.action if 'class_slot' in filters
                        else 'selected image Objective-C '+a.action)
        if gaps:
            reasons=[*gaps,*(['page_limit'] if cov['next_cursor'] else [])]
            cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
        if a.action == 'classes':
            diagnostics.append('Scope: declarations in the selected image class lists only; excludes categories, '
                               'inherited methods, other images and runtime-generated classes.')
            if gaps:
                diagnostics.append('Class discovery is incomplete. An empty filtered result does not prove absence. '
                                   'Pagination only pages captured rows; it cannot bypass exhausted discovery.')
                if rows:
                    slot = rows[0]['list_entry_va']
                    diagnostics.append(f"For verified class-list slot {slot}, use objc methods --class-slot {slot} "
                                       f"--image {image['image_id']} --arch {image['arch']} with the same --project. "
                                       'This covers selected class/metaclass declarations, not categories or inherited methods.')
                else:
                    diagnostics.append(f"Manual fallback: pin the same binary SHA-256 {image['sha256']} and "
                                       f"architecture {image['arch']}; inspect otool -arch {image['arch']} -ov BINARY "
                                       f"or xcrun dyld_info -arch {image['arch']} -objc BINARY. Verify an aligned "
                                       '__objc_classlist/__objc_nlclslist slot and method entry in that same slice, '
                                       'then use objc methods --class-slot SLOT with the same --project, --image and --arch. '
                                       'A class-object address is not a class-list slot. No Apple tool was run.')
            elif not records:
                diagnostics.append('No matching class declarations in the completely visited selected class-list scope.')
        elif gaps:
            diagnostics.extend(gaps)
        if a.action == 'ivars':
            diagnostics.append('Declared instance ivars only; inherited and runtime-resolved layouts are excluded. '
                               'Offsets are initial file values, not offset-storage addresses or inferred loads. '
                               'See offset_evidence for exact bytes or missing proof.')
        return envelope(command,rows,status='partial' if gaps else 'complete',cov=cov,diagnostics=diagnostics)
    if a.command in metadata.PREFLIGHT_LISTS:
        return metadata_collection(a,p,image)
    if a.command == 'exports' and a.source == 'dyld':
        return dyld_exports(a,p,image)
    if a.command == 'symbols' and a.source != 'ghidra':
        return file_symbols(a,p,image)
    snapshot,record=p.snapshot(image)
    if a.command in metadata.ENGINE_LISTS:
        return metadata_collection(a,p,image,snapshot)
    aid=snapshot['analysis_id']
    if xref_address is not None:
        refs,gaps = address_xrefs.match(snapshot,xref_address,direction)
        paging = argparse.Namespace(limit=a.limit or 100,cursor=a.cursor)
        rows,cov = page(refs,paging,aid,p.project_id,{'address':xref_address,'direction':direction},
                        order='xref-address/v1')
        cov['scope'] = 'recorded references at selected address'
        if gaps:
            reasons = [*gaps,*(['page_limit'] if cov['next_cursor'] else [])]
            cov.update(status='partial',known_total=None,truncation_reason=';'.join(reasons))
        data = {'image_id':image['image_id'],'arch':image['arch'],'address_space':'ram',
                'address':xref_address,'direction':direction,'references':rows,'gaps':gaps}
        return envelope(command,data,aid,'partial' if gaps else 'complete',cov)
    if va_range is not None:
        data = disassembly.query(snapshot,image,*va_range)
        reasons = ['range_instruction_evidence_incomplete'] if data['gaps'] else []
        reasons.extend(body_ownership.reasons(data.get('body_ownership',{})))
        partial = bool(reasons)
        count = len(data['instructions'])
        return envelope(command,data,aid,'partial' if partial else 'complete',
                        coverage('saved instructions within selected VA range',count,None if data['gaps'] else count,
                                 partial,reason=';'.join(reasons) or None))
    if a.command == 'annotations' and a.action == 'export':
        transfer = annotation_transfer.export(p,image)
        total = len(transfer['revisions'])
        return envelope(command,transfer,aid,cov=coverage('portable image annotation history',total,total))
    a = resolve_selector(a,p,image,snapshot)
    raw_snapshot = snapshot
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
        kinds = {'comment':('comment',),'type':annotations.TYPE_HINT_KINDS}.get(a.command)
        rows = [row for row in annotations_rows
                if (entry is None or row['engine_entry'] == entry)
                and (kinds is None or row['kind'] in kinds)]
        rows,cov = page(rows,a,aid,p.project_id,{'annotation_revision':revision,'entry':entry,'command':command},
                        order='annotation-revision/v1')
        cov['scope'] = {'annotations':'image annotation revisions','comment':'current image comments',
                        'type':'accepted image type hints'}[a.command]
        return envelope(command,rows,aid,cov=cov)
    if a.command == 'search':
        view = dict(snapshot,functions=functions)
        hits, gaps = search.snapshot_matches(view,term,a.search_scope,comments=annotations_rows,regex=a.regex)
        filters={'query':a.query,'scope':a.search_scope}
        if a.regex:filters['match']='regex'
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
        reasons = analysis_coverage_reasons(snapshot)
        reason = ';'.join(reasons) or None
        return envelope(command,snapshot,aid,snapshot['status'],coverage('committed normalized image export',len(functions),snapshot['engine'].get('function_count_total_reported_by_engine'),snapshot['status']!='complete',reason=reason),['Private recovered code/strings may be sensitive. Absolute host paths and volatile job timings are omitted.'])
    if a.command=='functions' and a.action=='list':
        rows=[f for f in functions if not a.name_contains or any(a.name_contains in n['name'] for n in f['names'])]
        filters={'name_contains':a.name_contains}
        if revision:filters['annotation_revision']=revision
        rows,cov=page(rows,a,aid,p.project_id,filters)
        gaps=[]
        if snapshot['engine'].get('functions_truncated'):
            gaps.append('discovery_limit')
        if a.name_contains and search.entry_labels_incomplete(functions):
            gaps.append('function_entry_label_coverage_incomplete')
        if any('body_overlap' in f for f in rows):
            gaps.append('function_body_overlap')
        if snapshot.get('body_ownership',{}).get('scan_truncated'):
            gaps.append('function_body_review_limit')
        if gaps:
            if cov['next_cursor']:
                gaps.append('page_limit')
            cov.update(status='partial',known_total=None,truncation_reason=';'.join(gaps))
        fields = ('function_id','image_id','arch','entry_va','address_space','engine_entry','body_ranges',
                  'names','signature','is_thunk','thunk_target','is_external','decompile_status','control_flow_review',
                  'control_flow_gaps','control_flow_traps','engine_decompile_status','body_overlap')
        return envelope(command,[{key: f[key] for key in fields if key in f} for f in rows],aid,cov=cov)
    if a.command=='decompile' and a.all:
        return decompile_batch(a,p,snapshot,functions)
    f=select_function(functions,a)
    if not fresh and a.command in ('functions','decompile','disasm','cfg'):
        f=saved_flow_gap_evidence.annotate_selected(p,image,raw_snapshot,record,f)
    if a.command=='xrefs':
        return function_xrefs(a,p,snapshot,f)
    if fresh:
        hints=annotations.type_hints(annotations_rows,functions) if with_hints else None
        policy = next((policy for enabled, policy in ((recover_switch, switch_tables), (recover_forwarded, forwarded_returns), (recover_parameters, callee_parameters),
                      (recover_scalar, scalar_signatures), (recover_direct, direct_signatures), (recover_dispatch, dispatch_returns)) if enabled), None)
        plan = policy.request(metadata.verified_slice(p,image),image,f,functions) if policy else None
        return fresh_decompile(a,p,image,f,record,revision,hints,signature_plan=plan,
                               address_selection=address_selection)
    if a.command=='calls':
        data,gaps=calls.graph(dict(snapshot,functions=functions),f,a.direction,a.depth,a.max_edges)
        count=len(data['edges'])
        return body_ownership.query_view(envelope(command,data,aid,'partial' if gaps else 'complete',
                        coverage('recorded call edges within requested depth',count,None if gaps else count,
                                 bool(gaps),reason=';'.join(gaps) or None)),f)
    if a.command=='functions':
        notes=[row for row in annotations_rows if row['engine_entry']==f['engine_entry']]
        if notes:f=dict(f,annotations=notes)
        unresolved = 'control_flow_gaps' in f
        incomplete = unresolved or any(c.get('truncated') or c.get('error') for c in f.get('coverage',{}).values())
        reason = 'unresolved_control_flow' if unresolved else 'facet_incomplete' if incomplete else None
        return body_ownership.query_view(envelope(command,f,aid,'partial' if incomplete else 'complete',
                        coverage('selected function evidence',1,1,incomplete,reason=reason)),f)
    if a.command=='disasm':
        data={'function_id':f['function_id'],'instructions':f['instructions']}
        partial=bool(f.get('instructions_truncated') or f.get('instructions_error'))
        count=len(f['instructions'])
    elif a.command=='decompile':
        data=f
        partial=f['decompile_status'] not in ('complete','not_requested') or f.get('pseudocode_truncated',False)
        count=1
    else:
        data={'function_id':f['function_id'],'blocks':f['blocks']}
        partial=bool(f.get('blocks_truncated') or f.get('cfg_error') or f.get('edges_truncated'))
        count=len(f['blocks'])
    unresolved = 'control_flow_gaps' in f
    if unresolved and a.command != 'decompile':
        data.update(control_flow_gaps=f['control_flow_gaps'], control_flow_review=f['control_flow_review'])
    partial = partial or unresolved
    reason = 'unresolved_control_flow' if unresolved else 'facet_incomplete' if partial else None
    return body_ownership.query_view(envelope(command,data,aid,'partial' if partial else 'complete',
                        coverage('selected function '+a.command,count,None,partial,reason=reason)),f)


def render_jsonl(result):
    data = result['data']
    if isinstance(data,list) and data:
        row_coverage = dict(result['coverage'],returned_count=1)
        for row in data:
            yield canonical(dict(result,data=row,coverage=row_coverage))+b'\n'
    else:
        yield from canonical_chunks(result)
        yield b'\n'


def render(result,fmt):
    if fmt=='text':
        return terminal.render(result)
    if fmt=='html':
        if result['command']=='evidence':
            return html_export.render_handoff(result)
        return html_export.render(result)
    if fmt=='dot':
        rows=['digraph cfg {','  // status: '+result['status']+'; bounded static evidence, not exhaustive runtime flow']
        if result['status'] == 'partial':
            rows.append('  // Partial result (exit 6): retained evidence is incomplete, not an engine crash.')
        if selection := result.get('address_selection'):
            rows.append(f"  // runtime VA {selection['runtime_va']} with slide {selection['load_slide']} selects {selection['va']}")
        for b in result['data']['blocks']:
            rows.append('  '+json.dumps(b['min'])+' [label='+json.dumps(b['min']+'..'+b['max'])+'];')
            for edge in b['dsts']:rows.append('  '+json.dumps(b['min'])+' -> '+json.dumps(edge['to'])+' [label='+json.dumps(edge['flow'])+'];')
        rows.append('}')
        return ('\n'.join(rows)+'\n').encode()
    if fmt=='jsonl':return b''.join(render_jsonl(result))
    if fmt=='json':return canonical(result)+b'\n'
    # ASCII JSON escaping prevents terminal-control injection in binary strings.
    return (json.dumps(result,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()


def main(argv=None):
    os.umask(0o077)
    args=None
    try:
        args=parser().parse_args(argv)
        result=execute(args)
        if result['status'] == 'partial':
            reason = result['coverage'].get('truncation_reason') or 'see coverage and data'
            result['diagnostics'].append(
                'Partial result (exit 6): useful artifacts are retained; this is not an engine crash. '
                'Missing coverage: ' + reason)
            if reason == 'lead_evidence_incomplete':
                result['diagnostics'].append(
                    'Worker completion and verified individual links do not establish complete graph coverage. '
                    'See each lead status, reason and gaps for missing evidence.')
        validate_envelope(result)
        code=6 if result['status']=='partial' else 0
        fmt='json' if result.get('error') else getattr(args,'format','json')
        chunks=render_jsonl(result) if fmt=='jsonl' else (render(result,fmt),)
        if getattr(args,'output',None):
            destination=Path(os.path.abspath(args.output))
            protect_output(args,destination)
            atomic_chunks(destination,chunks,args.force)
        else:
            sys.stdout.buffer.writelines(chunks)
        return code
    except Error as e:
        command=getattr(args,'command','unknown') if args else 'unknown'
        status = 'cancelled' if e.exit_code == 130 else 'failed'
        result=envelope(command,None,status=status,cov=coverage('requested command',0,None,True,reason=e.code),diagnostics=[str(e)])
        result['error']={'code':e.code,'message':str(e),'affected_object':getattr(args,'image',None) if args else None,'retryable':e.retryable,'partial_results':e.partial}
        code=e.exit_code
    except KeyboardInterrupt:
        result=envelope('unknown',None,status='cancelled',diagnostics=['Interrupted'])
        code=130
    except (OSError,ValueError,KeyError,TypeError) as e:
        result=envelope(getattr(args,'command','unknown'),None,status='failed',cov=coverage('requested command',0,None,True,reason='internal_failure'),diagnostics=[str(e)])
        result['error']={'code':'internal_failure','message':str(e),'affected_object':None,'retryable':False,'partial_results':None}
        code=10
    validate_envelope(result)
    sys.stdout.buffer.write(render(result,'json'))
    if code not in (0,6):sys.stderr.write(terminal.safe(result.get('error',{}).get('message','Command failed'))+'\n')
    return code
