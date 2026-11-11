"""Explicit saved receipt navigation, not graph discovery or runtime inference."""
import shlex
from . import evidence, focused, focused_references, metadata, terminal
from .errors import Error
from .storage import identity

POLICY='macscope-selected-reference-links/1'
MAX_RECEIPTS=20
MAX_REFERENCES=100


def command_hint(project_path,image,job,entry):
    path=str(project_path)
    if not path.isprintable() or len(path)>1024:
        return None
    command=shlex.join(['macscope','xrefs','--project',path,'--image',image,'--query-job',job,
                        '--address',entry,'--direction','from','--format','text'])
    return command if len(command.encode())<=4096 else None


def classify(receipts):
    """Join only unique same-image entries supported by byte-decoded direct calls."""
    entries={}
    for row in receipts:
        if row['status']=='verified':entries.setdefault((row['image_id'],row['entry_va']),[]).append(row)
    for row in receipts:
        for ref in row.get('references',[]):
            target=ref['recorded']['to'];matches=entries.get((row['image_id'],target),[])
            ref['status']='unresolved_target' if target is None else 'target_not_selected'
            ref['destination_receipts']=[]
            if len(matches)>1:ref['status']='ambiguous_selected_entry'
            elif matches:
                ref['status']='verified_selected_direct_link' if ref['direct_bytes_verified'] and ref['recorded']['type'] in ('UNCONDITIONAL_CALL','UNCONDITIONAL_JUMP') else 'recorded_target_match_not_direct_proof'
                ref['destination_receipts']=[{'job_id':matches[0]['requested_job_id'],'source_envelope_sha256':matches[0]['source_envelope_sha256'],
                                            'image_id':matches[0]['image_id'],'entry_va':matches[0]['entry_va']}]


def build(project,report):
    pins={p['image_id']:p for p in report['images']};images={i['image_id']:i for i in project.images()}
    rows=[];seen=set();omitted_receipts=omitted_references=0
    for leadrow in report['leads']:
        lead=leadrow['lead'];entry=(leadrow.get('function') or {}).get('entry_va')
        key=(lead['image_id'],lead.get('query_job'),entry)
        if entry and lead.get('query_job'):
            if key in seen:continue
            seen.add(key)
        if len(rows)>=MAX_RECEIPTS:omitted_receipts+=1;continue
        row={'lead_id':lead['id'],'image_id':lead['image_id'],'requested_job_id':lead.get('query_job'),
             'entry_va':entry,'status':'unavailable','references':[],'command':None}
        rows.append(row)
        if not entry or not lead.get('query_job') or evidence.IMPORT_PIN not in pins[lead['image_id']]:
            row['reason']=leadrow.get('reason') or 'verified_import_focused_receipt_required';continue
        try:
            image=images.get(lead['image_id']);evidence.open_image(project,image,pins[lead['image_id']])
            result=evidence.focused_query(project,image,metadata.verified_slice(project,image),entry,lead['query_job'])
        except Error as exc:
            row['reason']=exc.code;continue
        function=result['data'];view,groups=focused_references.project(result,'from')
        direct={(ins['addr'],target):ins for ins,target in focused.direct_calls(image['arch'],function) if target is not None}
        def proven(ref):
            ins=direct.get((ref['from'],ref['to']))
            return bool(ins and (ref['type']=='UNCONDITIONAL_CALL' or
                        (ref['type']=='UNCONDITIONAL_JUMP' and ins.get('flow')=='CALL_TERMINATOR')))
        row.update(status='verified',source_envelope_sha256=identity(result),publication_job_id=function['origin']['job_id'],
                   query_status=result['status'],outgoing_facets=view['recorded_facets'],gaps=view['gaps'],
                   incoming_scope='partial_not_global',extent=function['origin']['extent'])
        row['command']=command_hint(project.path,image['image_id'],lead['query_job'],entry)
        if row['command'] is None:row['command_reason']='project_path_not_safely_renderable'
        available=MAX_REFERENCES-sum(len(r['references']) for r in rows)
        row['references']=[{'recorded':ref,'direct_bytes_verified':proven(ref),
                            'direct_instruction_bytes':direct[(ref['from'],ref['to'])]['bytes'] if proven(ref) else None}
                           for _,ref in groups[:available]]
        row['omitted_references']=len(groups)-len(row['references'])+view['omitted_records']
        omitted_references+=row['omitted_references']
    classify(rows)
    return {'policy':POLICY,'status':'partial','scope':'explicit_selected_receipts_only','runtime_execution':'unknown',
            'receipts':rows,'omitted_receipts':omitted_receipts,'omitted_references':omitted_references}


def render(result):
    view=result['data']['selected_reference_links'];rows=view['receipts']
    lines=['Selected saved reference links [partial]',
           'Independent static observations only; incoming/global coverage and runtime execution remain unknown.']
    used=sum(len((s+'\n').encode()) for s in lines);shown=refs_shown=hints_shown=0;stopped=False
    def field(value):
        text=str(value);return terminal.safe(text[:160])+(' [clipped]' if len(text)>160 else '')
    def emit(line):
        nonlocal used,stopped
        size=len((line+'\n').encode())
        if stopped or len(lines)>=194 or used+size>31744:stopped=True;return False
        lines.append(line);used+=size;return True
    for row in rows:
        if not emit('Receipt '+field(row['requested_job_id'])+' image '+field(row['image_id'])+' entry '+field(row['entry_va'])+' ['+field(row['status'])+']'):break
        shown+=1
        if row['status']!='verified':emit('  Missing evidence: '+field(row.get('reason')));continue
        emit('  Source digest: '+field(row['source_envelope_sha256'])+'; query='+field(row['query_status'])+'; incoming=partial/not-global')
        emit('  Outgoing gaps: '+field(', '.join(row['gaps']) or 'none within recorded selected scope'))
        if row['command']:
            if emit('  Suggested command (not executed): '+row['command']):hints_shown+=1
        else:emit('  Command withheld: '+field(row.get('command_reason')))
        for ref in row['references']:
            raw=ref['recorded'];dest=ref['destination_receipts']
            line='  '+field(raw['from'])+' -> '+field(raw['to'])+' '+field(raw['type'])+' ['+field(ref['status'])+']'
            if dest:line+=' selected job '+field(dest[0]['job_id'])
            if not emit(line):break
            refs_shown+=1
    totalrefs=sum(len(r['references']) for r in rows);totalhints=sum(bool(r.get('command')) for r in rows)
    lines.extend([f'Receipts displayed: {shown}; omitted: {len(rows)-shown+view["omitted_receipts"]}.',
                  f'References displayed: {refs_shown}; omitted: {totalrefs-refs_shown+view["omitted_references"]}.',
                  f'Runnable hints displayed: {hints_shown}; omitted by presentation: {totalhints-hints_shown}.',
                  'No traversal or runtime target inference. Full bounded view: --reference-links --format json.',
                  'Full saved reference rows: use the explicit xrefs hints; incoming remains partial.'])
    return ('\n'.join(lines)+'\n').encode()
