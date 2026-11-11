"""Selected-byte disassembly, independent of function discovery/decompilation."""
import hashlib
import json
import os
import re
import uuid
from pathlib import Path

from . import engine, engine_checks, focused, jobs, metadata
from .disassembly import MAX_RANGE_BYTES
from .errors import Error
from .macho import thin
from .macho_view import MappedImage
from .storage import write_json
from .schema import validate_envelope
from .engine import digest, tree_digest

POLICY = 'macscope-import-disasm/1'
MAX_OUTPUT = 4 * 1024 * 1024


def selection(raw, image, start, end):
    if image['arch'] not in ('arm64', 'x86_64') or not 0 < end-start <= MAX_RANGE_BYTES:
        raise Error('disasm_scope', 'Select 1..4096 bytes of arm64 or x86_64 instructions', 2)
    if image['arch'] == 'arm64' and (start % 4 or end % 4):
        raise Error('disasm_alignment', 'arm64 range bounds must be four-byte aligned', 2)
    parsed = thin(raw, include_section_linkage=True)
    try:
        offset, _, protection = MappedImage(raw, parsed['segments'], reject_virtual_overlap=True).mapping(start, end-start)
    except ValueError as exc:
        raise Error('disasm_mapping', 'Range needs one unambiguous file-backed mapping', 3) from exc
    sections = [r for r in parsed['sections']
                if int(r['va'],16) < end and start < int(r['va'],16)+int(r['size'],16)]
    if (len(sections) != 1 or sections[0]['file_offset'] is None
            or not int(sections[0]['va'],16) <= start < end <= int(sections[0]['va'],16)+int(sections[0]['size'],16)
            or not protection & 4 or not int(sections[0]['flags'],16) & 0x80000400
            or offset != int(sections[0]['file_offset'],16)+start-int(sections[0]['va'],16)):
        raise Error('disasm_mapping', 'Range needs one executable instruction section with consistent mapping', 3)
    loader = parsed['loader']
    table = loader.get('data_in_code')
    if table and (table['status'] != 'complete' or any(focused.overlaps(offset,end-start,r,r['length']) for r in table['records'])):
        raise Error('disasm_data_in_code', 'Range has embedded data or incomplete data-in-code evidence', 3)
    crypt = loader.get('encryption')
    if crypt and crypt['cryptid'] and focused.overlaps(offset,end-start,crypt,int(crypt['size'],16)):
        raise Error('disasm_encryption', 'Range overlaps encrypted bytes', 3)
    payload = raw[offset:offset+end-start]
    if len(payload) != end-start:
        raise Error('disasm_mapping', 'Truncated selected range', 3)
    return {'policy':POLICY,'image_id':image['image_id'],'arch':image['arch'],'slice_sha256':image['sha256'],
            'start_va':hex(start),'end_va':hex(end),'slice_file_offset':hex(offset),
            'container_file_offset':hex(offset+int(image['offset'],16)),
            'range_sha256':hashlib.sha256(payload).hexdigest(),'requested_bytes':len(payload)}, payload


def validate_rows(result, proof, payload):
    """Validate all byte evidence before publication or replay; no inferred gaps."""
    try:
        rows, gaps = result['instructions'], result['gaps']
        if not isinstance(rows,list) or len(rows)>MAX_RANGE_BYTES or not isinstance(gaps,list) or len(gaps)>1:
            raise ValueError()
        cursor = int(proof['start_va'],16)
        end = int(proof['end_va'],16)
        for row in rows:
            if not isinstance(row,dict) or set(row) != {'addr','bytes','mnemonic','text'}:
                raise ValueError()
            if row['addr'] != hex(cursor) or not isinstance(row['bytes'],str) or not re.fullmatch(r'(?:[0-9a-f]{2}){1,15}',row['bytes']):
                raise ValueError()
            data = bytes.fromhex(row['bytes'])
            if proof['arch']=='arm64' and len(data)!=4:
                raise ValueError()
            position = cursor-int(proof['start_va'],16)
            if cursor+len(data)>end or payload[position:position+len(data)]!=data:
                raise ValueError()
            if any(not isinstance(row[k],str) or not 0<len(row[k])<=4096 for k in ('mnemonic','text')):
                raise ValueError()
            cursor += len(data)
        if gaps:
            gap, = gaps
            if (set(gap) != {'start_va','end_va','reason'} or gap['start_va']!=hex(cursor)
                    or gap['end_va']!=hex(end) or cursor>=end or gap['reason'] not in
                    ('undecodable_or_unavailable','instruction_crosses_range_boundary')):
                raise ValueError()
        elif cursor!=end:
            raise ValueError()
        return cursor-int(proof['start_va'],16)
    except (KeyError,TypeError,ValueError) as exc:
        raise Error('disasm_result', 'Disassembly byte evidence or coverage is invalid', 10) from exc


def binding(project, image, proof):
    return dict(proof, project_id=project.project_id, program_sha256=image.get('engine_baseline_sha256'))


def replay(project, image, proof, payload, job_id):
    directory, manifest = jobs.get(project,job_id)
    expected = binding(project,image,proof)
    if manifest.get('disasm_request') != expected or manifest.get('status') != 'complete':
        raise Error('disasm_receipt_identity','Receipt belongs to a different range, image, project or import',8)
    path = directory.parent/'disasm-result.json'
    result = engine.read_worker_object(path,MAX_OUTPUT)
    if digest(path) != manifest.get('disasm_result_sha256'):
        raise Error('disasm_receipt_identity','Receipt contents differ from committed digest',8)
    try:
        validate_envelope(result)
    except ValueError as exc:
        raise Error('disasm_receipt_identity','Receipt envelope is invalid',8) from exc
    data = result.get('data',{})
    if (result.get('command')!='disasm' or not isinstance(data,dict)
            or data.get('selection')!=expected or not isinstance(data.get('origin'),dict)
            or data['origin'].get('job_id')!=job_id):
        raise Error('disasm_receipt_identity','Receipt selection differs',8)
    covered = validate_rows(data,proof,payload)
    if data.get('covered_bytes')!=covered or result.get('status') != ('partial' if data['gaps'] else 'complete'):
        raise Error('disasm_receipt_identity','Receipt coverage differs',8)
    return result


def run(project, image, args, deps, proof, payload):
    # Reuse native host/trust/resource checks at both CLI and worker boundaries.
    engine.require_worker_host()
    if not args.experimental_trusted_input:
        raise Error('isolation_required','Native disassembly requires explicit input trust',3)
    if args.jobs!=1 or args.max_memory_mib is not None:
        raise Error('unsupported_budget','Use one worker and heap budget; hard memory cap unsupported',3)
    if any(c in str(project.path) for c in ('"','\\','\n','\r')):
        raise Error('worker_path_unsupported','Unsupported workspace path',3)
    imported = image.get('import_dependencies',{})
    if (not image.get('imported') or not deps.get('ghidra_tree_sha256')
            or imported.get('ghidra_tree_sha256')!=deps['ghidra_tree_sha256']
            or not engine.matches_auxiliary_jdk(imported,deps)):
        raise Error('focused_import_engine','Disassembly requires an import from the selected runtime',4)
    source = engine.import_program_path(project,image)
    source_digest = image.get('engine_baseline_sha256')
    if (not source_digest or source.is_symlink() or source.parent.is_symlink() or not source.is_dir()
            or tree_digest(source)!=source_digest):
        raise Error('baseline_integrity','Saved import differs from its digest',4)
    content_digest = tree_digest(source,ignore=focused.PROJECT_BACKUPS)
    job_id = uuid.uuid4().hex
    job = project.path/'jobs'/job_id
    job.mkdir(mode=0o700)
    for child in ('tmp','home'):
        (job/child).mkdir(mode=0o700)
    program = job/'program'
    sandbox = job/'sandbox.sb'
    sandbox.write_text(engine.profile(project,deps,write_root=job,read_only_program=True),encoding='utf-8')
    request = binding(project,image,proof)
    manifest = {'job_id':job_id,'mode':'query','image_id':image['image_id'],'dependencies':deps,
                'limits':engine.worker_limits(args,1),'disasm_request':request,'sandbox_sha256':digest(sandbox)}
    try:
        engine.copy_program(source,program,source_digest,'baseline_integrity')
        engine.verify_auxiliary_jdk(deps)
        g,j = Path(deps['ghidra_path']),Path(deps['java_home'])
        env = {'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(job/'home'),'USER':os.environ.get('USER','macscope'),
               'TMPDIR':str(job/'tmp')+'/', 'JAVA_HOME':str(j),'GHIDRA_HEADLESS_MAXMEM':str(args.heap_mib)+'M',
               'JAVA_TOOL_OPTIONS':'-Duser.home='+json.dumps(str(job/'home'))+' -Djava.io.tmpdir='+json.dumps(str(job/'tmp')),
               'LANG':'en_US.UTF-8'}
        manifest['environment'] = env
        output = job/'disasm-worker.json'
        argv = ['/usr/bin/sandbox-exec','-f',str(sandbox),str(g/'support/analyzeHeadless'),str(program),'image',
                '-process',image['image_id']+'.macho','-readOnly','-noanalysis','-scriptPath',str(engine.BRIDGE.resolve()),
                '-postScript','MacscopeDisasm.java',str(output),image['sha256'],proof['arch'],proof['start_va'],
                proof['end_va'],proof['range_sha256'],'-max-cpu','1','-analysisTimeoutPerFile',str(args.timeout),
                '-log',str(job/'engine.log'),'-scriptlog',str(job/'script.log')]
        engine.run_process(argv,cwd=job,env=env,timeout=args.timeout,startup_timeout=args.startup_timeout,
                           log_path=job/'launcher.log',manifest_path=job/'job.json',manifest=manifest)
        result = engine.read_worker_object(output,MAX_OUTPUT)
        if (result.get('schema')!=POLICY or result.get('ghidra_version')!=engine_checks.GHIDRA_VERSION
                or result.get('slice_sha256')!=image['sha256'] or result.get('range_sha256')!=proof['range_sha256']
                or result.get('start_va')!=proof['start_va'] or result.get('end_va')!=proof['end_va']
                or result.get('arch')!=proof['arch'] or result.get('autoanalysis') is not False):
            raise Error('disasm_worker_identity','Worker selection/runtime identity differs',10)
        engine_checks.verify_runtime(result.get('java_runtime'),deps['java_home'])
        engine.verify_auxiliary_jdk(deps)
        validate_rows(result,proof,payload)
        if tree_digest(source)!=source_digest or tree_digest(program,ignore=focused.PROJECT_BACKUPS)!=content_digest:
            raise Error('baseline_integrity','Disassembly changed a Program database',10)
        manifest['java_runtime'] = result['java_runtime']
        write_json(job/'job.json',manifest,force=True)
        return result,manifest
    except (Error,OSError,ValueError) as exc:
        # Preserve supervisor timeout/cancellation, rather than relabeling it a crash.
        if manifest.get('status') not in ('timeout','cancelled'):
            manifest.update(status='failed',error={'code':getattr(exc,'code','disasm_worker'),'message':str(exc)})
        write_json(job/'job.json',manifest,force=True)
        if isinstance(exc,Error):
            exc.partial = {'job_id':job_id}
            raise
        raise Error('disasm_worker','Worker did not publish a valid disassembly result',10,
                    partial={'job_id':job_id}) from exc


def publish(project, manifest, response):
    path = project.path/'jobs'/manifest['job_id']/'disasm-result.json'
    with jobs.result_publication('disasm',manifest['job_id']):
        write_json(path,response)
        manifest['disasm_result_sha256'] = digest(path)
        write_json(path.parent/'job.json',manifest,force=True)
    return response
