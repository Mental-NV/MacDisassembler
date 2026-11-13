"""Finite, resumable analyzed-image batches; never isolated focused receipts."""
import hashlib
import shutil
from pathlib import Path
from . import engine, jobs
from .errors import Error
from .macho import read_regular
from .storage import identity, write_json, json_object

SEMANTICS = 'shared-program-session/1'
COORDINATOR_POLICY = 'whole-chunk-index/1'


def selection(snapshot, requested=None):
    available = {hex(int(f['entry_va'], 16)) for f in snapshot['functions'] if f.get('entry_va')}
    if requested:
        try:
            entries = {hex(int(value, 16)) for value in requested}
        except ValueError as exc:
            raise Error('batch_selection', 'Entries must be hexadecimal addresses', 2) from exc
        if not entries <= available:
            raise Error('batch_selection', 'Entries must exist in the committed analysis snapshot', 2)
    else:
        entries = available
    if not entries:
        raise Error('batch_selection', 'No captured RAM functions in this analysis', 2)
    return sorted(entries, key=lambda value: int(value, 16))


def private_directory(path):
    if path.is_symlink():
        raise Error('batch_path', 'Batch directories must not be symlinks')
    path.mkdir(mode=0o700, exist_ok=True)
    if not path.is_dir():
        raise Error('batch_path', 'Batch destination is not a directory')


def export(project, image, args, deps):
    if not 1 <= args.batch_size <= 128 or not 128 <= args.reserve_mib <= 1048576:
        raise Error('batch_budget', 'Batch size must be 1..128 and reserve MiB 128..1048576', 2)
    snapshot, active = project.snapshot(image)
    entries = selection(snapshot, args.entry)
    source = engine.analyzed_program(project, active)
    # Frozen identity includes deadlines: a resume is replay of this export, not a new policy.
    binding = {'schema':'macscope-batch-export/1', 'semantics':SEMANTICS,
               'image_id':image['image_id'], 'analysis_id':snapshot['analysis_id'],
               'bridge_sha256':engine.bridge_digest(), 'coordinator_policy':COORDINATOR_POLICY,
               'program_sha256':active['analysis_program_sha256'], 'runtime':deps,
               'entries':entries, 'batch_size':args.batch_size,
               'limits':engine.worker_limits(args, args.batch_size)}
    export_id = identity(binding)
    base = project.path/'batch-exports'
    private_directory(base)
    destination = base/export_id
    existed = destination.exists()
    if existed and not args.resume:
        raise Error('batch_exists', 'Export exists; use --resume to verify and reuse durable records', 2)
    private_directory(destination)
    records = destination/'functions'
    private_directory(records)
    manifest = destination/'manifest.json'
    if existed:
        previous = json_object(read_regular(manifest, 64*1024*1024), 'batch_manifest', 'Invalid export manifest')
        if previous != binding:
            raise Error('batch_identity', 'Export identity mismatch')
    else:
        write_json(manifest, binding)
    complete = {}
    index_path = destination/'index.json'
    if index_path.exists():
        index = json_object(read_regular(index_path, 64*1024*1024), 'batch_index', 'Invalid export index')
        if index.get('export_id') != export_id:
            raise Error('batch_identity', 'Export index identity mismatch')
        if not isinstance(index.get('records'), dict):
            raise Error('batch_index', 'Invalid export record index')
        for entry, receipt in index['records'].items():
            if entry not in entries or not isinstance(receipt, dict):
                raise Error('batch_index', 'Invalid export record')
            data = read_regular(records/(entry+'.json'), 64*1024*1024)
            if hashlib.sha256(data).hexdigest() != receipt.get('sha256'):
                raise Error('batch_integrity', 'Export record changed: '+entry)
            if receipt.get('status') not in {'complete', 'not_requested'}:
                raise Error('batch_index', 'Invalid completed export record status')
            complete[entry] = receipt
    # Index commits complete original chunks only, never mix shared-session prefixes.
    for offset in range(0, len(entries), args.batch_size):
        chunk = entries[offset:offset+args.batch_size]
        count = sum(entry in complete for entry in chunk)
        if count not in (0, len(chunk)):
            raise Error('batch_index', 'Export index contains an incomplete shared-session chunk')
    source_bytes = sum(path.stat().st_size for path in source.rglob('*') if path.is_file())
    for offset in range(0, len(entries), args.batch_size):
        chunk = entries[offset:offset+args.batch_size]
        if all(entry in complete for entry in chunk):
            continue
        # Replay the entire original chunk after interruption, preserving shared-session semantics.
        required = source_bytes + args.reserve_mib*1024*1024 + 64*1024*1024
        if shutil.disk_usage(project.path).free < required:
            raise Error('batch_disk_reserve', 'Insufficient space for one Program copy and configured free-space reserve',
                        partial={'export_id':export_id,'completed':len(complete)})
        try:
            result, job = engine.run(project, image, 'query', args, deps, bulk_entries=chunk)
        except Error as exc:
            exc.partial = dict(exc.partial or {}, export_id=export_id, completed=len(complete))
            raise
        if ([f.get('entry_va') for f in result.get('functions', [])] != chunk
                or any(f.get('decompile_status') not in {'complete', 'not_requested'}
                       for f in result.get('functions', []))):
            raise Error('batch_result', 'Worker returned a different chunk selection')
        for function in result['functions']:
            entry = function['entry_va']
            path = records/(entry+'.json')
            write_json(path, {'semantics':SEMANTICS, 'export_id':export_id,
                             'chunk_entries':chunk, 'job_id':job['job_id'], 'function':function}, force=True)
            data = read_regular(path, 64*1024*1024)
            complete[entry] = {'sha256':hashlib.sha256(data).hexdigest(), 'status':function['decompile_status']}
        write_json(index_path, {'export_id':export_id,'records':complete}, force=True)
        # Only a successfully reaped/validated owned query copy; retain job diagnostics/bridge receipt.
        copy = engine.job_directory(project, job['job_id'])/'program'
        if (copy.parent.is_symlink() or copy.is_symlink()
                or copy.resolve() == source.resolve()):
            raise Error('batch_cleanup', 'Refusing unsafe disposable Program cleanup')
        if copy.exists():
            shutil.rmtree(copy)
    return {'export_id':export_id, 'path':str(destination), 'selected_count':len(entries),
            'record_count':len(complete), 'semantics':SEMANTICS,
            'coverage_scope':'captured analysis RAM inventory, not all binary functions',
            'outcomes':{status:sum(r['status']==status for r in complete.values())
                        for status in sorted({r['status'] for r in complete.values()})}}
