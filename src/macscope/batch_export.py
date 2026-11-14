"""Finite, resumable analyzed-image batches; never isolated focused receipts."""
import hashlib
import shutil
from pathlib import Path
from . import engine, jobs
from .errors import Error
from .macho import read_regular
from .storage import identity, is_digest, write_json, json_object

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
    chunks = [entries[offset:offset+args.batch_size]
              for offset in range(0, len(entries), args.batch_size)]
    chunk_for_entry = {entry: chunk for chunk in chunks for entry in chunk}
    complete = {}
    record_jobs = {}
    index_path = destination/'index.json'
    if index_path.exists():
        index = json_object(read_regular(index_path, 64*1024*1024), 'batch_index', 'Invalid export index')
        if index.get('export_id') != export_id:
            raise Error('batch_identity', 'Export index identity mismatch')
        if not isinstance(index.get('records'), dict):
            raise Error('batch_index', 'Invalid export record index')
        for entry, receipt in index['records'].items():
            if entry not in chunk_for_entry or not isinstance(receipt, dict):
                raise Error('batch_index', 'Invalid export record')
            data = read_regular(records/(entry+'.json'), 64*1024*1024)
            if hashlib.sha256(data).hexdigest() != receipt.get('sha256'):
                raise Error('batch_integrity', 'Export record changed: '+entry)
            if not isinstance(receipt.get('status'), str) or receipt['status'] not in {'complete', 'not_requested'}:
                raise Error('batch_index', 'Invalid completed export record status')
            record = json_object(data, 'batch_record', 'Invalid export record JSON')
            function = record.get('function')
            job_id = record.get('job_id')
            if (record.get('export_id') != export_id or record.get('semantics') != SEMANTICS
                    or record.get('chunk_entries') != chunk_for_entry[entry]
                    or not isinstance(job_id, str) or not jobs.JOB_ID.fullmatch(job_id)
                    or not isinstance(function, dict) or function.get('entry_va') != entry
                    or function.get('decompile_status') != receipt['status']):
                raise Error('batch_record', 'Export record provenance mismatch: '+entry)
            record_jobs[entry] = job_id
            complete[entry] = receipt
    # Index commits complete original chunks only, never mix shared-session prefixes.
    for chunk in chunks:
        count = sum(entry in complete for entry in chunk)
        if count not in (0, len(chunk)):
            raise Error('batch_index', 'Export index contains an incomplete shared-session chunk')
        if count and len({record_jobs[entry] for entry in chunk}) != 1:
            raise Error('batch_record', 'Export chunk combines records from different worker jobs')
    source_bytes = sum(path.stat().st_size for path in source.rglob('*') if path.is_file())
    for chunk in chunks:
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


def status(project, export_id):
    """Read one atomic progress index, not worker liveness or record integrity."""
    if not is_digest(export_id):
        raise Error('batch_identity', 'Export ID must be a lowercase SHA-256 digest', 2)
    destination = project.path/'batch-exports'/export_id
    binding = json_object(read_regular(destination/'manifest.json', 64*1024*1024),
                          'batch_manifest', 'Invalid export manifest')
    if identity(binding) != export_id:
        raise Error('batch_identity', 'Export manifest identity mismatch')
    entries, size = binding.get('entries'), binding.get('batch_size')
    if (binding.get('schema') != 'macscope-batch-export/1'
            or binding.get('semantics') != SEMANTICS
            or binding.get('coordinator_policy') != COORDINATOR_POLICY
            or not is_digest(binding.get('image_id'))
            or not is_digest(binding.get('analysis_id'))
            or type(size) is not int or not 1 <= size <= 128
            or not isinstance(entries, list) or not 1 <= len(entries) <= 10000
            or any(not isinstance(e, str) or not 3 <= len(e) <= 18
                   or not e.startswith('0x') or any(c not in '0123456789abcdef' for c in e[2:])
                   or e != hex(int(e, 16)) for e in entries)):
        raise Error('batch_manifest', 'Unsupported or invalid batch progress manifest')
    if entries != sorted(set(entries), key=lambda e: int(e, 16)):
        raise Error('batch_manifest', 'Batch entries must be unique and numerically sorted')
    index_path = destination/'index.json'
    try:
        index_path.lstat()
    except FileNotFoundError:
        index = None
    else:
        index = json_object(read_regular(index_path, 64*1024*1024),
                            'batch_index', 'Invalid export index')
    records = {} if index is None else index.get('records')
    if index is not None and index.get('export_id') != export_id:
        raise Error('batch_identity', 'Export index identity mismatch')
    if not isinstance(records, dict) or not records.keys() <= set(entries):
        raise Error('batch_index', 'Invalid export record index')
    outcomes = {}
    for receipt in records.values():
        if (not isinstance(receipt, dict) or not is_digest(receipt.get('sha256'))
                or not isinstance(receipt.get('status'), str)
                or receipt['status'] not in {'complete', 'not_requested'}):
            raise Error('batch_index', 'Invalid completed export record')
        outcomes[receipt['status']] = outcomes.get(receipt['status'], 0) + 1
    chunks = [entries[offset:offset+size] for offset in range(0, len(entries), size)]
    counts = [sum(entry in records for entry in chunk) for chunk in chunks]
    if any(count not in (0, len(chunk)) for count, chunk in zip(counts, chunks)):
        raise Error('batch_index', 'Export index contains an incomplete shared-session chunk')
    return {'export_id': export_id, 'image_id': binding['image_id'],
            'analysis_id': binding['analysis_id'], 'semantics': SEMANTICS,
            'selected_count': len(entries), 'indexed_count': len(records),
            'unindexed_count': len(entries)-len(records), 'chunk_count': len(chunks),
            'indexed_chunk_count': sum(count > 0 for count in counts),
            'index_present': index is not None,
            'index_sha256': identity(index) if index is not None else None,
            'indexed_outcomes': dict(sorted(outcomes.items())),
            'record_integrity': 'not_checked', 'worker_state': 'not_checked',
            'coverage_scope': 'frozen export selection, not all binary functions',
            'limitations': ['Counts describe one saved index snapshot, not live worker state.',
                            'Unindexed functions may be pending, running or failed.',
                            'Function files and hashes are not verified; use batch-export --resume for validation.']}
