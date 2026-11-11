"""Derived register facts from a verified focused receipt, never inferred prototypes."""
import copy
import re
from . import callback_evidence, evidence, metadata
from .errors import Error
from .storage import canonical, identity

POLICY = 'macscope-focused-register-relations/1'
MAX_INSTRUCTIONS = 128
MAX_BYTES = 1024 * 1024


def parse_range(value):
    if not isinstance(value, str) or not re.fullmatch(r'0x[0-9a-f]{1,16}:0x[0-9a-f]{1,16}', value):
        raise Error('register_range', 'Use explicit unslid START:END hexadecimal addresses', 2)
    start, end = (int(v, 16) for v in value.split(':'))
    if start % 4 or end % 4 or not 0 < end-start <= MAX_INSTRUCTIONS*4:
        raise Error('register_range', 'Select one to 128 aligned ARM64 instructions', 2)
    return start, end


def derive(result, selected, *, abi):
    if abi != 'aapcs64':
        raise Error('register_abi', 'Explicit AAPCS64 preservation hypothesis required', 2)
    start, end = selected
    # Recheck even internal callers; public query() validates the receipt first.
    if parse_range(f'{hex(start)}:{hex(end)}') != selected:
        raise Error('register_range', 'Invalid selected range', 2)
    function = result['data']; origin = function['origin']; extent = origin['extent']
    if function['arch'] != 'arm64':
        raise Error('register_arch', 'Register relationships support ARM64 only', 3)
    entry = int(extent['entry_va'], 16)
    if not entry <= start < end <= int(extent['end_va_exclusive'], 16):
        raise Error('register_extent', 'Range must stay within the verified selected function extent', 3)
    rows = [copy.deepcopy(row) for row in function['instructions'] if start <= int(row['addr'],16) < end]
    if (len(rows) != (end-start)//4 or any(row['addr'] != hex(start+4*i)
            or not isinstance(row.get('bytes'), str) or not re.fullmatch('[0-9a-f]{8}', row['bytes'])
            for i,row in enumerate(rows))):
        raise Error('register_instructions', 'Selected instruction evidence must be complete and contiguous', 3)
    parent_digest = identity(result)
    selection = {'arch':'arm64', 'start_va':hex(start), 'end_va':hex(end),
                 'parent_focused_envelope_sha256':parent_digest}
    derived = {'data':{'selection':selection,'instructions':rows,'gaps':[]}}
    facts = callback_evidence.project(derived, abi=abi, provenance=True,
                                      fallthrough=False, checked_add=False)['data']['callback_evidence']
    report = {'policy':POLICY, 'status':'partial',
        'source_kind':'verified_saved_import_focused_query', 'source_envelope_sha256':parent_digest,
        'image_id':function['image_id'], 'slice_sha256':function['slice_sha256'],
        'function_id':function['function_id'], 'entry_va':function['entry_va'],
        'origin':copy.deepcopy(origin), 'source_query_status':result['status'],
        'source_coverage':copy.deepcopy(function.get('coverage',{})),
        'source_control_flow_gaps':copy.deepcopy(function.get('control_flow_gaps',[])),
        'selection':selection, 'register_origin_scope':'function_entry' if start==entry else 'selected_range_only',
        'entry_to_range_reachability':'not_established',
        'decoder_policy':facts['policy'], 'derived_input_sha256':facts['source_envelope_sha256'],
        'derived_input_kind':'in_memory_projection_not_original_disassembly_receipt',
        'abi_hypothesis':abi, 'assumptions':facts['assumptions'],
        'limitations':['Execution must reach the selected range and follow its interpreted prefix.',
            'No composition across omitted guards or unsupported instructions.',
            'Post-call register values are opaque, not typed or meaningful returns.',
            'No argument count/types, runtime indirect target, object identity or persistence proved.',
            'Memory observations are symbolic; direct calls may have arbitrary memory effects.'],
        'sites':facts['sites'], 'gaps':facts['gaps'],
        'interpreted_end_va':facts['interpreted_end_va'], 'stop_reason':facts['stop_reason']}
    if len(canonical(report)) > MAX_BYTES:
        raise Error('register_budget', 'Register relationship report exceeds its byte budget', 3)
    return report


def query(project, job_id, range_text, abi):
    selected = parse_range(range_text)
    manifest = evidence.from_query_jobs(project, [job_id])
    lead = manifest['leads'][0]
    image = next(row for row in project.images() if row['image_id']==lead['image_id'])
    result = evidence.focused_query(project,image,metadata.verified_slice(project,image),lead['value'],job_id)
    report = derive(result, selected, abi=abi)
    report['requested_job_id'] = job_id
    report['publication_job_id'] = result['data']['origin']['job_id']
    if len(canonical(report)) > MAX_BYTES:
        raise Error('register_budget', 'Register relationship report exceeds its byte budget', 3)
    return report
