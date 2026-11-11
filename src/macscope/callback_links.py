"""One explicit saved-receipt link; never discover or execute dynamic targets."""
import copy

from . import callback_evidence, focused, import_disasm, jobs, metadata
from .errors import Error

POLICY = 'macscope-callback-receipt-link/1'


def attach(project, image, raw, response, job_id):
    """Verify the destination independently before adding a derived link."""
    _, manifest = jobs.get(project, job_id)
    request = manifest.get('disasm_request', {})
    if not isinstance(request, dict):
        raise Error('callback_target_receipt', 'Destination request is not an object', 8)
    try:
        start = metadata.hex_address(request.get('start_va'), 'Destination start')
        end = metadata.hex_address(request.get('end_va'), 'Destination end')
    except (Error, TypeError, ValueError) as exc:
        raise Error('callback_target_receipt', 'Destination must be a bounded import-disassembly receipt', 8) from exc
    proof, payload = import_disasm.selection(raw, image, start, end)
    target = import_disasm.replay(project, image, proof, payload, job_id)
    projected = callback_evidence.project(target)
    result = copy.deepcopy(response)
    report = result['data']['callback_evidence']
    target_report = projected['data']['callback_evidence']
    link = {'policy': POLICY, 'status': 'gap', 'destination_receipt': job_id,
            'source_envelope_sha256': report['source_envelope_sha256'],
            'destination_envelope_sha256': target_report['source_envelope_sha256'],
            'destination_selection': target['data']['selection'],
            'destination_evidence': target_report,
            'writer_attribution': 'unknown'}
    report['destination_link'] = link
    transfers = [site for site in report['sites']
                 if site['kind'] in ('direct_branch', 'direct_call') and site['target_va'] == hex(start)]
    if len(transfers) != 1:
        link['reason'] = 'selected_direct_destination_not_proven'
        return result
    try:
        extent, _ = focused.extent(raw, image, hex(start), policy='macscope-focused-import/1')
    except Error as exc:
        link.update(reason='destination_linker_extent_unavailable', extent_error=exc.code)
        return result
    if end > int(extent['end_va_exclusive'], 16):
        link['reason'] = 'destination_selection_exceeds_linker_extent'
        return result
    link.update(status='verified_direct_entry_link', transfer=transfers[0], destination_extent=extent)
    return result
