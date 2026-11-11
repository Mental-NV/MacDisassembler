"""One explicit saved-receipt link; never discover or execute dynamic targets."""
import copy

from . import callback_evidence, destination_effects, focused, import_disasm, jobs, metadata
from .errors import Error

POLICY = 'macscope-callback-receipt-link/1'


def attach(project, image, raw, response, job_id, *, abi=None, provenance=False, checked_add=False):
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
    projected = callback_evidence.project(target, abi=abi, provenance=provenance, checked_add=checked_add)
    result = copy.deepcopy(response)
    report = result['data']['callback_evidence']
    target_report = projected['data']['callback_evidence']
    link = {'policy': POLICY, 'status': 'gap', 'destination_receipt': job_id,
            'source_envelope_sha256': report['source_envelope_sha256'],
            'destination_envelope_sha256': target_report['source_envelope_sha256'],
            'destination_selection': target['data']['selection'],
            'destination_evidence': target_report,
            'source_path_obligations': [{'source_envelope_sha256':report['source_envelope_sha256'], 'evidence':copy.deepcopy(p)} for p in report.get('path_obligations',[])],
            'destination_path_obligations': [{'source_envelope_sha256':target_report['source_envelope_sha256'], 'evidence':copy.deepcopy(p)} for p in target_report.get('path_obligations',[])],
            'writer_attribution': 'unknown'}
    report['destination_link'] = link
    transfers = [site for site in report['sites']
                 if site['kind'] in ('direct_branch', 'direct_call') and site['target_va'] == hex(start)]
    if len(transfers) != 1:
        link['reason'] = 'selected_direct_destination_not_proven'
        link['destination_effects'] = destination_effects.project(raw, link)
        return result
    try:
        extent, _ = focused.extent(raw, image, hex(start), policy='macscope-focused-import/1')
    except Error as exc:
        link.update(reason='destination_linker_extent_unavailable', extent_error=exc.code)
        link['destination_effects'] = destination_effects.project(raw, link)
        return result
    if end > int(extent['end_va_exclusive'], 16):
        link['reason'] = 'destination_selection_exceeds_linker_extent'
        link['destination_effects'] = destination_effects.project(raw, link)
        return result
    link.update(status='verified_direct_entry_link', transfer=transfers[0], destination_extent=extent)
    if abi or provenance:
        inputs = transfers[0].get('register_inputs', {})
        def correspond(value):
            if (value.get('kind') == 'range_input_register'
                    and value.get('selection_start_va') == hex(start)
                    and value.get('source_envelope_sha256') == target_report['source_envelope_sha256']
                    and value.get('register') in inputs):
                return {'status': 'matched_input_register', 'evidence_scope': 'source_transfer',
                        'value': copy.deepcopy(inputs[value['register']])}
            return {'status': 'not_correlated', 'evidence_scope': 'destination', 'value': copy.deepcopy(value)}
        relations = []
        for site in target_report['sites']:
            if site['kind'] != 'memory_store':
                continue
            base = site['location']['base']
            base_binding, value_binding = correspond(base), correspond(site['value'])
            matched = all(binding['status'] == 'matched_input_register' for binding in (base_binding, value_binding))
            relations.append({'instruction_va': site['instruction_va'], 'instruction_bytes': site['instruction_bytes'],
                'destination_location': copy.deepcopy(site['location']), 'destination_value': copy.deepcopy(site['value']),
                'base_correspondence': base_binding, 'value_correspondence': value_binding,
                'storage_role': 'stack' if base['kind'] in ('stack_pointer_relative', 'unknown_stack_pointer') else 'unattributed_memory',
                'lane': site.get('lane'), 'abi_hypothesis': abi,
                'basis': ('abi_conditional_register_correspondence' if abi else 'byte_proven_register_correspondence')
                         if matched else 'partial_register_correspondence',
                'source_branch_conditions': list(transfers[0].get('conditional_on_branches', [])),
                'destination_branch_conditions': list(site.get('conditional_on_branches', [])),
                'source_call_conditions': list(transfers[0].get('conditional_on_calls', [])),
                'destination_call_conditions': list(site.get('conditional_on_calls', []))})
        link['store_relations'] = relations
    link['destination_effects'] = destination_effects.project(raw, link)
    return result
