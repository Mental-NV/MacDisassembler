"""Bounded composition of independent observations, never a memory alias proof."""
import copy

from . import callback_evidence, focused, import_disasm, jobs, metadata
from .errors import Error

POLICY = 'macscope-callback-composition/1'


def replay(project, image, raw, receipt, *, abi, provenance):
    _, manifest = jobs.get(project, receipt)
    request = manifest.get('disasm_request')
    if not isinstance(request, dict):
        raise Error('callback_composition_receipt', 'Expected a saved bounded disassembly receipt', 8)
    start = metadata.hex_address(request.get('start_va'), 'Composition start')
    end = metadata.hex_address(request.get('end_va'), 'Composition end')
    proof, payload = import_disasm.selection(raw, image, start, end)
    response = import_disasm.replay(project, image, proof, payload, receipt)
    return callback_evidence.project(response, abi=abi, provenance=provenance)['data']['callback_evidence']


def attach(project, image, raw, response, assignment, invocation, *, abi=None, provenance=False):
    """All roles are validated immutable receipts; two extra roles, one writer hop."""
    result = copy.deepcopy(response)
    thunk = result['data']['callback_evidence']
    assign = replay(project, image, raw, assignment, abi=abi, provenance=provenance)
    invoke = replay(project, image, raw, invocation, abi=abi, provenance=provenance)
    link = thunk.get('destination_link', {})
    writer = link.get('destination_evidence', {})
    roles = {'assignment': assign, 'invocation': invoke, 'thunk': thunk, 'writer': writer}
    view = {'policy': POLICY, 'status': 'inconclusive',
            'destination_effects': copy.deepcopy(link.get('destination_effects', {})), 'candidate_status': 'gap',
            'facts': {}, 'conditional_register_bindings': [], 'assumptions': [], 'gaps': [],
            'role_identities': {role: {'source_envelope_sha256': report.get('source_envelope_sha256'),
                                      'selection': copy.deepcopy(report.get('selection'))}
                                for role, report in roles.items()},
            'unknowns': ['assignment_and_invocation_slot_identity', 'intervening_memory_unchanged',
                         'runtime_invoked_code_identity', 'runtime_context_identity_and_abi',
                         'execution_order', 'application_writer_attribution', 'persistence'],
            'receipts': {'assignment': assignment, 'invocation': invocation,
                         'writer': link.get('destination_receipt')},
            'independent_evidence': {'assignment': assign, 'invocation': invoke}}
    # Attach after walking roles: the source report must not reference itself.
    for role, report in roles.items():
        for assumption in report.get('assumptions', []):
            view['assumptions'].append({'role': role, 'source_envelope_sha256': report['source_envelope_sha256'],
                                        'condition': assumption})
        for gap in report.get('gaps', []):
            view['gaps'].append({'role': role, 'evidence': copy.deepcopy(gap)})
    def gap(reason):
        view['gaps'].append({'reason': reason})
    # The exact byte-decoded target is a fact, not the dynamic invocation target.
    try:
        extent, _ = focused.extent(raw, image, thunk['selection']['start_va'], policy='macscope-focused-import/1')
        if int(thunk['selection']['end_va'],16) > int(extent['end_va_exclusive'],16):
            gap('thunk_selection_exceeds_linker_extent')
    except Error:
        gap('thunk_linker_extent_unavailable')
    stores = [s for s in assign['sites'] if s['kind'] == 'memory_store']
    targets = [s for s in stores if s['value'].get('kind') == 'address'
               and s['value'].get('value') == thunk['selection']['start_va']]
    target = targets[0] if len(targets) == 1 else None
    contexts = ([s for s in stores if s['instruction_va'] == target['instruction_va']
                 and 'lane' in s and s.get('lane') != target.get('lane')] if target else [])
    context = contexts[0] if len(contexts) == 1 else None
    if target is None or context is None:
        gap('unique_paired_assignment_not_proven')
    else:
        view['facts']['assignment_target_store'] = copy.deepcopy(target)
        view['facts']['assignment_context_store'] = copy.deepcopy(context)
        if context['value'].get('kind') not in ('range_input_register', 'address'):
            gap('assignment_context_value_unresolved')
        if any(int(s['instruction_va'], 16) > int(target['instruction_va'], 16) for s in stores):
            gap('later_assignment_store_possible_overwrite')
    calls = [s for s in invoke['sites'] if s['kind'] == 'indirect_invocation']
    call = calls[0] if len(calls) == 1 else None
    loads = [s for s in invoke['sites'] if s['kind'] == 'memory_load']
    operand = call.get('operand', {}) if call else {}
    target_loads = [s for s in loads if operand.get('kind') == 'memory_read'
                    and s['instruction_va'] == operand.get('origin_va')
                    and s.get('lane') == operand.get('lane')]
    target_load = target_loads[0] if len(target_loads) == 1 else None
    context_loads = ([s for s in loads if s['instruction_va'] == target_load['instruction_va']
                      and 'lane' in s and s.get('lane') != target_load.get('lane')]
                     if target_load else [])
    context_load = context_loads[0] if len(context_loads) == 1 else None
    if not call or not target_load or not context_load:
        gap('unique_paired_invocation_load_not_proven')
    else:
        view['facts']['invocation'] = copy.deepcopy(call)
        view['facts']['invocation_target_load'] = copy.deepcopy(target_load)
        view['facts']['invocation_context_load'] = copy.deepcopy(context_load)
        expected_context = {'kind': 'memory_read', 'origin_va': context_load['instruction_va'], 'lane': context_load['lane']}
        if call.get('register_inputs', {}).get(context_load['register']) != expected_context:
            gap('invocation_context_clobbered_or_untracked')
        if any(s['kind'] == 'memory_store' and int(s['instruction_va'],16) > int(target_load['instruction_va'],16) for s in invoke['sites']):
            gap('intervening_invocation_store')
        for stored, loaded in ((target, target_load), (context, context_load)):
            if stored and stored['location']['base'].get('kind') in ('address', 'integer_constant') and loaded['location']['base'].get('kind') in ('address', 'integer_constant'):
                store_address = (int(stored['location']['base']['value'],16) + stored['location']['offset']) & ((1 << 64)-1)
                load_address = (int(loaded['location']['base']['value'],16) + loaded['location']['offset']) & ((1 << 64)-1)
                if store_address != load_address:
                    gap('known_slot_address_mismatch')
        # Offset mismatch rejects a structural candidate; equality proves no identity.
        if target and context and (target['location']['offset'] != target_load['location']['offset']
                or context['location']['offset'] != context_load['location']['offset']):
            gap('assignment_invocation_layout_mismatch')
    if link.get('status') != 'verified_direct_entry_link':
        gap('verified_writer_link_missing')
    elif writer.get('selection', {}).get('start_va') == thunk['selection']['start_va']:
        gap('direct_link_cycle')
    else:
        view['facts']['direct_destination'] = copy.deepcopy(link['transfer'])
        relations = link.get('store_relations', [])
        if relations:
            view['facts']['writer_stores'] = copy.deepcopy(relations)
        else:
            gap('writer_store_not_proven')
    # A byte-proven back edge is a cycle, not permission to recurse.
    intervals = [(int(r['selection']['start_va'],16), int(r['selection']['end_va'],16))
                 for r in (thunk, writer) if r.get('selection')]
    if any(s['kind'] in ('direct_branch','direct_call') and
           any(start <= int(s['target_va'],16) < end for start,end in intervals)
           for s in writer.get('sites', [])):
        gap('writer_direct_link_cycle')
    # Semantic barriers cannot be crossed by presenting independently valid roles.
    allowed_stops = {'return_boundary', 'selected_prefix_end', 'direct_transfer_boundary', 'invocation_boundary'}
    for role, report in roles.items():
        if report.get('stop_reason') not in allowed_stops:
            gap(role + '_unsupported_boundary')
        if any(s['kind'] == 'direct_call' for s in report.get('sites', [])):
            gap(role + '_intervening_call')
        if any(g.get('reason') == 'disassembly_incomplete' for g in report.get('gaps', [])):
            gap(role + '_incomplete_disassembly')
    if not any('reason' in g for g in view['gaps']):
        view['candidate_status'] = 'conditional_candidate'
        # Do not substitute these into facts: the invocation target is unresolved.
        for register, value in sorted(call.get('register_inputs', {}).items()):
            view['conditional_register_bindings'].append({
                'destination': {'kind': 'range_input_register', 'register': register,
                                'selection_start_va': thunk['selection']['start_va'],
                                'source_envelope_sha256': thunk['source_envelope_sha256']},
                'source': {'role': 'invocation', 'source_envelope_sha256': invoke['source_envelope_sha256'],
                           'value': copy.deepcopy(value)},
                'requires_unverified': ['runtime_invoked_code_identity', 'execution_order'],
                'status': 'conditional_not_applied_to_facts'})
    thunk['composition'] = view
    return result
