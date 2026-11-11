"""Bounded composition of independent observations, never a memory alias proof."""
import copy

from . import callback_evidence, focused, import_disasm, jobs, metadata, writer_call_obligations
from .errors import Error

POLICY = 'macscope-callback-composition/3'



def assignment_diagnostic(report, expected_entry):
    """Describe selected-prefix stores without guessing which is a callback."""
    stores = [site for site in report['sites'] if site['kind'] == 'memory_store']
    addresses = [site for site in stores if site['value'].get('kind') == 'address']
    matches = [site for site in addresses if site['value'].get('value') == expected_entry]
    companions = ([site for site in stores if site['instruction_va'] == matches[0]['instruction_va']
                   and 'lane' in site and site.get('lane') != matches[0].get('lane')]
                  if len(matches) == 1 else [])
    if not stores:
        reason, next_evidence = 'no_stores_in_decoded_prefix', 'Check the selected prefix and its interpretation barriers.'
    elif not addresses:
        reason, next_evidence = 'no_address_valued_store', 'Independently establish a stored code address; do not infer one from a register name.'
    elif not matches:
        reason, next_evidence = 'no_matching_address_store', 'Check the selected thunk against independently evidenced address stores; other stores need not be callbacks.'
    elif len(matches) > 1:
        reason, next_evidence = 'multiple_matching_address_stores', 'Obtain unambiguous assignment evidence without discarding intervening instructions.'
    elif len(companions) != 1:
        reason, next_evidence = 'unique_match_without_unique_companion_lane', 'Obtain a uniquely associated paired-lane observation; do not assume closure layout.'
    else:
        reason, next_evidence = 'unique_matching_pair_observed', 'Inspect the remaining chain obligations; this pair alone does not establish composition.'
    observations = []
    for site in stores[:32]:
        item = {'instruction_va': site['instruction_va'], 'value_kind': site['value'].get('kind')}
        if 'lane' in site:
            item['lane'] = site['lane']
        if site['value'].get('kind') == 'address':
            item['address'] = site['value']['value']
        observations.append(item)
    return {'policy': 'macscope-assignment-diagnostic/1', 'reason': reason,
            'expected_thunk_entry': expected_entry, 'next_evidence': next_evidence,
            'source_envelope_sha256': report['source_envelope_sha256'],
            'selection': copy.deepcopy(report['selection']),
            'stop_reason': report['stop_reason'], 'gap_count': len(report['gaps']),
            'counts': {'stores': len(stores), 'address_valued': len(addresses),
                       'matching_address': len(matches), 'other_address': len(addresses)-len(matches),
                       'non_address': len(stores)-len(addresses),
                       'unique_match_companion_lanes': len(companions) if len(matches) == 1 else None},
            'observations': observations, 'omitted_stores': max(0, len(stores)-32)}


def replay(project, image, raw, receipt, *, abi, provenance, fallthrough=False):
    _, manifest = jobs.get(project, receipt)
    request = manifest.get('disasm_request')
    if not isinstance(request, dict):
        raise Error('callback_composition_receipt', 'Expected a saved bounded disassembly receipt', 8)
    start = metadata.hex_address(request.get('start_va'), 'Composition start')
    end = metadata.hex_address(request.get('end_va'), 'Composition end')
    proof, payload = import_disasm.selection(raw, image, start, end)
    response = import_disasm.replay(project, image, proof, payload, receipt)
    return callback_evidence.project(response, abi=abi, provenance=provenance, fallthrough=fallthrough)['data']['callback_evidence']


def attach(project, image, raw, response, assignment, invocation, *, abi=None, provenance=False, context_register=None, invocation_fallthrough=False, writer_calls=False):
    """All roles are validated immutable receipts; two extra roles, one writer hop."""
    if context_register is not None and context_register not in {f'x{i}' for i in (*range(8), *range(19,30))}:
        raise Error('callback_scope','Unsupported context register pin',2)
    if writer_calls and abi != 'aapcs64':
        raise Error('callback_scope','Writer-call obligations require explicit AAPCS64',2)
    result = copy.deepcopy(response)
    thunk = result['data']['callback_evidence']
    assign = replay(project, image, raw, assignment, abi=abi, provenance=provenance)
    invoke = replay(project, image, raw, invocation, abi=abi, provenance=provenance, fallthrough=invocation_fallthrough)
    link = thunk.get('destination_link', {})
    writer = link.get('destination_evidence', {})
    roles = {'assignment': assign, 'invocation': invoke, 'thunk': thunk, 'writer': writer}
    view = {'policy': POLICY, 'status': 'inconclusive',
            'destination_effects': copy.deepcopy(link.get('destination_effects', {})), 'candidate_status': 'gap',
            'facts': {}, 'conditional_register_bindings': [], 'assumptions': [], 'gaps': [],
            'invocation_context_mode': 'explicit_register' if context_register else 'paired_load',
            'context_register_pin': context_register, 'path_obligations': [], 'call_obligations': [],
            'role_identities': {role: {'source_envelope_sha256': report.get('source_envelope_sha256'),
                                      'selection': copy.deepcopy(report.get('selection'))}
                                for role, report in roles.items()},
            'unknowns': ['assignment_and_invocation_slot_identity', 'intervening_memory_unchanged',
                         'runtime_invoked_code_identity', 'runtime_context_identity_and_abi',
                         'execution_order', 'application_writer_attribution', 'persistence'],
            'receipts': {'assignment': assignment, 'invocation': invocation,
                         'writer': link.get('destination_receipt')},
            'independent_evidence': {'assignment': assign, 'invocation': invoke}}
    view['assignment_diagnostic'] = assignment_diagnostic(assign, thunk['selection']['start_va'])
    if writer_calls:
        proof = writer_call_obligations.project(link, roles)
        view['writer_call_evidence'] = proof
        view['gaps'].extend(dict(g, role='writer') for g in proof['gaps'])
        view['call_obligations'].extend(copy.deepcopy(proof['calls']))
        if proof['calls']:
            view['unknowns'].extend(['writer_callee_memory_side_effects', 'receiver_lifetime_after_writer_calls',
                                     'writer_calls_may_not_return_normally'])
    # Attach after walking roles: the source report must not reference itself.
    for role, report in roles.items():
        for obligation in report.get('path_obligations', []):
            view['path_obligations'].append({'role': role, 'source_envelope_sha256': report['source_envelope_sha256'], 'evidence': copy.deepcopy(obligation)})
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
    if context_register:
        context_operand = call.get('register_inputs', {}).get(context_register, {}) if call else {}
        context_loads = [s for s in loads if context_operand.get('kind') == 'memory_read'
                         and s['instruction_va'] == context_operand.get('origin_va')
                         and s.get('lane') == context_operand.get('lane')]
    else:
        context_loads = ([s for s in loads if s['instruction_va'] == target_load['instruction_va']
                          and 'lane' in s and s.get('lane') != target_load.get('lane')]
                         if target_load else [])
    context_load = context_loads[0] if len(context_loads) == 1 else None
    if not call or not target_load or not context_load:
        gap('unique_split_invocation_load_not_proven' if context_register else 'unique_paired_invocation_load_not_proven')
    else:
        view['facts']['invocation'] = copy.deepcopy(call)
        view['facts']['invocation_target_load'] = copy.deepcopy(target_load)
        view['facts']['invocation_context_load'] = copy.deepcopy(context_load)
        expected_context = {'kind': 'memory_read', 'origin_va': context_load['instruction_va']}
        if 'lane' in context_load:
            expected_context['lane'] = context_load['lane']
        if call.get('register_inputs', {}).get(context_register or context_load['register']) != expected_context:
            gap('invocation_context_clobbered_or_untracked')
        if target_load is context_load:
            gap('target_and_context_load_not_distinct')
        if target_load['location']['base'] != context_load['location']['base']:
            gap('split_load_base_identity_not_proven')
        earliest_load = min(int(target_load['instruction_va'],16),int(context_load['instruction_va'],16))
        if any(s['kind'] == 'memory_store' and int(s['instruction_va'],16) > earliest_load for s in invoke['sites']):
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
        if role == 'writer' and not writer_calls and any(s['kind'] == 'indirect_invocation' for s in report.get('sites', [])):
            gap('writer_indirect_invocation_boundary')
        direct_calls = [s for s in report.get('sites', []) if s['kind'] == 'direct_call']
        if direct_calls:
            if role == 'invocation' and any(int(report['selection']['start_va'],16) <= int(s['target_va'],16) < int(report['selection']['end_va'],16) for s in direct_calls):
                gap('invocation_direct_call_cycle_or_reentry')
            if role == 'invocation' and invocation_fallthrough and abi == 'aapcs64':
                view['call_obligations'].extend({'role': role, 'source_envelope_sha256': report['source_envelope_sha256'],
                    'evidence': copy.deepcopy(s), 'requires': ['normal_return', 'AAPCS64_callee_preservation'],
                    'memory_effects': 'unknown'} for s in direct_calls)
                view['unknowns'].append('context_lifetime_after_calls')
            elif not (role == 'writer' and writer_calls):
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
                'requires_branch_conditions': [p['evidence']['instruction_va'] for p in view['path_obligations']],
                'requires_call_conditions': [c['evidence']['instruction_va'] for c in view['call_obligations'] if c['role'] == 'invocation'],
                'status': 'conditional_not_applied_to_facts'})
    if view['path_obligations']:
        view['unknowns'].append('alternate_branch_paths_not_analyzed')
    thunk['composition'] = view
    return result
