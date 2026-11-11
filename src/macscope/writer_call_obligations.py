"""Bounded conditional destination-store relations; never callee purity proofs."""
import copy
from . import computed_store_value

POLICY = 'macscope-writer-call-obligations/2'
MAX_CALLS = 8
MAX_POST_CALL_STORES = 64


def project(link, roles):
    report = link['destination_evidence']
    calls = [s for s in report['sites'] if s['kind'] == 'direct_call']
    stores = [s for s in report['sites'] if s['kind'] == 'memory_store' and s.get('conditional_on_calls')]
    result = {'policy': POLICY, 'status': 'conditional_obligations' if calls else 'not_needed',
              'destination_envelope_sha256': report['source_envelope_sha256'],
              'calls': [], 'post_call_stores': [], 'gaps': [],
              'omitted_calls': max(0,len(calls)-MAX_CALLS),
              'omitted_post_call_stores': max(0,len(stores)-MAX_POST_CALL_STORES),
              'application_writer_attribution': 'unknown', 'runtime_execution': 'unknown', 'persistence': 'unknown'}
    if any(s['kind'] == 'indirect_invocation' for s in report['sites']):
        result['gaps'].append({'reason': 'writer_indirect_invocation_boundary'})
    if link.get('status') != 'verified_direct_entry_link':
        result['gaps'].append({'reason': 'writer_call_verified_destination_missing'})
    if len(calls) > MAX_CALLS:
        result['gaps'].append({'reason': 'writer_call_budget'})
    if len(stores) > MAX_POST_CALL_STORES:
        result['gaps'].append({'reason': 'writer_post_call_store_budget'})
    intervals = [(int(r['selection']['start_va'],16),int(r['selection']['end_va'],16))
                 for r in roles.values() if r.get('selection')]
    extent = link.get('destination_extent')
    if extent:
        intervals.append((int(extent['entry_va'],16),int(extent['end_va_exclusive'],16)))
    for call in calls[:MAX_CALLS]:
        result['calls'].append({'role': 'writer', 'source_envelope_sha256': report['source_envelope_sha256'],
                               'evidence': copy.deepcopy(call),
                               'requires': ['normal_return', 'AAPCS64_callee_preservation'],
                               'memory_effects': 'unknown', 'receiver_lifetime': 'unknown'})
        if any(start <= int(call['target_va'],16) < end for start,end in intervals):
            result['gaps'].append({'reason': 'writer_call_cycle_or_reentry', 'instruction_va': call['instruction_va']})
    relations = {(r['instruction_va'],r.get('lane')):r for r in link.get('store_relations',[])}
    def classify(value, binding):
        if value['kind'] == 'range_input_register' and binding.get('status') == 'matched_input_register':
            return 'matched_input_register'
        if value['kind'] in ('address','integer_constant'):
            return 'byte_defined'
        if value['kind'] in ('stack_pointer_relative','unknown_stack_pointer'):
            return 'explicit_stack_origin'
        return 'unresolved'
    for store in stores[:MAX_POST_CALL_STORES]:
        relation = relations.get((store['instruction_va'],store.get('lane')), {})
        base = classify(store['location']['base'],relation.get('base_correspondence',{}))
        value = classify(store['value'],relation.get('value_correspondence',{}))
        computation = computed_store_value.project(report,store) if value == 'unresolved' else None
        if computation:
            value = 'scoped_checked_add_computation'
        result['post_call_stores'].append({'evidence': copy.deepcopy(store),
            'base_basis': base, 'value_basis': value, 'register_relation': copy.deepcopy(relation),
            'abi_hypothesis': 'aapcs64', 'status': 'conditional_operands' if 'unresolved' not in (base,value) else 'unresolved_operands'})
        if computation:
            result['post_call_stores'][-1]['value_computation'] = computation
        for operand,basis in (('base',base),('value',value)):
            if basis == 'unresolved':
                result['gaps'].append({'reason': f'writer_post_call_{operand}_unresolved',
                                      'instruction_va': store['instruction_va'], 'lane': store.get('lane')})
    if result['gaps']:
        result['status'] = 'gap'
    return result
