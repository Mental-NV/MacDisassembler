"""Exactly two independently bounded ARM64 B instructions preserve tracked GPRs."""
import copy

POLICY = 'macscope-thunk-register-forwarding/1'
REGISTERS = tuple(f'x{i}' for i in (*range(8), *range(19,30)))


def project(chain, roles, source_proof, inner_proof):
    result = {'policy': POLICY, 'status': 'gap', 'gaps': [], 'bindings': [],
              'scope': 'two_static_B_edges_only',
              'runtime_execution': 'unknown', 'application_writer_attribution': 'unknown',
              'persistence': 'unknown',
              'role_identities': copy.deepcopy(chain['role_identities'])}
    if chain['link_status'] != 'verified_two_hop_entry_links' or chain['gaps']:
        result['gaps'].append({'reason': 'two_hop_entry_links_unverified'})
    for role, proof in (('outer',source_proof),('inner',inner_proof)):
        if proof['status'] != 'verified_complete_selected_thunk':
            result['gaps'].append({'reason': 'complete_thunk_extent_unverified', 'role': role,
                                   'evidence': copy.deepcopy(proof)})
    if result['gaps']:
        return result
    # The boundary verifier binds actual B bytes, exact selected extent and target.
    result['thunk_boundaries'] = {'outer': copy.deepcopy(source_proof), 'inner': copy.deepcopy(inner_proof)}
    result['edges'] = [dict(source_role=role, instruction_va=roles[role]['sites'][0]['instruction_va'],
                            instruction_bytes=roles[role]['sites'][0]['instruction_bytes'],
                            target_va=roles[role]['sites'][0]['target_va'],
                            source_envelope_sha256=roles[role]['source_envelope_sha256'])
                       for role in ('outer','inner')]
    def scoped(role,register):
        report = roles[role]
        return {'kind': 'range_input_register', 'register': register,
                'selection_start_va': report['selection']['start_va'],
                'source_envelope_sha256': report['source_envelope_sha256']}
    result['bindings'] = [{'source': scoped('outer',register),
                           'destination': scoped('destination',register),
                           'basis': 'two_verified_B_instructions_preserve_register',
                           'status': 'static_equality_not_applied_to_facts'} for register in REGISTERS]
    result['status'] = 'verified_static_register_forwarding'
    result['destination_entry_va'] = roles['destination']['selection']['start_va']
    return result
