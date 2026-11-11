"""Two independently pinned direct edges; no transitive register substitution."""
import copy
from . import callback_evidence, callback_links, focused, focused_tailcalls, import_disasm, jobs, metadata, thunk_forwarding, writer_call_obligations
from .errors import Error

POLICY = 'macscope-pinned-twohop/3'


def source_boundary(raw, image, outer, link):
    """An independently recomputed byte extent, not a transitive call proof."""
    result = {'policy': 'macscope-twohop-source-boundary/1', 'status': 'gap',
              'source_envelope_sha256': outer['source_envelope_sha256'],
              'selection': copy.deepcopy(outer['selection'])}
    def gap(reason):
        return dict(result, reason=reason)
    sites = outer['sites']
    if (len(sites) != 1 or sites[0]['kind'] != 'direct_branch'
            or outer['stop_reason'] != 'direct_transfer_boundary'
            or any(g.get('reason') != 'direct_transfer_boundary' for g in outer['gaps'])):
        return gap('complete_single_branch_evidence_required')
    if link.get('status') != 'verified_direct_entry_link':
        return gap('pinned_inner_entry_not_verified')
    selection = outer['selection']
    if (int(selection['end_va'],16)-int(selection['start_va'],16) != 4
            or sites[0]['instruction_va'] != selection['start_va']
            or sites[0]['target_va'] != link['destination_selection']['start_va']):
        return gap('selected_branch_identity_mismatch')
    try:
        proof, payload = focused.extent(raw, image, selection['start_va'],
                                       policy='macscope-focused-import/4')
    except Error as exc:
        return dict(gap('source_boundary_unavailable'), extent_error=exc.code)
    if proof['end_va_exclusive'] != selection['end_va'] or proof['length'] != 4:
        return gap('selection_is_not_complete_source_extent')
    if (payload.hex() != sites[0]['instruction_bytes']
            or focused_tailcalls.branch_target(int(selection['start_va'],16),payload) != int(sites[0]['target_va'],16)):
        return gap('selected_branch_bytes_mismatch')
    result.update(status='verified_complete_selected_thunk',
                  basis='terminal_linker_branch' if 'boundary' in proof else 'next_linker_start',
                  extent=proof, target_va=sites[0]['target_va'])
    return result


def attach(project,image,raw,response,via,target,*,abi=None,provenance=False,checked_add=False, writer_calls=False):
    if writer_calls and abi != 'aapcs64':
        raise Error('callback_scope','Writer-call obligations require explicit AAPCS64',2)
    # Reuse the ordinary verifier; even gap edges retain independent evidence.
    first=callback_links.attach(project,image,raw,response,via,abi=abi,provenance=provenance)
    outer=first['data']['callback_evidence']
    link1=outer['destination_link']
    inner=link1['destination_evidence']
    _,manifest=jobs.get(project,via)
    request=manifest.get('disasm_request')
    if not isinstance(request,dict):
        raise Error('callback_twohop_receipt','Expected bounded disassembly receipt',8)
    start=metadata.hex_address(request.get('start_va'),'Intermediate start')
    end=metadata.hex_address(request.get('end_va'),'Intermediate end')
    proof,payload=import_disasm.selection(raw,image,start,end)
    middle=callback_evidence.project(import_disasm.replay(project,image,proof,payload,via),abi=abi,provenance=provenance)
    second=callback_links.attach(project,image,raw,middle,target,abi=abi,provenance=provenance,checked_add=checked_add)
    link2=second['data']['callback_evidence']['destination_link']
    destination=link2['destination_evidence']
    roles={'outer':outer,'inner':inner,'destination':destination}
    gaps=[]
    def gap(reason,role=None):
        gaps.append(dict(reason=reason,**({'role':role} if role else {})))
    # The projected root is no longer a one-hop view. Its two edges are explicit.
    outer.pop('destination_link')
    selections={role:r['selection'] for role,r in roles.items()}
    intervals={role:(int(s['start_va'],16),int(s['end_va'],16)) for role,s in selections.items()}
    for role in ('outer','inner'):
        r=roles[role];lo,hi=intervals[role]
        if hi-lo!=4 or len(r['sites'])!=1 or r['sites'][0]['kind']!='direct_branch' or r['stop_reason']!='direct_transfer_boundary':
            gap('single_instruction_thunk_not_proven',role)
        if any(g.get('reason')=='disassembly_incomplete' for g in r['gaps']):
            gap('incomplete_thunk_disassembly',role)
    for label,link in (('outer_to_inner',link1),('inner_to_destination',link2)):
        if link.get('status')!='verified_direct_entry_link':
            gap(link.get('reason','direct_entry_link_not_proven'),label)
    values=list(intervals.items())
    for i,(role,(lo,hi)) in enumerate(values):
        for other,(other_lo,other_hi) in values[i+1:]:
            if lo<other_hi and other_lo<hi:
                gap('overlapping_role_selections',role+':'+other)
    # Include full independently verified destination extent for reentry checks.
    guarded=list(intervals.values())
    extent=link2.get('destination_extent')
    if extent:
        guarded.append((int(extent['entry_va'],16),int(extent['end_va_exclusive'],16)))
    for site in destination['sites']:
        if site['kind'] in ('direct_branch','direct_call') and any(lo<=int(site['target_va'],16)<hi for lo,hi in guarded):
            gap('destination_cycle_or_reentry')
            break
    chain={'policy':POLICY,'status':'inconclusive',
        'link_status':'gap' if gaps else 'verified_two_hop_entry_links',
        'source_extent':'not_proven_selected_bytes_only',
        'role_identities':{role:{'selection':copy.deepcopy(r['selection']),
            'source_envelope_sha256':r['source_envelope_sha256']} for role,r in roles.items()},
        'receipts':{'inner':via,'destination':target},
        'edges':[link1,link2], 'gaps':gaps,
        'destination_effects':copy.deepcopy(link2['destination_effects']),
        'destination_stop_reason':destination['stop_reason'],
        'destination_gaps':copy.deepcopy(destination['gaps']),
        'path_obligations':[{'role':'destination','source_envelope_sha256':destination['source_envelope_sha256'],
                            'evidence':copy.deepcopy(p)} for p in destination['path_obligations']],
        'assumptions':[{'role':'destination','condition':a} for a in destination['assumptions']],
        'call_obligations':[{'role':'destination','evidence':copy.deepcopy(s),
                            'source_envelope_sha256':destination['source_envelope_sha256'],
                            'requires':['normal_return','AAPCS64_callee_preservation'],'memory_effects':'unknown'}
                           for s in destination['sites'] if s['kind']=='direct_call' and abi=='aapcs64'],
        'unknowns':['transitive_register_correspondence_not_applied','runtime_execution',
                    'application_writer_attribution','persistence','execution_order']}
    boundary = source_boundary(raw,image,outer,link1)
    chain['source_extent_evidence'] = boundary
    if boundary['status'] == 'verified_complete_selected_thunk':
        chain['source_extent'] = boundary['status']
    inner_boundary = source_boundary(raw,image,inner,link2)
    forwarding = thunk_forwarding.project(chain,roles,boundary,inner_boundary)
    chain['register_forwarding'] = forwarding
    if forwarding['status'] == 'verified_static_register_forwarding':
        chain['unknowns'].remove('transitive_register_correspondence_not_applied')
        chain['unknowns'].append('forwarded_inputs_not_substituted_into_destination_facts')
    if chain['path_obligations']:
        chain['unknowns'].append('alternate_branch_paths_not_analyzed')
    if chain['call_obligations']:
        chain['unknowns'].extend(['callee_memory_side_effects','receiver_lifetime_after_calls'])
    if writer_calls:
        proof=writer_call_obligations.project(link2,roles)
        if destination['stop_reason'] not in ('selected_prefix_end','return_boundary','direct_transfer_boundary'):
            proof['gaps'].append({'reason':'writer_unsupported_boundary'})
        if any(g.get('reason')=='disassembly_incomplete' for g in destination['gaps']):
            proof['gaps'].append({'reason':'writer_incomplete_disassembly'})
        if gaps:
            proof['gaps'].append({'reason':'two_hop_route_not_verified'})
        if proof['gaps']:proof['status']='gap'
        chain['writer_call_evidence']=proof
        chain['unknowns'].append('computed_operand_runtime_value')
    outer['two_hop_chain']=chain
    return first
