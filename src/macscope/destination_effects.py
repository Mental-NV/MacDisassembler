"""Attribute static stores to bounded storage evidence, never application behavior."""
import copy

from . import macho
from .errors import Error
from .macho_view import MappedImage

POLICY = 'macscope-destination-effects/1'
MAX_STORES = 2048
MAX_MAPPINGS = 4096


def project(raw, link):
    report = link['destination_evidence']
    result = {'policy': POLICY, 'destination_identity': link['status'],
              'destination_envelope_sha256': report['source_envelope_sha256'],
              'source_envelope_sha256': link['source_envelope_sha256'],
              'destination_selection': copy.deepcopy(report['selection']),
              'assumptions': copy.deepcopy(report.get('assumptions', [])),
              'coverage': 'interpreted_selected_prefix_only',
              'interpreted_end_va': report['interpreted_end_va'],
              'stop_reason': report['stop_reason'], 'observed_stores': [],
              'application_writer_attribution': 'unknown', 'runtime_execution': 'unknown',
              'persistence': 'unknown', 'counts': {'stack_or_frame': 0,
                'mapped_image_nonstack': 0, 'unresolved_destination': 0}, 'omitted_stores': 0}
    metadata, mapped, mapping_error = None, None, None
    try:
        metadata = macho.thin(raw)
        if len(metadata['sections']) > MAX_MAPPINGS or len(metadata['segments']) > MAX_MAPPINGS:
            mapping_error = 'mapping_budget'
        else:
            mapped = MappedImage(raw, metadata['segments'], reject_virtual_overlap=True)
    except (Error, ValueError):
        mapping_error = 'mapping_unavailable_or_ambiguous'
    relations = {(r['instruction_va'], r.get('lane')): r for r in link.get('store_relations', [])}
    stores = [s for s in report['sites'] if s['kind'] == 'memory_store']
    result['omitted_stores'] = max(0, len(stores)-MAX_STORES)
    for site in stores[:MAX_STORES]:
        base = site['location']['base']
        scope = 'destination'
        relation = relations.get((site['instruction_va'], site.get('lane')), {})
        binding = relation.get('base_correspondence', {})
        if binding.get('status') == 'matched_input_register':
            base, scope = binding['value'], 'source_transfer'
        effect = {'instruction_va': site['instruction_va'], 'instruction_bytes': site['instruction_bytes'],
                  'lane': site.get('lane'), 'width': 8, 'base_evidence': copy.deepcopy(base),
                  'base_evidence_scope': scope, 'abi_hypothesis': relation.get('abi_hypothesis'), 'location': copy.deepcopy(site['location']),
                  'source_call_conditions': list(relation.get('source_call_conditions', [])),
                  'destination_call_conditions': list(site.get('conditional_on_calls', [])),
                  'classification': 'unresolved_destination', 'reason': 'base_not_address_proven'}
        kind = base.get('kind')
        if kind in ('stack_pointer_relative', 'unknown_stack_pointer'):
            effect.update(classification='stack_or_frame', reason='explicit_stack_origin')
        elif kind == 'address':
            address = int(base['value'],16) + site['location']['offset']
            if address < 0 or address + 8 > 1 << 64:
                effect['reason'] = 'effective_range_overflow'
            elif mapping_error:
                effect['reason'] = mapping_error
            else:
                # No wrapping, guessed slide, section-name semantics or zero-fill inference.
                sections = [s for s in metadata['sections'] if int(s['va'],16) <= address
                            and address+8 <= int(s['va'],16)+int(s['size'],16)]
                overlaps = [s for s in metadata['sections'] if int(s['va'],16) < address+8
                            and int(s['va'],16)+int(s['size'],16) > address]
                if len(sections) != 1 or len(overlaps) != 1:
                    effect['reason'] = 'section_mapping_missing_or_ambiguous'
                elif sections[0]['file_offset'] is None:
                    effect['reason'] = 'section_not_file_backed'
                else:
                    section = sections[0]
                    try:
                        offset, _, protection = mapped.mapping(address,8)
                        section_offset = int(section['file_offset'],16)+address-int(section['va'],16)
                        if section_offset != offset:
                            effect['reason'] = 'section_segment_mapping_mismatch'
                        elif not protection & 2 or protection & 4:
                            effect['reason'] = 'mapping_not_writable_nonexecutable'
                        else:
                            effect.update(classification='mapped_image_nonstack', reason='unique_writable_image_range',
                                          static_image_va=hex(address), file_offset=hex(offset),
                                          section={'va': section['va'], 'size': section['size'],
                                                   'file_offset': section['file_offset'], 'protections': protection},
                                          attribution_scope='static_image_range_not_application_field')
                    except ValueError:
                        effect['reason'] = 'segment_mapping_missing_or_ambiguous'
        result['observed_stores'].append(effect)
        result['counts'][effect['classification']] += 1
    kinds = [kind for kind,count in result['counts'].items() if count]
    result['summary'] = ('no_observed_stores' if not kinds else
                         'only_stack_or_frame_stores' if kinds == ['stack_or_frame'] else
                         'only_unresolved_store_destinations' if kinds == ['unresolved_destination'] else
                         'mapped_image_stores_observed' if kinds == ['mapped_image_nonstack'] else
                         'mixed_observed_store_destinations')
    if result['omitted_stores']:
        result['summary'] = 'partial_store_classification'
    return result
