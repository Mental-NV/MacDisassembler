"""References in one verified saved focused query; never an image-wide index."""
import copy
from . import address_xrefs, evidence, metadata
from .storage import identity

POLICY='macscope-focused-receipt-xrefs/1'
MAX_RECORDS=4096


def project(result,direction):
    function=result['data']
    refs=address_xrefs.FunctionReferences({})
    groups=[];facets={};gaps=[];omitted=0
    for side in (('to','from') if direction=='both' else (direction,)):
        key='to_entry' if side=='to' else 'from_body'
        facet='xrefs_to_entry' if side=='to' else 'xrefs_from'
        rows,incomplete,_=refs.records(function,side)
        available=MAX_RECORDS-len(groups)
        groups.extend((key,copy.deepcopy(row)) for row in rows[:available])
        omitted+=max(0,len(rows)-available)
        facets[key]=copy.deepcopy(function.get('coverage',{}).get(facet,{}))
        if incomplete:gaps.append(facet+'_incomplete')
        if side=='to':gaps.append('incoming_scope_not_global')
        if any(row.get('to') is None for row in rows[:available]):gaps.append('unresolved_recorded_target')
    if omitted:gaps.append('record_budget')
    if result['status']!='complete':gaps.append('query_result_partial')
    if direction in ('from','both') and function.get('control_flow_gaps'):gaps.append('unresolved_control_flow')
    data={'policy':POLICY,'source_envelope_sha256':identity(result),
          'source_query_status':result['status'],'function_id':function['function_id'],
          'entry_va':function['entry_va'],'image_id':function['image_id'],
          'slice_sha256':function['slice_sha256'],'direction':direction,
          'scope':'recorded_selected_function_only','runtime_execution':'unknown',
          'origin':copy.deepcopy(function['origin']),'recorded_facets':facets,
          'reference_sources':{key:'saved_focused_query' for key in facets},
          'gaps':sorted(set(gaps)),'omitted_records':omitted,
          'control_flow_gaps':copy.deepcopy(function.get('control_flow_gaps',[]))}
    data.update({key:[] for key in facets})
    return data,groups


def query(project_,image,entry,job_id,direction):
    raw=metadata.verified_slice(project_,image)
    result=evidence.focused_query(project_,image,raw,entry,job_id)
    data,groups=project(result,direction)
    data['requested_job_id']=job_id
    data['publication_job_id']=result['data']['origin']['job_id']
    return data,groups
