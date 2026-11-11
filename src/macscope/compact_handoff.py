"""Bounded text-only evidence presentation; no evidence transformations."""
import heapq

from . import evidence_summary, terminal

MAX_LEADS = 24
MAX_BLOCKERS = 2
MAX_FIELD = 80
MAX_LINES = 200
MAX_BYTES = 32768
FOOTER_RESERVE = 1024


def field(value):
    text = str(value)
    return terminal.safe(text[:MAX_FIELD]) + (' [clipped]' if len(text) > MAX_FIELD else '')


def priority(code):
    if 'failed' in code or 'unavailable' in code or 'unpublished' in code:
        return 0
    if 'ambiguous' in code:
        return 1
    if 'limit' in code or 'budget' in code:
        return 2
    return 3


def blockers(row):
    reason = row.get('reason')
    gaps = row.get('gaps') or []
    selected = [reason] if reason else []
    remaining = MAX_BLOCKERS - len(selected)
    selected.extend(code for _, code in heapq.nsmallest(
        remaining, enumerate(gaps), key=lambda pair: (priority(pair[1]), pair[0])))
    return selected, len(gaps) + bool(reason) - len(selected)


def render(result):
    leads = result['data'].get('leads', [])
    lines = [f"macscope evidence compact [{field(result['status'])}]",
             'Partial evidence exits 6; retained artifacts are not an engine crash.' if result['status'] == 'partial'
             else 'Status is recorded evidence status, not runtime verification.',
             'Worker success or complete individual links do not establish complete graph coverage.']
    used = len(('\n'.join(lines) + '\n').encode('utf-8'))
    shown = omitted_blockers = 0
    for row in leads[:MAX_LEADS]:
        codes, omitted = blockers(row)
        block = [f"Lead {field(row.get('lead', {}).get('id', 'ID unavailable'))} [{field(row['status'])}]"]
        block.extend('  Blocker (site unspecified): ' + field(code) for code in codes)
        if row['status'] == 'resolved':
            block.append('  Selected static requirements met; runtime behavior remains unknown.')
        else:
            if not codes:
                block.append('  Missing evidence unspecified; no gap site inferred.')
            block.append('  Next: ' + evidence_summary.next_action(codes))
        block.append(f'  Additional blocker entries omitted: {omitted}')
        size = len(('\n'.join(block) + '\n').encode('utf-8'))
        if used + size > MAX_BYTES - FOOTER_RESERVE or len(lines) + len(block) > MAX_LINES - 5:
            break
        lines.extend(block)
        used += size
        shown += 1
        omitted_blockers += omitted
    lines.extend([f'Leads displayed: {shown}; omitted: {len(leads) - shown}.',
                  f'Additional blocker entries omitted for displayed leads: {omitted_blockers}.',
                  'Nested evidence details omitted (compact-only presentation).',
                  'Full evidence: rerun the same evidence invocation with --format json or --format text.'])
    if 'objc_send_context' in result['data']:
        lines.append('Optional static selector-stub context omitted; dynamic dispatch remains unknown. Use full JSON/text.')
    if 'objc_type_evidence' in result['data']:
        lines.append('Optional Objective-C type details omitted; use full JSON, HTML or text evidence.')
    return ('\n'.join(lines) + '\n').encode('utf-8')
