"""Bounded recorded token-address presentation, never source reconstruction."""
from . import pseudocode, terminal

MAX_FUNCTIONS=8
MAX_CODE_LINES=256
MAX_LINES=512
MAX_BYTES=128*1024
MAX_TEXT=1024*1024
MAX_SPANS=8192
MAX_RANGES=8


def render(result):
    lines=[];size=0;clipped=0;shown_clipped=0;exhausted=False;omitted_lines=0;omitted_ranges=0
    def field(value,limit=160):
        nonlocal clipped
        text='unavailable' if value is None else str(value) if isinstance(value,(str,int,bool)) else '[unsupported field]'
        if len(text)>limit:clipped+=1
        return terminal.safe(text[:limit])+('…' if len(text)>limit else '')
    def emit(value):
        nonlocal size,shown_clipped,exhausted
        encoded=len((value+'\n').encode('utf-8'))
        if exhausted or len(lines)>=MAX_LINES-8 or size+encoded>MAX_BYTES-4096:
            exhausted=True
            return False
        lines.append(value);size+=encoded;shown_clipped=clipped;return True
    emit('Address-linked pseudocode (recorded token ranges; not whole-line instruction ownership)')
    emit('Outcome: '+field(result.get('status'))+'; line numbers are presentation indices, not source lines.')
    data=result.get('data')
    data=data if isinstance(data,dict) else {}
    rows=data.get('functions',[data])
    rows=rows if isinstance(rows,list) else []
    if not rows or not any(isinstance(r,dict) and ('pseudocode' in r or 'decompile_status' in r) for r in rows[:MAX_FUNCTIONS]):
        emit('Address-linked pseudocode unavailable for this result; no code or addresses inferred.')
        rows=[]
    shown=0
    for row in rows[:MAX_FUNCTIONS]:
        if not isinstance(row,dict):row={}
        if not emit('Function '+field(row.get('entry_va') or row.get('engine_entry'))+'; decompile='+field(row.get('decompile_status'))):break
        shown+=1
        emit('  Function ID: '+field(row.get('function_id')))
        names=row.get('names');first=names[0] if isinstance(names,list) and names else {}
        name=first.get('name') if isinstance(first,dict) else None
        emit('  Recorded name: '+field(name or row.get('name') or 'unnamed'))
        code=row.get('pseudocode')
        if not isinstance(code,str) or not code:
            emit('  Pseudocode unavailable: '+field(row.get('decompile_error')))
            continue
        spans=[];reason=None
        coverage=row.get('coverage');coverage=coverage if isinstance(coverage,dict) else {}
        coverage=coverage.get('address_spans');coverage=coverage if isinstance(coverage,dict) else {}
        recorded=row.get('address_spans',[])
        invalid=not isinstance(recorded,list) or any(not isinstance(span,dict) or not isinstance(span.get('ranges'),list) for span in recorded[:MAX_SPANS])
        if invalid:
            reason='invalid recorded spans; mappings unavailable'
        elif len(code)>MAX_TEXT or len(recorded)>MAX_SPANS or sum(len(span['ranges']) for span in recorded)>MAX_SPANS:
            reason='mapping budget exceeded; unseen mappings unknown'
        else:
            try:
                if len(code.encode('utf-16-le',errors='surrogatepass'))>MAX_TEXT:
                    reason='mapping budget exceeded; unseen mappings unknown'
                else:
                    spans,info=pseudocode.address_spans(row,code)
                    reason=info.get('reason')
            except (ValueError,TypeError,KeyError,AttributeError):
                spans=[];reason='invalid recorded spans; mappings unavailable'
        emit('  Token mapping coverage: '+field(coverage.get('status'))+'; '+field(reason or 'validated recorded spans'))
        emit('  Recorded pseudocode truncated: '+field(row.get('pseudocode_truncated')))
        emit('  Columns: presentation line | recorded token ranges (entire line) | recorded pseudocode (may be clipped)')
        count=code.count('\n')+1;position=0;utf16_position=0;displayed=0
        for number in range(1,min(count,MAX_CODE_LINES)+1):
            end=code.find('\n',position)
            if end<0:end=len(code)
            # Mapping occurs before clipping/escaping, against the untouched text.
            utf16_end=utf16_position+(len(code[position:end].encode('utf-16-le',errors='surrogatepass'))//2 if spans else 0)
            ranges=sorted({(lo,hi) for span in spans if span['text_start']<utf16_end and utf16_position<span['text_end']
                           for lo,hi in span['ranges']},key=lambda r:(int(r[0],16),int(r[1],16))) if end>position else []
            addresses=', '.join(lo if lo==hi else lo+'..'+hi for lo,hi in ranges[:MAX_RANGES]) or '— (no recorded token mapping)'
            extra=max(0,len(ranges)-MAX_RANGES)
            if extra:addresses+=f' (+{extra} ranges omitted)'
            snippet=field(code[position:min(end,position+257)],256)
            if not emit(f'{number:4d} | {addresses} | {snippet}'):break
            displayed+=1;omitted_ranges+=extra
            position=end+1;utf16_position=utf16_end+1
        omitted_lines+=count-displayed
    # Reserved space keeps omission accounting visible even after output exhaustion.
    lines.extend([f'Omitted functions: {len(rows)-shown}; code lines in shown functions: {omitted_lines}; ranges on shown lines: {omitted_ranges}.',
                  f'Clipped fields: {shown_clipped}. Unmapped lines do not prove absence of machine behavior.',
                  'Full recorded evidence: repeat with --format json. No pseudocode or receipts were modified.'])
    return ('\n'.join(lines)+'\n').encode('utf-8')
