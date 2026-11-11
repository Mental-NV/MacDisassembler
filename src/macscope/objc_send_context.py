"""Selected static selector-stub facts, never Objective-C runtime dispatch resolution."""
import struct
from . import evidence, metadata, objc, macho_symbols
from .errors import Error
from .macho import thin
from .dyld_legacy import library_for_ordinal
from .storage import identity

POLICY = 'macscope-objc-send-context/1'
MAX_INSTRUCTIONS = 512
MAX_SITES = 16
MAX_TOTAL_SITES = 64
LIMITATIONS = ['Static instruction targets do not prove execution.',
              'Receiver class, dynamic IMP, dispatched call return contract and effects remain unknown.',
              'Not an exhaustive send inventory; zero omissions only describes the selected bounded output.',
              'Raw pseudocode, receipt coverage and unresolved flow gaps are unchanged.']


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def branch(site, raw):
    if site % 4 or len(raw) != 4:
        return None
    word = int.from_bytes(raw, 'little')
    if word & 0x7c000000 != 0x14000000:
        return None
    target = site + (signed(word & 0x3ffffff, 26) << 2)
    return (target, 'BL' if word & 0x80000000 else 'B') if 0 <= target < 1 << 64 else None


def load_slot(pc, adrp, ldr, register):
    if adrp & 0x9f00001f != 0x90000000 | register:
        raise ValueError('unsupported_stub_template')
    if ldr & 0xffc003ff != 0xf9400000 | (register << 5) | register:
        raise ValueError('unsupported_stub_template')
    page = (pc & ~0xfff) + (signed(((adrp >> 5) & 0x7ffff) << 2 | (adrp >> 29 & 3), 21) << 12)
    slot = page + ((ldr >> 10 & 0xfff) << 3)
    if not 0 <= slot < (1 << 64) - 7:
        raise ValueError('stub_slot_overflow')
    return slot


class ImageContext:
    def __init__(self, binary, image):
        self.binary = binary
        self.parsed = thin(binary)
        if self.parsed['arch'] != 'arm64' or image['arch'] != 'arm64':
            raise ValueError('unsupported_architecture')
        self.objc = objc.ObjCImage(binary, image, self.parsed, scoped=True)
        self.view = self.objc.view
        self.imports, self.import_gaps = macho_symbols.inventory(binary, 'indirect', int(image['offset'], 16))
        declared, gaps = macho_symbols.inventory(binary, 'symbols', int(image['offset'], 16))
        self.import_gaps += gaps
        self.declared = {row['symbol_index']: row for row in declared}

    def section(self, va, size, name=None, executable=False):
        rows = [s for s in self.parsed['sections'] if int(s['va'], 16) < va + size and va < int(s['va'], 16) + int(s['size'], 16)]
        if len(rows) != 1:
            raise ValueError('ambiguous_or_missing_section')
        s = rows[0]
        if (va < int(s['va'], 16) or va + size > int(s['va'], 16) + int(s['size'], 16)
                or (name and s['name'] != name) or bool(s['protections'] & 4) != executable):
            raise ValueError('unsupported_section')
        offset, _, protections = self.view.mapping(va, size)
        if (s['file_offset'] is None or offset != int(s['file_offset'], 16) + va - int(s['va'], 16)
                or not protections & 1 or bool(protections & 4) != executable):
            raise ValueError('section_mapping_mismatch')
        return s, offset

    def resolve(self, site, raw, target, kind):
        _, offset = self.section(site, 4, executable=True)
        if self.binary[offset:offset+4] != raw or branch(site, raw) != (target, kind):
            raise ValueError('source_bytes_mismatch')
        section, offset = self.section(target, 32, '__objc_stubs', executable=True)
        if target % 4 or (target - int(section['va'], 16)) % 32:
            raise ValueError('unsupported_stub_alignment')
        payload = self.binary[offset:offset+32]
        a, b, c, d, e, *padding = struct.unpack('<8I', payload)
        if e != 0xd61f0200 or padding != [0xd4200020]*3:
            raise ValueError('unsupported_stub_template')
        selector_slot = load_slot(target, a, b, 1)
        import_slot = load_slot(target+8, c, d, 16)
        self.section(selector_slot, 8, '__objc_selrefs')
        if selector_slot % 8 or import_slot % 8:
            raise ValueError('unaligned_pointer_slot')
        self.section(import_slot, 8)
        selector_va = self.objc.target(selector_slot)
        selector = self.view.string(selector_va)
        matches = [r for r in self.imports if r['va'] == hex(import_slot)]
        if self.import_gaps or len(matches) != 1:
            raise ValueError('incomplete_indirect_symbol_evidence')
        symbol = matches[0]
        declaration = self.declared.get(symbol.get('symbol_index'), {})
        relocation = self.objc.relocation(import_slot)
        ordinal = int(declaration.get('n_desc', '0'), 16) >> 8
        ordinal = {254: -2, 255: -1}.get(ordinal, ordinal)
        libraries = [d['path'] for d in self.parsed['loader']['dylibs'] if d['kind'] != 'id']
        library = library_for_ordinal(ordinal, libraries)
        if (symbol['kind'] != 'symbol' or symbol['name'] != '_objc_msgSend'
                or symbol['symbol_kind'] != 'undefined' or symbol['slot_kind'] != 'non_lazy_pointer'
                or symbol['slot_size'] != 8 or declaration.get('name') != '_objc_msgSend'
                or declaration.get('kind') != 'undefined' or int(declaration.get('n_desc', '0xc0'), 16) & 0xc0
                or relocation.get('kind') != 'bind'
                or relocation.get('symbol') != '_objc_msgSend' or relocation.get('import_addend') != 0
                or relocation.get('inline_addend', 0) != 0
                or ('pointer_format' in relocation and (relocation['pointer_format'] not in
                    ('DYLD_CHAINED_PTR_64', 'DYLD_CHAINED_PTR_64_OFFSET') or 'inline_addend' not in relocation))
                or relocation.get('library_ordinal') != ordinal or not library or relocation.get('library') != library
                or relocation.get('resolution') != 'declared_symbol'
                or relocation.get('weak_import') is not False):
            raise ValueError('unverified_message_send_import')
        return {'status': 'verified_static_selector_path', 'source_va': hex(site), 'source_bytes': raw.hex(),
                'branch_kind': kind, 'stub_va': hex(target), 'stub_bytes': payload.hex(),
                'selector_reference_va': hex(selector_slot), 'selector_va': hex(selector_va), 'selector': selector,
                'import_slot_va': hex(import_slot), 'import_symbol': '_objc_msgSend',
                'indirect_symbol': symbol, 'bind_relocation': relocation,
                'runtime_target': 'unknown', 'return_contract': 'unknown', 'receiver_class': 'unknown'}


def build(project, report):
    pins = {p['image_id']: p for p in report['images']}
    images = {i['image_id']: i for i in project.images()}
    rows = []
    remaining = MAX_TOTAL_SITES
    for leadrow in report['leads'][:16]:
        lead = leadrow['lead']; entry = (leadrow.get('function') or {}).get('entry_va')
        row = {'lead_id': lead['id'], 'image_id': lead['image_id'], 'requested_job_id': lead.get('query_job'),
               'entry_va': entry, 'status': 'unavailable', 'sites': [], 'omitted_instructions': 0, 'omitted_sites': 0}
        rows.append(row)
        if not entry or not lead.get('query_job') or evidence.IMPORT_PIN not in pins[lead['image_id']]:
            row['reason'] = 'verified_import_focused_receipt_required'; continue
        try:
            image = images.get(lead['image_id'])
            evidence.open_image(project, image, pins[lead['image_id']])
            binary = metadata.verified_slice(project, image)
            result = evidence.focused_query(project, image, binary, entry, lead['query_job'])
            context = ImageContext(binary, image)
            function = result['data']
            row.update(status='partial', reason='dynamic_dispatch_and_global_coverage_unknown', source_envelope_sha256=identity(result),
                       query_status=result['status'], extent=function['origin']['extent'], pin=pins[lead['image_id']])
            instructions = function['instructions']
            row['omitted_instructions'] = max(0, len(instructions)-MAX_INSTRUCTIONS)
            for ins in instructions[:MAX_INSTRUCTIONS]:
                site = int(ins['addr'], 16); raw = bytes.fromhex(ins['bytes']); decoded = branch(site, raw)
                if decoded is None: continue
                if len(row['sites']) >= MAX_SITES or not remaining:
                    row['omitted_sites'] += 1; continue
                remaining -= 1
                target, kind = decoded
                try: record = context.resolve(site, raw, target, kind)
                except (ValueError, Error) as exc:
                    record = {'status': 'unresolved', 'source_va': hex(site), 'source_bytes': raw.hex(),
                              'branch_kind': kind, 'stub_va': hex(target), 'reason': exc.code if isinstance(exc, Error) else str(exc)}
                if record['status'] == 'verified_static_selector_path':
                    from . import send_register_origins
                    record['register_origins'] = send_register_origins.build(context, function, record)
                row['sites'].append(record)
        except (ValueError, Error) as exc:
            row['reason'] = exc.code if isinstance(exc, Error) else str(exc)
    return {'policy': POLICY, 'status': 'partial', 'scope': 'selected_saved_arm64_receipts',
            'limitations': LIMITATIONS, 'receipts': rows, 'omitted_leads': max(0, len(report['leads'])-16)}


def redact(section, sanitizer):
    clean = sanitizer(section)
    for original, row in zip(section['receipts'], clean['receipts']):
        if original != row:
            # Do not present redacted pointer/selector strings as verified bytes.
            row['sites'] = []
            row['status'] = 'unavailable'
            row['reason'] = 'context_redacted'
    return clean


def summary(section):
    from . import terminal
    if section.get('policy') != POLICY:
        raise Error('objc_send_policy', 'Unsupported selector-stub context policy', 2)
    lines = ['Static selector-stub paths (dynamic target, dispatched return and receiver class unknown):']
    shown = 0
    total = sum(len(row['sites']) for row in section['receipts'])
    for row in section['receipts']:
        for site in row['sites']:
            if shown >= 4: break
            text = (site['source_va'] + ' -> ' + site['stub_va'] + ' ' +
                    (site['selector'] + ' via _objc_msgSend' if site['status'] == 'verified_static_selector_path'
                     else 'unresolved: ' + site['reason']))
            origins = site.get('register_origins', {})
            if origins.get('status') == 'verified_conditional_register_origins':
                origin = origins['receiver_register']['origin']
                text += ' ; x0 <- ' + ('entry ' + origin['register'] if origin['kind'] == 'entry_register' else origin['value'])
            elif origins:
                text += ' ; x0 origin unavailable: ' + origins.get('reason', 'unknown')
            lines.append(terminal.safe(text[:200]) + (' [clipped]' if len(text)>200 else ''))
            shown += 1
    lines.append(f'Sites shown: {shown}; omitted here: {total-shown}. No supported match does not mean no sends.')
    lines.append('Original engine flow gaps are retained; these are additional static facts, not dispatch resolution.')
    return '\n'.join(lines)+'\n'
