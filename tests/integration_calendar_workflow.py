#!/usr/bin/env python3
"""Rehearse a Calendar evidence handoff using only the built-in owned fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

from macscope.schema import validate_envelope, validate_function
from macscope.storage import atomic


SOURCE = Path(__file__).resolve().parents[1] / 'fixture' / 'calendar'
XIB = SOURCE / 'CalendarWiring.xib'
MAIN = 'Contents/MacOS/OwnedCalendar'
KIT = 'Contents/Frameworks/OwnedCalendarKit.framework/Versions/A/OwnedCalendarKit'
RESOURCE_DIRECTORY = 'Contents/Resources/Calendar'
RESOURCE = RESOURCE_DIRECTORY + '/RangePreferences.json'
NIB = RESOURCE_DIRECTORY + '/Calendar.nib'
STRINGS = RESOURCE_DIRECTORY + '/Calendar.strings'
TITLE_KEY = 'aA0-ab-002.title'
LEAD = 'OwnedCalendar.RangePreferences'
SELECTOR = 'calendarDayDuration:'
METHOD = '-[OwnedCalendarController calendarDayDuration:]'
DURATION = '_owned_calendar_day_seconds'
MIDNIGHT = '_owned_calendar_midnight'
ROUTE = '_owned_calendar_route'
TRUST = '--experimental-trusted-input'


def cli(*args, expected=(0, 6)):
    result = subprocess.run([sys.executable, '-m', 'macscope', *map(str, args), '--json'],
                            capture_output=True, timeout=420)
    assert result.returncode in expected, (args, result.returncode, result.stdout, result.stderr)
    envelope = json.loads(result.stdout)
    validate_envelope(envelope)
    return envelope


def ibtool(*args):
    result = subprocess.run(['/usr/bin/xcrun', 'ibtool', *map(str, args)], capture_output=True, timeout=60)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout


def build_fixture(app):
    for path in (MAIN, KIT, RESOURCE):
        (app / path).parent.mkdir(parents=True, exist_ok=True)
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
        'CFBundleExecutable': 'OwnedCalendar', 'CFBundleIdentifier': 'local.macscope.owned-calendar',
        'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': '1.0',
    }))
    shutil.copyfile(SOURCE / 'RangePreferences.json', app / RESOURCE)
    kit = app / KIT
    (kit.parents[1] / 'Current').symlink_to('A')
    (kit.parents[2] / kit.name).symlink_to('Versions/Current/OwnedCalendarKit')
    clang = ['/usr/bin/xcrun', 'clang', '-arch', 'arm64', '-O1', '-fno-optimize-sibling-calls']
    subprocess.run([*clang, '-dynamiclib', '-install_name', '@rpath/' + KIT.split('Frameworks/', 1)[1],
                    SOURCE / 'OwnedCalendarKit.c', '-o', kit], check=True, timeout=60)
    subprocess.run([*clang, '-framework', 'Foundation', '-Wl,-rpath,@executable_path/../Frameworks',
                    SOURCE / 'OwnedCalendar.m', kit, '-o', app / MAIN], check=True, timeout=60)
    ibtool('--compile', app / NIB, XIB)
    ibtool('--generate-strings-file', app / STRINGS, XIB)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_addresses(path, names):
    rows = subprocess.check_output(['/usr/bin/xcrun', 'nm', '-n', path], text=True, timeout=30)
    addresses = {}
    for line in rows.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and parts[2] in names:
            addresses[parts[2]] = hex(int(parts[0], 16))
    assert addresses.keys() == set(names), addresses
    return addresses


def capture_resources(app, inputs):
    inventory = cli('resources', 'list', app, '--under', RESOURCE_DIRECTORY, expected=(0,))
    records = {row['relative_path']: row for row in inventory['data']}
    assert records.keys() == {RESOURCE, NIB, STRINGS}
    for path, row in records.items():
        assert row['sha256'] == inputs[path] and row['size'] == (app / path).stat().st_size

    args = ('resources', 'nib', app, '--file', NIB)
    nib = cli(*args, expected=(0,))
    assert nib['data']['sha256'] == inputs[NIB]
    assert nib['coverage']['known_total'] == len(nib['data']['records']) == 4
    first = cli(*args, '--limit', '2', expected=(0,))
    cursor = first['coverage']['next_cursor']
    assert cursor and first['coverage']['truncation_reason'] == 'page_limit'
    second = cli(*args, '--cursor', cursor, expected=(0,))
    assert first['data']['records'] + second['data']['records'] == nib['data']['records']

    localized = cli('resources', 'strings', app, '--file', STRINGS, '--key', TITLE_KEY, expected=(0,))
    assert localized['data']['sha256'] == inputs[STRINGS]
    oracle = plistlib.loads(ibtool('--connections', '--objects', '--localizable-strings', XIB))
    declared = oracle['com.apple.ibtool.document.connections']
    source_objects = oracle['com.apple.ibtool.document.objects']
    source_titles = oracle['com.apple.ibtool.document.localizable-strings']['aA0-ab-002']
    action, = (row for row in nib['data']['records'] if row['kind'] == 'action')
    outlet, = (row for row in nib['data']['records'] if row['kind'] == 'outlet')
    labels = {row['field']: row for row in nib['data']['records'] if row['kind'] == 'button_label'}
    assert action['label'] == declared['aA0-ab-003']['label'] == SELECTOR
    assert outlet['label'] == declared['aA0-ab-004']['label'] == 'weekButton'
    assert action['source'] == outlet['destination'] and action['destination'] == outlet['source']
    assert action['destination']['declared_class'] == source_objects['-2']['custom-class']
    assert action['source']['archive_class'] == source_objects['aA0-ab-001']['class']
    for archived, authored in (('NSContents', 'title'), ('NSAlternateContents', 'alternateTitle')):
        assert labels[archived]['label'] == source_titles[authored]
        assert labels[archived]['control'] == action['source']
    assert localized['data']['records'] == [{'key': TITLE_KEY, 'value': source_titles['title']}]
    print('Owned interface declarations and localization verified against ibtool', flush=True)
    interface = {'authority': 'compiled_owned_fixture', 'inventory': [records[NIB], records[STRINGS]],
                 'nib': nib, 'localization': localized}
    return records[RESOURCE], interface


def prepare(project, app):
    build_fixture(app)
    inputs = {path: digest(app / path) for path in (MAIN, KIT, RESOURCE, NIB, STRINGS)}
    marker, *durations = subprocess.check_output([app / MAIN], text=True, timeout=30).splitlines()
    assert marker == LEAD and durations == ['86400', '82800', '86400'], (marker, durations)
    assert json.loads((app / RESOURCE).read_bytes())['scenario'] == marker
    entries = native_addresses(app / MAIN, (METHOD, ROUTE, '_main'))
    entries.update(native_addresses(app / KIT, (DURATION, MIDNIGHT)))
    resource, interface = capture_resources(app, inputs)
    cli('project', 'create', project, expected=(0,))
    imported = cli('import', app, '--project', project, '--arch', 'arm64',
                   '--include-images', KIT, TRUST, expected=(0,))
    assert [row['bundle_image']['relative_path'] for row in imported['data']] == [MAIN, KIT]
    images = {}
    for row in imported['data']:
        path = row['bundle_image']['relative_path']
        scope = ('--project', project, '--image', row['image_id'])
        analysis = cli('analyze', *scope, TRUST)
        assert analysis['data']['function_count'] > 0
        image = cli('headers', *scope)['data']
        assert image['arch'] == 'arm64' and image['sha256'] == image['artifact_sha256'] == inputs[path]
        images[path] = {key: image[key] for key in ('image_id', 'arch', 'sha256', 'artifact_sha256', 'uuid')}
        images[path]['analysis_id'] = analysis['analysis_id']
    recovered = cli('decompile', '--project', project, '--image', images[KIT]['image_id'],
                    '--address', entries[DURATION], '--fresh', '--recover-callee-parameters', TRUST)
    assert recovered['data']['origin']['callee_parameter_recovery']['status'] == 'applied'
    assert {path: digest(app / path) for path in inputs} == inputs
    print('Owned app oracle and both full Ghidra analyses verified', flush=True)
    return {'entries': entries, 'images': images, 'resource': resource, 'interface': interface,
            'durations_seconds': [int(value) for value in durations],
            'recovered_job': recovered['data']['origin']['job_id']}


def function_evidence(scope, image, entry):
    selected = cli('functions', 'show', *scope, '--address', entry)
    row = selected['data']
    validate_function(row)
    assert selected['analysis_id'] == image['analysis_id'] and row['entry_va'] == entry
    selection = (*scope, '--function-id', row['function_id'])
    assembly = cli('disasm', *selection)
    pseudocode = cli('decompile', *selection)
    refs = cli('xrefs', *selection)
    trace = cli('calls', *selection, '--depth', '1', '--max-edges', '16')
    assert all(result['analysis_id'] == image['analysis_id'] for result in (assembly, pseudocode, refs, trace))
    code = pseudocode['data']['pseudocode']
    spans = pseudocode['data']['address_spans']
    assert code and spans and trace['data']['depth'] == 1
    instructions = assembly['data']['instructions']
    raw = ''.join(ins['bytes'] for ins in instructions)
    file_bytes = cli('bytes', *scope, '--address', entry, '--length', len(raw) // 2)['data']['bytes']
    assert raw == file_bytes and instructions[0]['addr'] == entry
    assert hashlib.sha256(bytes.fromhex(raw)).hexdigest() == row['instruction_bytes_sha256']
    starts = {ins['addr'] for ins in instructions}
    for span in spans:
        assert span['text_end'] > span['text_start']
        assert all(start in starts for start, _ in span['ranges'])
    facets = {'disassembly': assembly, 'pseudocode': pseudocode, 'references': refs, 'trace': trace}
    return {'function_id': row['function_id'], 'entry_va': entry, 'image_id': row['image_id'],
            'analysis_id': row['analysis_id'], 'arch': row['arch'], 'instructions': instructions,
            'pseudocode': code, 'address_spans': spans, 'references': refs['data'], 'trace': trace['data'],
            'coverage': {name: result['coverage'] for name, result in facets.items()}}


def correlate_interface(interface, method, handler, image):
    nib, localization = (interface[key] for key in ('nib', 'localization'))
    hashes = {row['relative_path']: row['sha256'] for row in interface['inventory']}
    for capture, command, path in ((nib, 'resources nib', NIB), (localization, 'resources strings', STRINGS)):
        validate_envelope(capture)
        assert capture['command'] == command and capture['data']['relative_path'] == path
        assert capture['status'] == capture['coverage']['status'] == 'complete'
        assert capture['data']['sha256'] == hashes[path]
    action, = (row for row in nib['data']['records'] if row['kind'] == 'action' and row['label'] == method['name'])
    outlet, = (row for row in nib['data']['records'] if row['kind'] == 'outlet' and row['destination'] == action['source'])
    title, = (row for row in nib['data']['records'] if row['kind'] == 'button_label'
              and row['field'] == 'NSContents' and row['control'] == action['source'])
    label, = localization['data']['records']
    assert title['label'] == label['value'] and label['key'] == TITLE_KEY
    assert action['destination']['declared_class'] == method['class_name']
    assert method['image_id'] == handler['image_id'] == image['image_id']
    assert method['implementation_va'] == handler['entry_va'] and handler['analysis_id'] == image['analysis_id']
    return dict(interface, match={
        'basis': 'archived receiver class and selector match an exact Objective-C method entry',
        'action_object_index': action['object_index'], 'outlet_object_index': outlet['object_index'],
        'control_object_index': action['source']['object_index'], 'title_key': label['key'],
        'image_id': handler['image_id'], 'analysis_id': handler['analysis_id'], 'arch': handler['arch'],
        'artifact_sha256': image['artifact_sha256'], 'slice_sha256': image['sha256'],
        'function_id': handler['function_id'], 'entry_va': handler['entry_va'],
    })


def handoff(project, context):
    images, entries = context['images'], context['entries']
    main, kit = (('--project', project, '--image', images[path]['image_id']) for path in (MAIN, KIT))
    method, = cli('objc', 'methods', *main, '--name-contains', SELECTOR)['data']
    assert method['name'] == SELECTOR and method['implementation_va'] == entries[METHOD]
    string, = cli('search', LEAD, *main, '--in', 'strings')['data']
    assert string['context'] == LEAD and string['va'] is not None
    string_refs = cli('xrefs', *main, '--to', string['va'])['data']['references']
    main_body = cli('functions', 'show', *main, '--address', entries['_main'])['data']
    main_starts = {ins['addr'] for ins in main_body['instructions']}
    assert any(ref['from'] in main_starts for ref in string_refs)

    functions = {name: function_evidence(scope, images[path], entries[name])
                 for path, scope, names in ((MAIN, main, (METHOD, ROUTE)), (KIT, kit, (DURATION, MIDNIGHT)))
                 for name in names}
    handler, dispatch, duration, midnight = (functions[key] for key in (METHOD, ROUTE, DURATION, MIDNIGHT))
    computed, = (edge for edge in dispatch['trace']['edges'] if 'COMPUTED_CALL' in edge['type'])
    assert computed['resolution'] == 'indirect_or_inferred' and computed['callee_function_id'] is None
    assert computed['reported_target'] is None and SELECTOR in dispatch['pseudocode']
    assert any(edge['caller_function_id'] == main_body['function_id']
               and edge['callee_function_id'] == dispatch['function_id'] for edge in dispatch['trace']['edges'])
    local_call, = (edge for edge in handler['trace']['edges']
                   if edge['caller_function_id'] == handler['function_id'] and edge['resolution'] == 'direct')
    stub = cli('functions', 'show', *main, '--function-id', local_call['callee_function_id'])['data']
    binding, = (row for row in cli('fixups', *main, '--kind', 'bind')['data']['records']
                if row['symbol'] == DURATION)
    assert stub['is_thunk'] and stub['thunk_target']['library'] == binding['library']
    stub_refs = cli('xrefs', *main, '--function-id', stub['function_id'])['data']['from_body']
    assert any(row['to'] == binding['va'] and row['type'] == 'READ' for row in stub_refs)
    exported, = cli('exports', *kit, '--source', 'dyld', '--name-contains', DURATION)['data']['records']
    assert exported['name'] == binding['symbol'] and exported['va'] == duration['entry_va']
    calls = [edge for edge in duration['trace']['edges']
             if edge['resolution'] == 'direct' and edge['callee_function_id'] == midnight['function_id']]
    assert len(calls) == 2
    for key, function, column in (('from_body', duration, 'to'), ('to_entry', midnight, 'from')):
        assert {ref['from'] for ref in function['references'][key] if ref['type'] == 'UNCONDITIONAL_CALL'
                and ref[column] is not None} == {edge['callsite'] for edge in calls}

    # Receipt replay has no engine fallback, even if a saved receipt disappears.
    unavailable = project / 'unavailable-engine'
    assert not unavailable.exists() and not unavailable.is_symlink()
    resumed = cli('jobs', 'resume', context['recovered_job'], '--project', project,
                  '--ghidra', unavailable, TRUST)
    recovered = resumed['data']
    proof = recovered['origin']['callee_parameter_recovery']
    assert recovered['reused_restart'] and resumed['analysis_id'] == images[KIT]['analysis_id']
    assert recovered['function_id'] == duration['function_id'] and proof['status'] == 'applied'
    applied, = proof['applied']
    assert [p['register'] for p in applied['parameters']] == ['x0', 'x1', 'x2', 'x3']
    rendered_calls = re.findall(r'_owned_calendar_midnight\(([^()\n]*)\)', recovered['pseudocode'])
    assert len(rendered_calls) == 2 and all(len(call.split(',')) == 4 for call in rendered_calls)
    missing = cli('functions', 'show', *main, '--address', '0x1', expected=(2,))
    assert missing['error']['code'] == 'function_selector' and missing['error']['partial_results'] == []
    report = {
        'schema': 'macscope-owned-calendar-handoff/1', 'images': images, 'functions': functions,
        'leads': {'selector': method, 'string': string, 'string_references': string_refs,
                  'resource': context['resource']},
        'declared_linkage': {'local_call': local_call, 'thunk_target': stub['thunk_target'],
                             'binding': binding, 'framework_export': exported},
        'selected_recovery': {'origin': proof, 'pseudocode': recovered['pseudocode'],
                              'address_spans': recovered['address_spans']},
        'missing_control': {'entry_va': '0x1', 'image_id': images[MAIN]['image_id'], 'error': missing['error']},
        'observed': {'authority': 'executed owned fixture', 'durations_seconds': context['durations_seconds']},
        'static_inference': 'The declared date-range path computes two local midnights using the offset change.',
        'open_questions': ['The computed Objective-C dispatch target remains unresolved in the static trace.'],
    }
    if 'interface' in context:
        report['schema'] = 'macscope-owned-calendar-handoff/2'
        report['interface'] = correlate_interface(context['interface'], method, handler, images[MAIN])
    return report


def verify_selected_handoff(project, context, control):
    images = context['images']
    pins = [{**{key: image[key] for key in ('image_id', 'arch', 'artifact_sha256', 'analysis_id')},
             'slice_sha256': image['sha256']} for image in images.values()]
    leads = [
        {'id': 'selector', 'image_id': images[MAIN]['image_id'], 'kind': 'objc_selector', 'value': SELECTOR},
        {'id': 'string', 'image_id': images[MAIN]['image_id'], 'kind': 'string', 'value': LEAD},
        {'id': 'duration', 'image_id': images[KIT]['image_id'], 'kind': 'name', 'value': DURATION,
         'query_job': context['recovered_job']},
        {'id': 'missing', 'image_id': images[MAIN]['image_id'], 'kind': 'address', 'value': '0x1'},
    ]
    with tempfile.TemporaryDirectory(dir=project.parent) as directory:
        manifest = Path(directory) / 'leads.json'
        atomic(manifest, json.dumps({'schema': 'macscope-evidence-leads/1', 'images': pins, 'leads': leads}).encode())
        result = cli('evidence', '--project', project, '--leads', manifest, '--link-imports', expected=(6,))
    selector, string, duration, missing = result['data']['leads']
    assert selector['function']['function_id'] == control['functions'][METHOD]['function_id']
    assert string['function']['entry_va'] == context['entries']['_main']
    assert duration['function']['pseudocode'] == control['functions'][DURATION]['pseudocode']
    assert duration['query']['pseudocode'] == control['selected_recovery']['pseudocode']
    assert missing['reason'] == 'lead_not_found' and missing['function'] is None
    link, = selector['declared_imports']['links']
    expected = control['declared_linkage']
    assert link['status'] == 'declared_match' and link['callsite'] == expected['local_call']['callsite']
    assert link['binding'] == expected['binding'] and link['export'] == expected['framework_export']
    assert link['target']['function_id'] == duration['function']['function_id']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--replay', action='store_true', help='Verify the handoff again without a new worker')
    args = parser.parse_args()
    root = args.directory.resolve()
    os.umask(0o077)
    project, app = root / 'Calendar Project', root / 'inputs' / 'Owned Calendar.app'
    context_file, report = root / 'context.json', root / 'calendar-handoff.json'
    if args.replay:
        context = json.loads(context_file.read_bytes())
    else:
        root.mkdir(mode=0o700)
        context = prepare(project, app)
        atomic(context_file, json.dumps(context, sort_keys=True).encode() + b'\n')
    before = sorted((project / 'jobs').iterdir())
    evidence = handoff(project, context)
    verify_selected_handoff(project, context, evidence)
    assert sorted((project / 'jobs').iterdir()) == before
    content = json.dumps(evidence, indent=2, sort_keys=True).encode() + b'\n'
    assert str(root).encode() not in content
    if args.replay:
        assert content == report.read_bytes(), 'Regenerated evidence differs from the saved handoff'
    else:
        atomic(report, content)
    assert report.stat().st_mode & 0o077 == 0
    print(f'{report}\nSHA-256 {digest(report)}')


if __name__ == '__main__':
    main()
