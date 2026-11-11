#!/usr/bin/env python3
"""Owned resource-first, no-analysis Calendar investigation, one slice at a time.

Run on macOS with an existing Ghidra/JDK and PYTHONPATH=src. Never launches
an app or loads a nib. An existing capture is replayed instead of rebuilt.
Generated resources, receipts, binaries and reports stay in a new private
output directory, outside Git. --replay needs neither the app nor Ghidra.
"""
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

from macscope import focused, html_export, resource_nib, resource_strings, storage
from macscope.schema import validate_envelope
import resource_first_oracle

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'fixture/calendar'
CLASS = 'OwnedCalendarResourceController'
ACTION = 'changeAdvancedState:'
ENTRIES = {'load': f'-[{CLASS} awakeFromNib]', 'change': f'-[{CLASS} {ACTION}]',
           'dispatch': '_owned_calendar_resource_dispatch'}
MAIN = 'Contents/MacOS/OwnedResourceCalendar'
NIB = 'Contents/Resources/Calendar/ResourceFirst.nib'
STRINGS = 'Contents/Resources/Calendar/ResourceFirst.strings'
TRUST = '--experimental-trusted-input'
SCHEMA = 'macscope-owned-resource-first/1'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value, *, force=False):
    storage.atomic(path, storage.canonical(value) + b'\n', force=force)


def invoke(root, label, *words, expected=(0, 6), env=None):
    # This harness is deliberately incapable of whole-image autoanalysis.
    assert words and words[0] != 'analyze', 'Whole-image analysis is forbidden in this regression'
    command = [sys.executable, '-m', 'macscope', *map(str, words), '--json']
    result = subprocess.run(command, capture_output=True, timeout=240, env=env)
    storage.atomic(root / (label + '.json'), result.stdout, force=True)
    storage.atomic(root / (label + '.stderr'), result.stderr, force=True)
    assert result.returncode in expected, (label, result.returncode, result.stdout, result.stderr)
    response = json.loads(result.stdout)
    validate_envelope(response)
    return response


def apple(root, label, *words):
    result = subprocess.run(['/usr/bin/xcrun', *map(str, words)], capture_output=True, timeout=90)
    storage.atomic(root / (label + '.txt'), result.stdout)
    storage.atomic(root / (label + '.stderr'), result.stderr, force=True)
    assert result.returncode == 0, (label, result.stdout, result.stderr)
    return result.stdout


def build(root, arch):
    app = root / 'Owned Resource Calendar.app'
    binary = app / MAIN
    binary.parent.mkdir(parents=True)
    (app / NIB).parent.mkdir(parents=True)
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
        'CFBundleExecutable': binary.name, 'CFBundleIdentifier': 'local.macscope.owned-resource-calendar',
        'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': '1.0'}))
    # Keep ordinary tail calls and the unresolved caller-supplied tail dispatch.
    # No debug info, app launch, library loading, or runtime oracle is needed.
    apple(root, 'build', 'clang', '-arch', arch, '-mmacosx-version-min=13.0', '-O1',
          '-fno-objc-arc', '-fno-inline', '-framework', 'AppKit', '-Wl,-fixup_chains',
          SOURCE / 'ResourceFirstCalendar.m', '-o', binary)
    xib = SOURCE / 'ResourceFirstCalendarWiring.xib'
    apple(root, 'compile-nib', 'ibtool', '--compile', app / NIB, xib)
    apple(root, 'generate-strings', 'ibtool', '--generate-strings-file', app / STRINGS, xib)
    return app


def one(rows, predicate):
    selected = [row for row in rows if predicate(row)]
    assert len(selected) == 1, selected
    return selected[0]


def wiring(nib):
    validate_envelope(nib)
    assert nib['command'] == 'resources nib' and nib['data']['relative_path'] == NIB
    assert nib['status'] == nib['coverage']['status'] == 'complete'
    rows = nib['data']['records']
    action = one(rows, lambda r: r['kind'] == 'action' and r['label'] == ACTION)
    toggle = one(rows, lambda r: r['kind'] == 'outlet' and r['label'] == 'advancedToggle')
    row = one(rows, lambda r: r['kind'] == 'outlet' and r['label'] == 'advancedRow')
    assert action['source'] == toggle['destination']
    assert action['destination'] == toggle['source'] == row['source']
    assert action['destination']['declared_class'] == CLASS
    assert action['source']['archive_class'] == 'NSButton'
    assert row['destination']['archive_class'] == 'NSCustomView'
    assert row['destination'] != action['source']
    return {'action': action, 'toggle_outlet': toggle, 'row_outlet': row}


def resource_capture(root, app):
    captures = {
        'inventory': invoke(root, 'resources', 'resources', 'list', app,
                            '--under', 'Contents/Resources/Calendar', expected=(0,)),
        'nib': invoke(root, 'nib', 'resources', 'nib', app, '--file', NIB, expected=(0,)),
        'strings': invoke(root, 'strings', 'resources', 'strings', app, '--file', STRINGS, expected=(0,)),
    }
    match = wiring(captures['nib'])
    oracle = plistlib.loads(apple(root, 'ibtool-oracle', 'ibtool', '--connections', '--objects',
                                 '--localizable-strings', SOURCE / 'ResourceFirstCalendarWiring.xib'))
    connections = list(oracle['com.apple.ibtool.document.connections'].values())
    objects = oracle['com.apple.ibtool.document.objects']
    assert objects['-2']['custom-class'] == CLASS
    for label, target, kind in ((ACTION, 'rC0-ab-002', 'IBCocoaActionConnection'),
                                ('advancedToggle', 'rC0-ab-002', 'IBCocoaOutletConnection'),
                                ('advancedRow', 'rC0-ab-001', 'IBCocoaOutletConnection')):
        declared = one(connections, lambda r: r.get('label') == label)
        # ibtool represents action connections owner -> control, while the
        # compiled nib exposes sender -> receiver. Normalize deliberately.
        assert declared['type'] == kind and declared['source-id'] == '-2'
        assert declared['destination-id'] == target, declared
    assert objects['rC0-ab-001']['class'] == 'IBNSCustomView'
    assert objects['rC0-ab-001']['className'] == 'NSView'
    assert objects['rC0-ab-002']['class'] == 'NSButton'
    # A saved raw copy allows parser replay without the external app. It is not
    # a fake runnable bundle, and no archived object is instantiated.
    saved = root / 'saved-resources'
    saved.mkdir()
    files = {}
    for relative in (NIB, STRINGS):
        path = saved / Path(relative).name
        shutil.copyfile(app / relative, path)
        files[relative] = {'file': path.name, 'sha256': digest(path), 'size': path.stat().st_size}
        assert captures['nib' if relative == NIB else 'strings']['data']['sha256'] == digest(path)
    return {'captures': captures, 'files': files, 'wiring': match,
            'apple_connections': connections, 'apple_objects': objects,
            'xib_sha256': digest(SOURCE / 'ResourceFirstCalendarWiring.xib')}


def verify_saved_resources(root, resource):
    for relative, record in resource['files'].items():
        # Only the two harness-authored filenames may be replayed.
        assert relative in (NIB, STRINGS) and record['file'] == Path(relative).name
        path = root / 'saved-resources' / record['file']
        assert digest(path) == record['sha256'] and path.stat().st_size == record['size']
        capture = resource['captures']['nib' if relative == NIB else 'strings']
        validate_envelope(capture)
        assert capture['status'] == capture['coverage']['status'] == 'complete'
        assert capture['data']['relative_path'] == relative
        assert capture['data']['sha256'] == record['sha256'] and capture['data']['size'] == record['size']
    raw = (root / 'saved-resources' / Path(NIB).name).read_bytes()
    nodes, _ = resource_nib.parse(raw)
    connections, gaps = resource_nib.connections(nodes)
    labels, label_gaps = resource_nib.button_labels(nodes)
    assert not gaps and not label_gaps
    captured = resource['captures']['nib']['data']['records']
    assert sorted(connections + labels, key=storage.canonical) == sorted(captured, key=storage.canonical)
    assert wiring(resource['captures']['nib']) == resource['wiring']
    # String parser replay is independently checked against the saved capture.
    values, _, _ = resource_strings.parse((root / 'saved-resources' / Path(STRINGS).name).read_bytes())
    assert [{'key': key, 'value': value} for key, value in sorted(values.items())] == resource['captures']['strings']['data']['records']


def selected_apple_instructions(text, start, end):
    rows = []
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-fA-F]{8,16})\s+(.+)$', line)
        if match and start <= int(match[1], 16) < end:
            rows.append({'address': hex(int(match[1], 16)), 'assembly': match[2].strip()})
    assert rows, (hex(start), hex(end))
    return rows


def prepare(root, arch):
    root.mkdir(mode=0o700)
    app = build(root, arch)
    binary = app / MAIN
    inputs = {path: digest(app / path) for path in (MAIN, NIB, STRINGS)}
    # Resource declarations are selected before any binary/engine inquiry.
    resources = resource_capture(root, app)
    nm = apple(root, 'apple-nm', 'nm', '-arch', arch, '-n', binary).decode()
    symbols = {}
    for line in nm.splitlines():
        fields = line.split(maxsplit=2)
        if len(fields) == 3 and fields[2] in ENTRIES.values():
            symbols[fields[2]] = hex(int(fields[0], 16))
    assert symbols.keys() == set(ENTRIES.values()), symbols
    native = apple(root, 'apple-disassembly', 'otool', '-arch', arch, '-tvV', binary).decode()
    native_objc = apple(root, 'apple-objc', 'dyld_info', '-arch', arch, '-objc', binary).decode()
    apple(root, 'apple-fixups', 'dyld_info', '-arch', arch, '-fixups', binary)
    project = root / 'project'
    invoke(root, 'create', 'project', 'create', project, expected=(0,))
    imported = invoke(root, 'import', 'import', app, '--project', project, '--arch', arch,
                      TRUST, '--timeout', '180', expected=(0,))
    image_id = imported['data'][0]['image_id']
    scope = ('--project', project, '--image', image_id, '--arch', arch)
    captures = {'classes': invoke(root, 'classes', 'objc', 'classes', *scope,
                                  '--name-contains', CLASS, expected=(0,))}
    owner = one(captures['classes']['data'], lambda r: r['name'] == CLASS)
    assert owner['arch'] == arch and owner['image_id'] == image_id
    slot = owner['list_entry_va']
    captures['class_pointer'] = invoke(root, 'class-pointer', 'fixups', *scope, '--address', slot, expected=(0,))
    pointer = one(captures['class_pointer']['data']['records'], lambda r: r['va'] == slot)
    assert pointer['kind'] == 'rebase' and pointer['target_va'] == owner['class_va']
    captures['methods'] = invoke(root, 'methods', 'objc', 'methods', *scope, '--class-slot', slot, expected=(0,))
    captures['ivars'] = invoke(root, 'ivars', 'objc', 'ivars', *scope, expected=(0,))
    captures['selectors'] = invoke(root, 'selectors', 'objc', 'selectors', *scope, expected=(0,))
    for selector in ('awakeFromNib', ACTION):
        method = one(captures['methods']['data'], lambda r: r['name'] == selector and r['class_name'] == CLASS)
        symbol = f'-[{CLASS} {selector}]'
        assert method['implementation_va'] == symbols[symbol]
        # Independent Apple metadata listing of the exact implementation.
        assert re.search(r'0x0*' + symbols[symbol][2:] + r'\s+-\[' + re.escape(CLASS + ' ' + selector) + r'\]',
                         native_objc, re.IGNORECASE), (method, native_objc)
    for name in ('advancedRow', 'advancedToggle', '_configuredState'):
        ivar = one(captures['ivars']['data'], lambda r: r['class_name'] == CLASS and r['name'] == name)
        assert ivar['offset_status'] == 'recorded' and ivar['size_bytes'] == 8
    for name in ('setHidden:', 'state', ACTION):
        assert any(r['name'] == name and r['origin'] == 'selector_reference' for r in captures['selectors']['data'])
    saved = storage.Project(project)
    image = saved.select(image=image_id, arch=arch)
    assert not image.get('active_analysis')
    pin = {key: image[key] for key in ('image_id', 'arch', 'artifact_sha256')}
    pin.update(slice_sha256=image['sha256'], import_program_sha256=image['engine_baseline_sha256'])
    reports, extents, apple_selected = {}, {}, {}
    for name, symbol in ENTRIES.items():
        entry = symbols[symbol]
        # Confirm exact linker entry before asking the selected worker.
        extent, _ = focused.select(saved, image, entry)
        extents[name] = extent
        response = invoke(root, 'focused-' + name, 'decompile', *scope, '--address', entry,
                          '--from-import', TRUST, '--timeout', '150', '--function-timeout', '30')
        function = response['data']
        assert response['analysis_id'] is None and function['entry_va'] == entry
        assert function['origin']['extent']['program_sha256'] == pin['import_program_sha256']
        assert function['pseudocode'] and not function['pseudocode_truncated']
        payload = bytes.fromhex(''.join(row['bytes'] for row in function['instructions']))
        assert hashlib.sha256(payload).hexdigest() == function['instruction_bytes_sha256']
        # Public bytes corroboration, in the explicit same image and slice.
        byte_capture = invoke(root, 'bytes-' + name, 'bytes', *scope, '--address', entry,
                              '--length', len(payload), expected=(0,))
        assert bytes.fromhex(byte_capture['data']['bytes']) == payload
        # Preserve all independently captured Apple rows within the exact linker
        # extent, including padding the decompiler might omit.
        apple_selected[name] = selected_apple_instructions(native, int(entry, 16), int(extent['end_va_exclusive'], 16))
        starts = {row['address'] for row in apple_selected[name]}
        assert all(row['addr'] in starts for row in function['instructions'])
        reports[name] = response
    dispatch = reports['dispatch']['data']
    assert reports['dispatch']['status'] == 'partial' and dispatch.get('control_flow_gaps')
    assert any(g['evidence']['classification']['kind'] == 'unclassified' for g in dispatch['control_flow_gaps'])
    byte_oracle = resource_first_oracle.verify(
        binary.read_bytes(), image, reports, captures['ivars']['data'], captures['selectors']['data'], apple_selected)
    leads = [{'id': name, 'image_id': image_id, 'kind': 'address', 'value': row['data']['entry_va'],
              'query_job': row['data']['origin']['job_id']} for name, row in reports.items()]
    leads.append({'id': 'nib-action', 'image_id': image_id, 'kind': 'objc_selector', 'value': ACTION,
                  'class_name': CLASS, 'class_slot': slot, 'query_job': reports['change']['data']['origin']['job_id']})
    leads.append({'id': 'class-pointer', 'image_id': image_id, 'kind': 'fixup', 'value': slot})
    manifest = {'schema': 'macscope-evidence-leads/1', 'images': [pin], 'leads': leads}
    save(root / 'leads.json', manifest)
    assert {path: digest(app / path) for path in inputs} == inputs
    assert saved.select(image=image_id, arch=arch)['engine_baseline_sha256'] == pin['import_program_sha256']
    context = {'schema': SCHEMA, 'arch': arch, 'inputs': inputs, 'resources': resources,
               'metadata': captures, 'pin': pin, 'extents': extents, 'apple_instructions': apple_selected,
               'byte_oracle': byte_oracle, 'queries': reports, 'manifest_sha256': storage.identity(manifest),
               'fixture_source_sha256': digest(SOURCE / 'ResourceFirstCalendar.m')}
    save(root / 'context.json', context)
    return context


def render(report):
    view = html_export.Report('Owned resource-first Calendar evidence', 'Static selected investigation',
                              [('Architecture', report['pin']['arch']), ('Slice SHA-256', report['pin']['slice_sha256']),
                               ('Imported Program SHA-256', report['pin']['import_program_sha256'])],
                              {'status': 'partial'})
    for key in ('facts', 'bounded_inferences', 'unknowns', 'coverage_by_step', 'resources', 'metadata',
                'apple_instructions', 'byte_oracle', 'source_identity'):
        view.evidence(key.replace('_', ' ').capitalize(), report[key])
    for index, lead in enumerate(report['selected_evidence']['data']['leads']):
        if lead['function'] is not None:
            view.function(index, lead['function'])
    view.evidence('Pinned selected evidence', report['selected_evidence'])
    return view.finish()


def replay(root, context):
    assert context['schema'] == SCHEMA
    verify_saved_resources(root, context['resources'])
    project = root / 'project'
    pin = context['pin']
    saved = storage.Project(project)
    image = saved.select(image=pin['image_id'], arch=pin['arch'])
    assert not image.get('active_analysis')
    assert image['engine_baseline_sha256'] == pin['import_program_sha256']
    assert image['sha256'] == pin['slice_sha256'] and image['artifact_sha256'] == pin['artifact_sha256']
    assert storage.identity(storage.strict_json((root / 'leads.json').read_bytes())) == context['manifest_sha256']
    from macscope.metadata import verified_slice
    assert resource_first_oracle.verify(verified_slice(saved, image), image, context['queries'],
        context['metadata']['ivars']['data'], context['metadata']['selectors']['data'],
        context['apple_instructions']) == context['byte_oracle']
    before_jobs = sorted((project / 'jobs').iterdir())
    offline = dict(os.environ, MACSCOPE_GHIDRA='/nonexistent-resource-first-engine',
                   MACSCOPE_JAVA_HOME='/nonexistent-resource-first-java')
    scope = ('--project', project, '--image', pin['image_id'], '--arch', pin['arch'])
    slot = context['resources']['wiring']['action']['destination']['declared_class']
    assert slot == CLASS
    owner = one(context['metadata']['classes']['data'], lambda r: r['name'] == CLASS)
    queries = {
        'classes': ('objc', 'classes', *scope, '--name-contains', CLASS),
        'class_pointer': ('fixups', *scope, '--address', owner['list_entry_va']),
        'methods': ('objc', 'methods', *scope, '--class-slot', owner['list_entry_va']),
        'ivars': ('objc', 'ivars', *scope), 'selectors': ('objc', 'selectors', *scope)}
    for name, words in queries.items():
        replayed = invoke(root, 'replay-metadata-' + name, *words, env=offline, expected=(0,))
        assert replayed == context['metadata'][name], 'Saved metadata differs: ' + name
    for name, original in context['queries'].items():
        job_id = original['data']['origin']['job_id']
        receipt = project / 'jobs' / job_id / 'query-result.json'
        before = receipt.read_bytes()
        result = invoke(root, 'replay-' + name, 'jobs', 'resume', job_id, '--project', project, TRUST, env=offline)
        for key in ('pseudocode', 'instructions', 'origin', 'control_flow_gaps', 'flow_gap_sources'):
            assert result['data'].get(key) == original['data'].get(key), (name, key)
        assert receipt.read_bytes() == before
    exports = [invoke(root, 'evidence-' + str(i), 'evidence', '--project', project,
                      '--leads', root / 'leads.json', '--link-focused', expected=(6,), env=offline) for i in (1, 2)]
    assert exports[0] == exports[1]
    evidence = exports[0]
    by_id = {row['lead']['id']: row for row in evidence['data']['leads']}
    assert by_id['nib-action']['function']['entry_va'] == context['queries']['change']['data']['entry_va']
    assert by_id['class-pointer']['fixup'] is not None
    assert sorted((project / 'jobs').iterdir()) == before_jobs
    report = {'schema': SCHEMA, 'pin': pin,
        'facts': [
            'Saved compiled-nib action/outlet declarations agree with the owned XIB and ibtool records.',
            'The archived receiver class and selector match a same-slice Objective-C method and exact linker entry.',
            'Selected pseudocode and instruction bytes come from focused import receipts, without whole-image analysis.',
            'A fixture-specific byte oracle verifies the load receiver and true argument, and the state comparison/equality branch that skips the configuration store; Apple disassembly independently covers those instructions.',
            'Caller-supplied dispatch remains unresolved and its raw warnings and gap evidence are retained.'],
        'bounded_inferences': [
            'The selected load-method bytes support a setHidden:YES request to the declared advancedRow ivar, without resolving the runtime implementation.',
            'The selected state-method bytes support a local configuration write when the state request result differs from the declared _configuredState value.'],
        'unknowns': [
            'Nib wiring alone does not establish visibility, handler execution or a reachable UI path.',
            'This does not establish that the row can never appear, runtime dispatch targets, persistence or layout geometry.',
            'No app was executed, no nib was instantiated and no runtime oracle is asserted.',
            'Focused queries do not establish whole-image caller or callee coverage.'],
        'coverage_by_step': {**{k: v['coverage'] for k, v in context['resources']['captures'].items()},
                             **{k: v['coverage'] for k, v in context['metadata'].items()},
                             **{k: v['coverage'] for k, v in context['queries'].items()},
                             'handoff': evidence['coverage']},
        'source_identity': {'fixture_source_sha256': context['fixture_source_sha256'],
                            'xib_sha256': context['resources']['xib_sha256'], 'inputs': context['inputs'],
                            'manifest_sha256': context['manifest_sha256']},
        'resources': context['resources'], 'metadata': context['metadata'],
        'apple_instructions': context['apple_instructions'], 'byte_oracle': context['byte_oracle'], 'selected_evidence': evidence}
    json_bytes, html_bytes = storage.canonical(report) + b'\n', render(report)
    assert str(root).encode() not in json_bytes and str(root).encode() not in html_bytes
    for filename, payload in (('handoff.json', json_bytes), ('handoff.html', html_bytes)):
        path = root / filename
        if path.exists():
            assert path.read_bytes() == payload, 'Normalized handoff changed: ' + filename
        else:
            storage.atomic(path, payload)
        assert path.stat().st_mode & 0o077 == 0
    return {'arch': pin['arch'], 'status': 'passed', 'application_executed': False,
            'whole_image_analysis': False, 'offline_replay': True,
            'slice_sha256': pin['slice_sha256'], 'program_sha256': pin['import_program_sha256'],
            'json_sha256': digest(root / 'handoff.json'), 'html_sha256': digest(root / 'handoff.html'),
            'selected_status': {k: v['status'] for k, v in context['queries'].items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--arch', choices=('arm64', 'x86_64', 'both'), default='both')
    parser.add_argument('--replay', action='store_true', help='Require existing saved captures; never build or launch engine')
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output_dir.resolve()
    assert output.parent.is_dir(), 'Use an existing output parent'
    if not output.exists():
        assert not args.replay, 'No saved captures to replay'
        output.mkdir(mode=0o700)
    summaries = []
    for arch in (('arm64', 'x86_64') if args.arch == 'both' else (args.arch,)):
        root = output / arch
        try:
            context_file = root / 'context.json'
            if context_file.is_file():
                context = storage.strict_json(context_file.read_bytes())
                assert context['arch'] == arch, 'Saved capture architecture differs'
            else:
                assert not args.replay and not root.exists(), 'Incomplete capture: preserve it and choose a new output directory'
                assert sys.platform == 'darwin', 'Fresh owned capture requires macOS'
                context = prepare(root, arch)
            app = root / 'Owned Resource Calendar.app'
            absent = root / 'Original App Unavailable'
            # Keep immutable project slices: offline byte revalidation needs them.
            if app.exists():
                assert not absent.exists()
                app.rename(absent)
                try:
                    summary = replay(root, context)
                finally:
                    absent.rename(app)
            else:
                summary = replay(root, context)
            summaries.append(summary)
        except Exception as error:
            # A failure on one architecture is not evidence about the other.
            # Preserve the partial corpus; never silently rebuild it in place.
            summaries.append({'arch': arch, 'status': 'failed', 'error_type': type(error).__name__,
                              'reason': str(error), 'application_executed': False})
        save(output / 'summary.json', summaries, force=True)
    print(json.dumps(summaries, indent=2))
    if any(row['status'] != 'passed' for row in summaries):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
