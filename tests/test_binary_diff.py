import hashlib

from macscope import cli, evidence, storage
from test_core import TemporaryCase


class BinaryDiffTests(TemporaryCase):
    def fixture(self, label, definitions, *, arch='x86_64', digest=None):
        aid, image_id = (storage.identity([label, key]) for key in ('analysis', 'image'))
        digest = digest or storage.identity(label)
        image = dict(arch=arch, image_id=image_id, sha256=digest, artifact_sha256=storage.identity([label, 'file']))
        functions = []
        for index, (name, encoding) in enumerate(definitions):
            address = 0x1000 + index * 0x10
            entry = hex(address)
            coverage = {key: dict(status='complete', emitted=1) for key in ('instructions', 'body_ranges')}
            functions.append(dict(function_id=storage.identity([aid, entry]), image_id=image_id,
                analysis_id=aid, arch=arch, entry_va=entry, engine_entry=entry, address_space='ram',
                name=name, names=[dict(name=name, origin='ghidra')], is_external=False, is_thunk=False,
                instructions=[dict(addr=entry, bytes=encoding, text=encoding)],
                body_ranges=[[entry, hex(address+len(encoding)//2-1)]], coverage=coverage,
                instruction_bytes_sha256=hashlib.sha256(bytes.fromhex(encoding)).hexdigest(),
                decompile_status='complete', pseudocode=f'int {name}() {{\n  return 0x{encoding};\n}}\n'))
        data = dict(analysis_id=aid, image=image, functions=functions, engine={}, status='complete')
        path = self.root / (label + '.json')
        self.save(path, data)
        return path, data

    def save(self, path, data):
        storage.write_json(path, cli.envelope('export', data, data['analysis_id']), force=True)

    def compare(self, left, right, scope='functions', *extra):
        args = cli.parser().parse_args(['diff', str(left), str(right), '--scope', scope, *extra])
        return cli.execute(args)

    def test_same_slice_uses_entry_identity_across_distinct_analyses(self):
        left, a = self.fixture('a', [('_owned', 'c3')])
        right, b = self.fixture('b', [('_owned', 'c3')], digest=a['image']['sha256'])
        row, = self.compare(left, right)['data']['records']
        self.assertNotEqual(row['left']['function_id'], row['right']['function_id'])
        self.assertEqual(row['match'], {'basis': ['same_slice_entry'], 'status': 'same_slice_entry'})
        self.assertEqual(row['status'], 'unchanged')

    def test_observed_changes_include_code_rename_and_pseudocode_line(self):
        left, _ = self.fixture('a', [('_changed', 'c3'), ('_old', 'ffc3')])
        right, _ = self.fixture('b', [('_changed', '90'), ('_new', 'ffc3'), ('_added', 'cc')])
        data = self.compare(left, right)['data']
        changed, renamed, added = data['records']
        self.assertEqual(changed['match'], {'basis': ['engine_name'], 'status': 'candidate'})
        self.assertEqual(changed['first_instruction_difference']['left']['bytes'], 'c3')
        self.assertEqual(renamed['match']['basis'], ['instruction_bytes'])
        self.assertEqual(renamed['changed_fields'], ['names'])
        self.assertEqual(added['status'], 'unmatched_right')
        code = self.compare(left, right, 'pseudocode')['data']['records'][0]
        self.assertEqual(code['first_line_difference']['line'], 2)
        self.assertEqual(code['first_line_difference']['right'], '  return 0x90;\n')

    def test_conflicting_signals_do_not_force_a_pair(self):
        left, _ = self.fixture('a', [('_candidate', 'c3')])
        right, _ = self.fixture('b', [('_candidate', '90'), ('_other', 'c3')])
        result = self.compare(left, right)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['data']['summary'], {'uncertain': 3})
        left_row = next(row for row in result['data']['records'] if 'left' in row)
        self.assertEqual(set(left_row['candidates']), {'engine_name', 'instruction_bytes'})

    def test_partial_instruction_facets_cannot_become_rename_evidence(self):
        left, a = self.fixture('a', [('_old', 'c3')])
        right, _ = self.fixture('b', [('_new', 'c3')])
        a['functions'][0]['body_ranges'][0][1] = '0x1001'
        self.save(left, a)
        result = self.compare(left, right)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['data']['gaps'], ['unmatched_instruction_evidence_incomplete'])
        self.assertEqual(result['data']['summary'], {'unmatched_left': 1, 'unmatched_right': 1})
        a['functions'][0]['instructions'][0]['bytes'] = '90'
        self.save(left, a)
        self.error('diff_export', self.compare, left, right)

    def test_metadata_scope_and_cursor_bind_to_both_input_files(self):
        left, a = self.fixture('a', [('_owned', 'c3')])
        right, b = self.fixture('b', [('_owned', 'c3')], arch='arm64')
        for snapshot, path, rpath in ((a, left, '/old'), (b, right, '/new')):
            snapshot['image']['loader'] = {'rpaths': [rpath]}
            self.save(path, snapshot)
        self.error('diff_architecture', self.compare, left, right)
        data = self.compare(left, right, 'metadata')['data']
        rpath = next(row for row in data['records'] if row['field'] == 'loader.rpaths')
        self.assertEqual(rpath, dict(field='loader.rpaths', left=['/old'], right=['/new'], status='changed'))
        first = self.compare(left, right, 'metadata', '--limit', '1')
        cursor = first['coverage']['next_cursor']
        self.error('stale_cursor', self.compare, right, left, 'metadata', '--cursor', cursor)
        b['image']['loader']['rpaths'] = ['/other']
        self.save(right, b)
        self.error('stale_cursor', self.compare, left, right, 'metadata', '--cursor', cursor)


class HandoffDiffTests(TemporaryCase):
    def fixture(self, label, *, entry=0x1000, remote=0x4000, encoding='c3', text='return;',
                selector='calendarDayDuration:', arch='x86_64', lead_id='handler', unresolved=False,
                path='Contents/MacOS/Calendar'):
        digest = lambda key: storage.identity([label,key])
        pin = {'image_id':digest('image'),'arch':arch,'artifact_sha256':digest('artifact'),
               'slice_sha256':digest('slice'),'import_program_sha256':digest('Program')}
        lead = {'id':lead_id,'image_id':pin['image_id'],'kind':'objc_selector','value':selector,
                'class_slot':hex(entry+0x1000),'query_job':digest('job')[:32]}
        ranges = [[hex(entry),hex(entry+len(encoding)//2-1)]]
        coverage = {key:{'status':'complete','emitted':1} for key in ('instructions','body_ranges')}
        function = None if unresolved else {
            'function_id':digest('function'),'entry_va':hex(entry),'body_ranges':ranges,'coverage':coverage,
            'instructions':[{'addr':hex(entry),'bytes':encoding}],'pseudocode':text,'decompile_status':'complete',
            'names':[{'name':'FUN_'+hex(entry)[2:],'origin':'ghidra'}],
            'origin':{'mode':'focused_readonly_import','job_id':lead['query_job']},
            'references':{'to':{'records':[],'status':'partial'},'from':{'status':'complete',
                'records':[{'from':hex(entry),'to':hex(remote),'type':'UNCONDITIONAL_CALL'}]}},
            'call_trace':{'edges':[{'callsite':hex(entry),'reported_target':hex(remote),'resolution':'unresolved_target',
                                    'type':'UNCONDITIONAL_CALL'}],'gaps':['function_coverage_incomplete']}}
        row = {'lead':lead,'status':'unresolved' if unresolved else 'partial','reason':'job_missing' if unresolved else None,
               'function':function,'query':None,'gaps':[] if unresolved else ['references_to_incomplete'],
               'matches':[{'implementation_va':hex(entry)}]}
        data = {'schema':evidence.REPORT_SCHEMA,'authority':'committed_static_evidence','manifest_sha256':digest('manifest'),
                'images':[dict(pin,status='available',bundle_image={'relative_path':path,'main_executable':True})],
                'leads':[row]}
        file = self.root/(label+'.json')
        self.save(file,data)
        return file,data

    def save(self, path, data):
        count = len(data['leads'])
        storage.write_json(path,cli.envelope('evidence',data,status='partial',
                                             cov=cli.coverage('selected',count,count,True)),force=True)

    def compare(self, left, right, *extra):
        return cli.execute(cli.parser().parse_args(['diff',str(left),str(right),'--scope','evidence',*extra]))

    def test_moved_code_and_new_job_only_change_provenance(self):
        left,_ = self.fixture('old')
        right,_ = self.fixture('moved',entry=0x2000,remote=0x8000)
        result = self.compare(left,right)
        row, = result['data']['records']
        self.assertEqual(result['status'],'partial')
        self.assertEqual(row['status'],'unchanged_observations')
        self.assertEqual(row['changed_observations'],[])
        self.assertTrue({'entry_va','query_job','call_locations','reference_locations_from'} <= set(row['changed_provenance']))

    def test_compatible_lead_reports_changed_bytes_and_text_without_copying_text(self):
        left,_ = self.fixture('old')
        right,_ = self.fixture('changed',encoding='90',text='owned private pseudocode')
        result = self.compare(left,right)
        row, = result['data']['records']
        self.assertEqual(row['status'],'changed')
        self.assertEqual(row['changed_observations'],['instruction_bytes','pseudocode'])
        self.assertNotIn(b'owned private pseudocode',storage.canonical(result))

    def test_coverage_loss_and_incompatible_scope_are_distinct(self):
        left,_ = self.fixture('old')
        missing,_ = self.fixture('missing',unresolved=True)
        other,_ = self.fixture('different',selector='monthDuration:')
        added,_ = self.fixture('new-lead',lead_id='extra')
        self.assertEqual(self.compare(left,missing)['data']['summary'],{'unresolved':1})
        row, = self.compare(left,other)['data']['records']
        self.assertEqual((row['status'],row['reason']),('incomparable','selector_changed'))
        data = self.compare(left,added,'--limit','1')
        cursor = data['coverage']['next_cursor']
        self.assertIsNotNone(cursor)
        self.assertEqual(self.compare(left,added,'--cursor',cursor)['data']['records'][0]['status'],'lead_removed')
        self.error('stale_cursor',self.compare,added,left,'--cursor',cursor)

    def test_malformed_handoff_has_typed_error(self):
        left,_ = self.fixture('old')
        right,data = self.fixture('malformed')
        data['leads'][0]['function']['references']['from']['records'] = None
        self.save(right,data)
        self.error('diff_evidence',self.compare,left,right)
