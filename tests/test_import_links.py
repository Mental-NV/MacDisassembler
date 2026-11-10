import unittest

from macscope import import_links


class ImportLinkTests(unittest.TestCase):
    def test_bundle_resolution_requires_an_explicit_supported_path(self):
        bundle = {'relative_path': 'Contents/MacOS/Calendar', 'main_executable': True}
        rpaths = ['@executable_path/../Frameworks', '@loader_path/../../..', '/usr/lib']
        self.assertEqual(import_links.relative_paths('@rpath/Kit.framework/Kit', rpaths, bundle),
                         ['Contents/Frameworks/Kit.framework/Kit'])
        self.assertEqual(import_links.relative_paths('@rpath/Kit', rpaths, dict(bundle, main_executable=False)), [])

    def test_flat_namespace_weak_and_nonzero_addend_bindings_are_withheld(self):
        image = {'flags': '0x80', 'loader': {'dylibs': [{'kind': 'load', 'path': '@rpath/Kit'}]}}
        bind = {'library': '@rpath/Kit', 'symbol': '_calendar', 'library_ordinal': 1, 'weak_import': False,
                'import_addend': 0, 'slice_file_offset': '0x100', 'resolution': 'declared_symbol'}
        self.assertTrue(import_links.strong_bind(image, bind, 256))
        for flags in ('0x0', '0x180'):
            self.assertFalse(import_links.strong_bind(dict(image, flags=flags), bind, 256))
        for change in ({'weak_import': True}, {'import_addend': 4}, {'library_ordinal': 0},
                       {'stream': 'weak_bind'}, {'authenticated': True}):
            self.assertFalse(import_links.strong_bind(image, dict(bind, **change), 256))

    def test_provider_must_match_install_name_path_and_architecture_uniquely(self):
        path = 'Contents/Frameworks/Kit'
        caller = {'arch': 'arm64', 'image_id': 'main'}
        row = {'reason': None, 'bundle_paths': [path], 'binding': {'library': '@rpath/Kit', 'symbol': '_calendar'}}
        export = {'kind': 'regular', 'weak_definition': False, 'va': '0x40'}
        provider = {'pin': {'arch': 'arm64', 'image_id': 'kit'}, 'name': '@rpath/Kit', 'path': path,
                    'exports': {'_calendar'.encode().hex(): (export, ['target'])}, 'error': None}
        for mismatch in (dict(provider, path='Contents/MacOS/Kit'), dict(provider, name='@rpath/Other'),
                         dict(provider, pin={'arch': 'x86_64', 'image_id': 'kit'})):
            rejected = import_links.destination(row, caller, [mismatch])
            self.assertEqual(rejected['reason'], 'import_provider_unmatched')
            self.assertIsNone(rejected['target'])
        alternative = dict(provider, pin={'arch': 'arm64', 'image_id': 'other-kit'})
        ambiguous = import_links.destination(row, caller, [provider, alternative])
        self.assertEqual(ambiguous['reason'], 'import_provider_ambiguous')
        self.assertEqual(ambiguous['candidate_image_ids'], ['kit', 'other-kit'])
        self.assertIsNone(ambiguous['target'])
        self.assertEqual(import_links.destination(row, caller, [provider])['target']['function_id'], 'target')
