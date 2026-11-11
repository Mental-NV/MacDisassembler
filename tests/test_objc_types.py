"""Owned type grammar and opt-in CLI presentation; no native engine required."""
import json
import io
import random
import struct
import unittest
from unittest.mock import patch

from macscope import cli, engine, import_state, macho, objc_types as types, storage
from macscope.schema import validate_envelope
from test_core import TemporaryCase
from test_objc import BASE, fixture, property_fixture


class EncodingTests(unittest.TestCase):
    def decoded(self, encoding):
        result = types.decode_ivar(encoding)
        self.assertEqual(result['status'], 'decoded', result)
        self.assertEqual(result['type']['encoding_span'], [0,len(encoding)])
        return result['type']

    def test_scalars_are_encoding_names_not_inferred_typedefs(self):
        for code, display in types.SCALARS.items():
            self.assertEqual(self.decoded(code)['display'], display)
        self.assertEqual(self.decoded('c')['display'], 'char')
        for code, display in (('*','char *'),('#','Class'),(':','SEL')):
            self.assertEqual(self.decoded(code)['display'], display)

    def test_object_protocol_and_block_names(self):
        for encoding, display in (('@','id'), ('@"NSString"','NSString *'),
                                  ('@"NSObject<NSCopying>"','NSObject<NSCopying> *'),
                                  ('@"<First><Second>"','id<First><Second>'),
                                  ('@"Module.Type"','Module.Type *'),
                                  ('@?','block (signature unavailable)')):
            self.assertEqual(self.decoded(encoding)['display'], display)
        self.assertIsNone(self.decoded('@?')['signature'])
        value = self.decoded('@"bad\n\x1b\u202ename"')
        self.assertEqual(value['name'], 'bad\n\x1b\u202ename')
        self.assertTrue(value['display'].isascii())
        self.assertTrue(value['display'].isprintable())

    def test_nested_pointer_array_qualifiers_and_aggregate_fields(self):
        self.assertEqual(self.decoded('^[3i]')['display'], 'pointer to array[3] of int')
        self.assertEqual(self.decoded('[3^i]')['display'], 'array[3] of pointer to int')
        self.assertEqual(self.decoded('r^ri')['display'], 'const pointer to const int')
        self.assertEqual(self.decoded('rnNoORV@')['qualifiers'], list(types.QUALIFIERS.values()))
        value = self.decoded('{Owned="point"{Point=dd}"items"[2^i]}')
        self.assertEqual(value['display'], 'struct Owned')
        self.assertEqual([f['name'] for f in value['fields']], ['point','items'])
        self.assertEqual(value['fields'][0]['type']['fields'][1]['type']['display'], 'double')
        self.assertEqual(self.decoded('(Choice=iq)')['kind'], 'union')
        self.assertTrue(self.decoded('{Opaque}')['opaque'])
        self.assertIsNone(self.decoded('{Opaque}')['fields'])
        self.assertEqual(self.decoded('{Empty=}')['fields'], [])
        self.assertEqual(self.decoded('{?=i}')['display'], 'struct anonymous')
        self.assertEqual(self.decoded('b5')['width'], 5)

    def test_method_declaration_hidden_arguments_and_encoded_offsets(self):
        row = types.decode_method('v32@0:8@16B24', 'take:enabled:', 'instance')
        self.assertEqual(row['status'], 'decoded')
        self.assertEqual(row['declaration'], '- (void)take:(id)arg1 enabled:(bool)arg2')
        self.assertEqual(row['encoded_frame_size'], 32)
        self.assertEqual([a['encoded_offset'] for a in row['arguments']], [0,8,16,24])
        self.assertEqual([a['name'] for a in row['arguments']], ['self','_cmd','arg1','arg2'])
        self.assertEqual(row['arguments'][2]['name_origin'], 'generated')
        row = types.decode_method('@@:', 'shared', 'class')
        self.assertEqual(row['declaration'], '+ (id)shared')
        self.assertIsNone(row['encoded_frame_size'])
        self.assertEqual([a['encoded_offset'] for a in row['arguments']], [None,None])
        row = types.decode_method('v24@+0:8i-4', 'take:', 'instance')
        self.assertEqual(row['status'], 'decoded')
        self.assertEqual(row['arguments'][2]['encoded_offset'], -4)

    def test_aggregate_object_quote_ambiguity_is_not_guessed(self):
        # Owned Clang metadata confirms that these quotes introduce fields.
        # The generic optional-field-name grammar also permits object names.
        for encoding in ('{Pair="first"@"second"@}', '(Mixed="object"@"count"i)',
                         '{Pointer="first"^@"second"i}'):
            row = types.decode_ivar(encoding)
            self.assertEqual(row['status'],'unsupported')
            self.assertEqual(row['diagnostics'],['ambiguous_object_or_field_name'])
            self.assertNotIn('type',row)
        value = self.decoded('{Typed="typed"@"OwnedRoot""count"i}')
        self.assertEqual(value['fields'][0]['type']['display'],'OwnedRoot *')
        self.assertEqual(value['fields'][1]['name'],'count')
        self.assertEqual(self.decoded('{Last="typed"@"OwnedRoot"}')['fields'][0]['type']['display'],'OwnedRoot *')
        self.assertEqual(self.decoded('{Array="items"[2@"OwnedRoot"]}')['fields'][0]['type']['element']['display'],'OwnedRoot *')

    def test_empty_selector_keywords_and_unsupported_spelling(self):
        for selector, encoding, declaration in (('foo::','v24@0:8i16i20','- (void)foo:(int)arg1 :(int)arg2'),
                                               (':','v20@0:8i16','- (void):(int)arg1')):
            row = types.decode_method(encoding,selector,'instance')
            self.assertEqual(row['status'],'decoded')
            self.assertEqual(row['declaration'],declaration)
        row = types.decode_method('v20@0:8i16','café:','instance')
        self.assertEqual((row['status'],row['diagnostics']),('unsupported',['unsupported_selector_spelling']))

    def test_unsupported_and_invalid_do_not_emit_a_partial_type(self):
        for encoding, status, reason in (
                ('?', 'unsupported', 'unknown_type'), ('^r?', 'unsupported', 'unknown_type'),
                ('jD', 'unsupported', 'unsupported_type_code'), ('', 'invalid', 'empty_or_nontext_encoding'),
                ('rrq', 'invalid', 'duplicate_qualifier'), ('q8', 'invalid', 'trailing_type_data'),
                ('[3i', 'invalid', 'unterminated_array'), ('[３i]', 'invalid', 'expected_decimal'),
                ('[-1i]', 'invalid', 'expected_decimal'), ('b', 'invalid', 'expected_decimal'),
                ('{=i}', 'invalid', 'missing_aggregate_name'), ('{Tag=i', 'invalid', 'unterminated_aggregate'),
                ('@"Missing', 'invalid', 'unterminated_name'), ('^', 'invalid', 'expected_type')):
            row = types.decode_ivar(encoding)
            self.assertEqual((row['status'], row['diagnostics']), (status,[reason]), encoding)
            self.assertNotIn('type', row)
        for value, status in ((None,'unavailable'), (17,'invalid'), (b'i','invalid')):
            self.assertEqual(types.decode_ivar(value)['status'],status)

    def test_method_failure_withholds_full_declaration(self):
        for encoding, selector, kind in (('v16i0:8','probe','instance'),('v16@0i8','probe','instance'),
                ('v','probe','instance'),('v24@0:8v16','take:','instance'),
                ('v16@0:8','take:','instance'),('v24@0:8@16','probe','instance'),
                ('v16@0:8','bad\nname','instance'),('v16@0:8','probe','other'),
                ('v-1@0:8','probe','instance'),('v16@+:8','probe','instance'),
                ('v24@0:8?16','take:','instance')):
            row = types.decode_method(encoding,selector,kind)
            self.assertNotEqual(row['status'],'decoded',row)
            self.assertNotIn('declaration',row)
            self.assertNotIn('arguments',row)

    def test_independent_limits_exact_boundary(self):
        self.assertEqual(types.decode_ivar('^'*(types.MAX_DEPTH-1)+'i')['status'],'decoded')
        self.assertEqual(types.decode_ivar('^'*types.MAX_DEPTH+'i')['diagnostics'],['nesting_limit'])
        self.assertEqual(types.decode_ivar('{T='+'i'*(types.MAX_NODES-1)+'}')['status'],'decoded')
        self.assertEqual(types.decode_ivar('{T='+'i'*types.MAX_NODES+'}')['diagnostics'],['type_node_limit'])
        self.assertEqual(types.decode_ivar('b'+'9'*types.MAX_DIGITS)['status'],'decoded')
        self.assertEqual(types.decode_ivar('b'+'9'*(types.MAX_DIGITS+1))['diagnostics'],['decimal_width_limit'])
        text = '{'+'x'*(types.MAX_INPUT-2)+'}'
        self.assertEqual(types.decode_ivar(text)['status'],'decoded')
        self.assertEqual(types.decode_ivar(text+'i')['diagnostics'],['input_length_limit'])
        selector = 'take:'*(types.MAX_ARGUMENTS-2)
        self.assertEqual(types.decode_method('v@:'+'i'*(types.MAX_ARGUMENTS-2),selector,'instance')['status'],'decoded')
        self.assertEqual(types.decode_method('v@:'+'i'*(types.MAX_ARGUMENTS-1),selector,'instance')['diagnostics'],['argument_limit'])
        with patch.object(types,'MAX_RESULT_BYTES',1):
            self.assertEqual(types.decode_ivar('i')['diagnostics'],['decoded_output_limit'])
            self.assertNotIn('declaration',types.decode_method('v@:', 'probe', 'instance'))

    def test_seeded_mutations_are_bounded_deterministic_and_honest(self):
        rng = random.Random(173)
        seeds = ['v32@0:8@16B24','{Owned="point"{Point=dd}"items"[2^i]}','@"NSObject<NSCopying>"']
        alphabet = 'v@:#?^[]{}()=0123456789+-rb"\n\x00\u202e'
        for index in range(1000):
            text = list(seeds[index%len(seeds)])
            for _ in range(rng.randrange(1,6)):
                text.insert(rng.randrange(len(text)+1),rng.choice(alphabet))
            text = ''.join(text)
            row = types.decode_method(text,'take:enabled:','instance') if index%3==0 else types.decode_ivar(text)
            again = types.decode_method(text,'take:enabled:','instance') if index%3==0 else types.decode_ivar(text)
            self.assertEqual(row,again)
            self.assertIn(row['status'],('decoded','invalid','unsupported','limited'))
            self.assertLess(len(json.dumps(row)),200000)
            if row['status'] != 'decoded':
                self.assertNotIn('declaration',row)
                self.assertNotIn('type',row)


class DecoderCliTests(TemporaryCase):
    def stage(self,binary):
        project = self.project()
        source = macho.inspect_bytes(binary)
        image = dict(source['slices'][0],artifact_sha256=source['artifact_sha256'],input_name='owned')
        import_state.stage_inputs(project,image,binary)
        with project.db(False) as db:
            db.execute('INSERT INTO images(id,arch,metadata,imported) VALUES(?,?,?,1)',
                       (image['image_id'],image['arch'],storage.canonical(image).decode()))
        return project

    def query(self,project,scope,*args):
        with patch.object(engine,'dependencies',side_effect=AssertionError('engine forbidden')):
            return cli.execute(cli.parser().parse_args(['objc',scope,'--project',str(project.path),*args]))

    def test_opt_in_exact_slot_preserves_raw_and_renders_json_text(self):
        project = self.stage(fixture())
        raw = self.query(project,'methods','--class-slot',hex(BASE+0x300))
        decoded = self.query(project,'methods','--class-slot',hex(BASE+0x300),'--decode-types')
        validate_envelope(decoded)
        self.assertEqual(decoded['data'][0]['decoded_types']['declaration'],'- (void)probe')
        self.assertEqual([{k:v for k,v in row.items() if k != 'decoded_types'} for row in decoded['data']],raw['data'])
        self.assertEqual(decoded['coverage'],raw['coverage'])
        self.assertEqual(self.query(project,'methods','--class-slot',hex(BASE+0x300)),raw)
        self.assertIn('- (void)probe',cli.render(decoded,'text').decode())
        self.assertEqual(json.loads(cli.render(decoded,'json')),decoded)
        self.assertEqual(self.query(project,'methods','--decode-types','--name-contains','absent')['data'],[])

    def test_unsupported_encoding_does_not_relabel_inventory_or_drop_row(self):
        data = bytearray(fixture())
        data[0x540:0x548] = b'?16@0:8\0'
        project = self.stage(bytes(data))
        result = self.query(project,'methods','--decode-types')
        self.assertEqual(result['status'],'complete')
        self.assertEqual(result['coverage']['known_total'],1)
        self.assertEqual(result['data'][0]['type_encoding'],'?16@0:8')
        self.assertEqual(result['data'][0]['decoded_types']['status'],'unsupported')
        self.assertIn('incomplete for 1 of 1 rows',' '.join(result['diagnostics']))

    def test_decode_only_page_and_bind_policy_without_changing_raw_cursor(self):
        data = bytearray(fixture())
        struct.pack_into('<I',data,0x484,2)
        data[0x4A0:0x4B8] = data[0x488:0x4A0]
        project = self.stage(bytes(data))
        raw = self.query(project,'methods','--limit','1')
        with patch.object(types,'decode_row',wraps=types.decode_row) as decode:
            first = self.query(project,'methods','--decode-types','--limit','1')
        self.assertEqual(decode.call_count,1)
        cursor = first['coverage']['next_cursor']
        self.assertNotEqual(cursor,raw['coverage']['next_cursor'])
        self.error('stale_cursor',self.query,project,'methods','--cursor',cursor)
        self.error('stale_cursor',self.query,project,'methods','--decode-types','--cursor',raw['coverage']['next_cursor'])
        with patch.object(types,'POLICY','objc-type-encoding/next'):
            self.error('stale_cursor',self.query,project,'methods','--decode-types','--cursor',cursor)
        second = self.query(project,'methods','--decode-types','--cursor',cursor)
        self.assertEqual(len(second['data']),1)
        self.assertIsNone(second['coverage']['next_cursor'])

    def test_empty_ivar_decode_filter_keeps_partial(self):
        from test_objc import owned_empty_ivar_fixture
        project=self.stage(bytes(owned_empty_ivar_fixture()))
        for args in [[],['--class-slot',hex(BASE+0x300)],['--name-contains','owned']]:
            result=self.query(project,'ivars','--decode-types',*args)
            validate_envelope(result)
            row,=result['data']
            self.assertEqual(row['type_encoding'],'')
            self.assertEqual(row['decoded_types']['status'],'invalid')
            self.assertEqual(row['decoded_types']['diagnostics'],['empty_or_nontext_encoding'])
            self.assertEqual(result['status'],'partial')
            self.assertIn('ivar_type_unavailable',result['coverage']['truncation_reason'])
        class Output:
            buffer=io.BytesIO()
        output=Output()
        with patch('sys.stdout',output), patch.object(engine,'dependencies',side_effect=AssertionError('engine forbidden')):
            code=cli.main(['objc','ivars','--project',str(project.path),'--class-slot',hex(BASE+0x300),
                           '--decode-types','--name-contains','owned','--json'])
        self.assertEqual(code,6)
        self.assertEqual(json.loads(output.buffer.getvalue())['status'],'partial')

    def test_ivar_decoding_preserves_recorded_offsets(self):
        data = bytearray(property_fixture())
        struct.pack_into('<Q',data,0x3B0,BASE+0x600)
        struct.pack_into('<II',data,0x600,32,1)
        struct.pack_into('<3Q2I',data,0x608,BASE+0x680,BASE+0x790,BASE+0x7A0,3,8)
        struct.pack_into('<I',data,0x680,12)
        data[0x790:0x796] = b'value\0'
        data[0x7A0:0x7A3] = b'^q\0'
        project = self.stage(bytes(data))
        result = self.query(project,'ivars','--decode-types')
        validate_envelope(result)
        row, = result['data']
        self.assertEqual(row['decoded_types']['type']['display'],'pointer to long long')
        self.assertEqual((row['declared_offset_bytes'],row['size_bytes']),(12,8))


if __name__ == '__main__':
    unittest.main()
