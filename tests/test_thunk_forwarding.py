"""Owned exact B-only routes; source/register identity is not runtime evidence."""
import struct
from test_core import TemporaryCase
import test_callback_twohop as fixture_module
from test_macho import command,image as macho_image


class ForwardingTests(TemporaryCase):
    save=fixture_module.TwoHopTests.save
    resave=fixture_module.TwoHopTests.resave
    change=fixture_module.TwoHopTests.change
    chain=fixture_module.TwoHopTests.chain
    def setUp(self):
        super().setUp();self.project_=self.project()
        section=struct.pack('<16s16s2Q8I',b'__text',b'__TEXT',0x1200,0x80,0x200,2,0,0,0x80000400,0,0,0)
        segment=struct.pack('<16s4Q4I',b'__TEXT',0x1000,0x300,0,0x300,7,5,1,0)
        raw=bytearray(macho_image(commands=[command(0x19,segment+section),command(0x26,struct.pack('<II',0x280,6))]))
        raw.extend(bytes(0x300-len(raw)))
        raw[0x200:0x204]=bytes.fromhex('04000014')
        raw[0x210:0x214]=bytes.fromhex('04000014')
        raw[0x220:0x228]=bytes.fromhex('800a00f9c0035fd6')
        raw[0x280:0x286]=bytes.fromhex('800410101000')
        self.raw=bytes(raw);self.source_end=0x1204;self.inner_end=0x1214;self.writer_end=0x1228
        self.image={'image_id':'owned','arch':'arm64','offset':'0x0','engine_baseline_sha256':'a'*64}
        self.resave()

        # Add exact ends for both B-only functions; preserve writer boundary.
        raw=bytearray(self.raw)
        stream=bytes.fromhex('8004040c040c1000')
        # LC_FUNCTION_STARTS datasize is last four bytes of command table.
        commands=struct.unpack_from('<I',raw,20)[0]
        struct.pack_into('<I',raw,32+commands-4,len(stream))
        raw[0x280:0x280+len(stream)]=stream
        self.raw=bytes(raw);self.resave()

    def test_exact_two_Bs_forward_scoped_inputs_only(self):
        c=self.chain();r=c['register_forwarding']
        self.assertEqual(r['status'],'verified_static_register_forwarding')
        self.assertEqual(r['destination_entry_va'],'0x1220')
        self.assertEqual(len(r['bindings']),19)
        self.assertEqual(c['status'],'inconclusive')
        self.assertNotIn('transitive_register_correspondence_not_applied',c['unknowns'])
        self.assertIn('forwarded_inputs_not_substituted_into_destination_facts',c['unknowns'])
        for binding in r['bindings']:
            self.assertEqual(binding['source']['selection_start_va'],'0x1200')
            self.assertEqual(binding['destination']['selection_start_va'],'0x1220')
            self.assertEqual(binding['source']['register'],binding['destination']['register'])
            self.assertNotEqual(binding['source']['source_envelope_sha256'],binding['destination']['source_envelope_sha256'])
        self.assertEqual(c['destination_effects']['application_writer_attribution'],'unknown')

    def test_inner_prefix_preserves_edges_but_not_forwarding(self):
        raw=bytearray(self.raw);raw[0x284]=8;raw[0x285]=8
        self.raw=bytes(raw);self.resave()
        c=self.chain();r=c['register_forwarding']
        self.assertEqual(c['link_status'],'verified_two_hop_entry_links')
        self.assertEqual(c['source_extent'],'verified_complete_selected_thunk')
        self.assertEqual(r['status'],'gap');self.assertEqual(r['bindings'],[])
        self.assertEqual(r['gaps'][0]['role'],'inner')
        self.assertIn('transitive_register_correspondence_not_applied',c['unknowns'])

    def test_nonB_or_wrong_destination_does_not_forward(self):
        for offset,code in ((0x200,'04000094'),(0x210,'04000094'),(0x210,'05000014')):
            before=self.raw;self.change(offset,code)
            r=self.chain()['register_forwarding'];self.assertEqual(r['status'],'gap');self.assertFalse(r['bindings'])
            self.raw=before;self.resave()

    def test_destination_cycle_does_not_forward(self):
        self.change(0x220,'f8ffff17')
        self.assertEqual(self.chain()['register_forwarding']['status'],'gap')

    def test_no_mutation_and_deterministic_evidence(self):
        before=self.source.copy();first=self.chain();self.assertEqual(first,self.chain());self.assertEqual(before,self.source)
        self.assertEqual(first['destination_effects'],first['edges'][1]['destination_effects'])
