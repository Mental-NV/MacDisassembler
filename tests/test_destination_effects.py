"""Owned static image effects do not establish application-state writers."""
import hashlib
import struct
from unittest.mock import patch
from macscope import callback_evidence, callback_links, destination_effects, import_disasm
from test_core import TemporaryCase
from test_macho import command, image as macho_image
import test_callback_links


def adr(reg, pc, target):
    delta=(target-pc) & ((1<<21)-1)
    return (0x10000000|((delta&3)<<29)|((delta>>2)<<5)|reg).to_bytes(4,'little').hex()


class DestinationEffectTests(TemporaryCase):
    save = test_callback_links.CallbackLinkTests.save

    def setup_image(self, code=None, protection=3, overlap=False, source='04000014', zero=False, shadow=False):
        self.image_count = getattr(self, 'image_count', 0) + 1
        self.project_ = self.project('workspace' + str(self.image_count))
        text=struct.pack('<16s16s2Q8I',b'__text',b'__TEXT',0x1200,0x80,0x200,2,0,0,0x80000400,0,0,0)
        segment=struct.pack('<16s4Q4I',b'__TEXT',0x1000,0x300,0,0x300,7,5,1,0)
        data=struct.pack('<16s16s2Q8I',b'__data',b'__DATA',0x2000,0x100,0x300,3,0,0,int(zero),0,0,0)
        dsegment=struct.pack('<16s4Q4I',b'__DATA',0x2000,0x100,0x300,0x100,3,protection,2 if overlap else 1,0)
        commands=[command(0x19,segment+text),command(0x19,dsegment+data+(data if overlap else b'')),command(0x26,struct.pack('<II',0x280,5))]
        if shadow:
            commands.append(command(0x19,struct.pack('<16s4Q4I',b'__SHADOW',0x2000,0x100,0,0,3,3,0,0)))
        raw=bytearray(macho_image(commands=commands))
        raw.extend(bytes(0x400-len(raw)))
        raw[0x200:0x200+len(bytes.fromhex(source))]=bytes.fromhex(source)
        code=code or adr(1,0x1210,0x2000)+'200000f9c0035fd6'
        raw[0x210:0x210+len(bytes.fromhex(code))]=bytes.fromhex(code)
        raw[0x280:0x285]=bytes.fromhex('8004101000')
        self.raw=bytes(raw)
        self.image={'image_id':'owned','arch':'arm64','sha256':hashlib.sha256(raw).hexdigest(),
                    'offset':'0x0','engine_baseline_sha256':'a'*64}
        self.source=self.save('b'*32,0x1200,0x1200+len(bytes.fromhex(source)))
        self.save('c'*32,0x1210,0x1210+len(bytes.fromhex(code)))

    def link(self, abi=None):
        return callback_links.attach(self.project_,self.image,self.raw,
            callback_evidence.project(self.source,abi=abi,provenance=True),'c'*32,
            abi=abi,provenance=True)['data']['callback_evidence']['destination_link']

    def test_image_store_is_not_application_attribution(self):
        self.setup_image()
        link=self.link();r=link['destination_effects'];store,=r['observed_stores']
        self.assertEqual(r['destination_identity'],'verified_direct_entry_link')
        self.assertEqual(r['summary'],'mapped_image_stores_observed')
        self.assertEqual(store['static_image_va'],'0x2000')
        self.assertEqual(store['file_offset'],'0x300')
        self.assertEqual(r['application_writer_attribution'],'unknown')
        self.assertEqual(r['runtime_execution'],'unknown')
        self.assertEqual(r['persistence'],'unknown')
        self.assertEqual(link['writer_attribution'],'unknown')
        self.assertEqual(link['store_relations'][0]['storage_role'],'unattributed_memory')

    def test_stack_and_frame_stores_only(self):
        self.setup_image(code='fd030091a00300f9c0035fd6') # MOV x29,sp; STR x0,[x29]
        r=self.link(abi='aapcs64')['destination_effects']
        self.assertEqual(r['summary'],'only_stack_or_frame_stores')
        self.assertEqual(r['counts']['stack_or_frame'],1)
        self.assertEqual(r['application_writer_attribution'],'unknown')

    def test_source_transfer_stack_evidence(self):
        self.setup_image(source='e003009103000014',code='010000f9c0035fd6')
        r=self.link(abi='aapcs64')['destination_effects']
        self.assertEqual(r['summary'],'only_stack_or_frame_stores')
        self.assertEqual(r['observed_stores'][0]['base_evidence_scope'],'source_transfer')

    def test_unknown_frame_register_is_not_stack_proof(self):
        self.setup_image(code='a00300f9c0035fd6')
        r=self.link()['destination_effects']
        self.assertEqual(r['summary'],'only_unresolved_store_destinations')

    def test_no_observed_stores_is_prefix_only(self):
        self.setup_image(code='c0035fd6')
        r=self.link()['destination_effects']
        self.assertEqual(r['summary'],'no_observed_stores')
        self.assertEqual(r['coverage'],'interpreted_selected_prefix_only')
        self.assertEqual(r['application_writer_attribution'],'unknown')

    def test_invalid_mapping_cases(self):
        for options,reason in [({'protection':1},'mapping_not_writable_nonexecutable'),
                               ({'protection':7},'mapping_not_writable_nonexecutable'),
                               ({'overlap':True},'section_mapping_missing_or_ambiguous'),
                               ({'zero':True},'section_not_file_backed'),
                               ({'shadow':True},'segment_mapping_missing_or_ambiguous'),
                               ({'code':adr(1,0x1210,0x20fc)+'200000f9c0035fd6'},'section_mapping_missing_or_ambiguous')]:
            with self.subTest(options=options):
                self.setup_image(**options)
                store,=self.link()['destination_effects']['observed_stores']
                self.assertEqual(store['classification'],'unresolved_destination')
                self.assertEqual(store['reason'],reason)

    def test_unverified_link_keeps_independent_effects(self):
        self.setup_image(source='05000014')
        r=self.link()['destination_effects']
        self.assertEqual(r['destination_identity'],'gap')
        self.assertEqual(r['summary'],'mapped_image_stores_observed')
        self.assertEqual(r['application_writer_attribution'],'unknown')

    def test_immutable_offline_replay(self):
        self.setup_image()
        def snapshot():return {str(p):p.read_bytes() for p in (self.project_.path/'jobs').rglob('*') if p.is_file()}
        before=snapshot()
        with patch.object(import_disasm.engine,'dependencies',side_effect=AssertionError('native')):
            self.assertEqual(self.link(),self.link())
        self.assertEqual(snapshot(),before)

    def test_mapping_budget_preserves_raw_stores(self):
        self.setup_image()
        with patch.object(destination_effects,'MAX_MAPPINGS',1):
            link=self.link()
        store,=link['destination_effects']['observed_stores']
        self.assertEqual(store['reason'],'mapping_budget')
        self.assertEqual(len(link['store_relations']),1)

    def test_overflow_and_literal_integer_are_not_attributed(self):
        self.setup_image()
        link=self.link()
        site=next(s for s in link['destination_evidence']['sites'] if s['kind']=='memory_store')
        link['store_relations']=[]
        site['location']['base']={'kind':'address','value':'0xffffffffffffffff'}
        r=destination_effects.project(self.raw,link)
        self.assertEqual(r['observed_stores'][0]['reason'],'effective_range_overflow')
        site['location']['base']={'kind':'integer_constant','value':'0x2000'}
        r=destination_effects.project(self.raw,link)
        self.assertEqual(r['observed_stores'][0]['reason'],'base_not_address_proven')

    def test_store_budget_reports_omission(self):
        self.setup_image()
        link=self.link()
        with patch.object(destination_effects,'MAX_STORES',0):
            r=destination_effects.project(self.raw,link)
        self.assertEqual(r['omitted_stores'],1)
        self.assertEqual(r['summary'],'partial_store_classification')
        self.assertEqual(r['observed_stores'],[])
