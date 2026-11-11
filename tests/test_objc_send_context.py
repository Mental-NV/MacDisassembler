import copy
import struct
import unittest
from unittest.mock import patch
from macscope import objc_send_context as m
from macscope.macho_view import MappedImage
from macscope.errors import Error


def context():
    data=bytearray(0x1000)
    data[0x100:0x104]=bytes.fromhex('40000014') # B 0x200
    data[0x200:0x220]=struct.pack('<8I',0x90000001,0xf9430021,0x90000010,0xf9438210,0xd61f0200,*([0xd4200020]*3))
    # x1 slot0x600; x16 slot0x700
    data[0x800:0x809]=b'ownedRun\0'
    sections=[dict(name=n,va=hex(a),size=hex(z),file_offset=hex(a),protections=p)
              for n,a,z,p in [('__text',0x100,0x40,5),('__objc_stubs',0x200,0x20,5),('__objc_selrefs',0x600,8,3),('__got',0x700,8,3),('__cstring',0x800,0x20,1)]]
    obj=m.ImageContext.__new__(m.ImageContext);obj.binary=bytes(data);obj.parsed={'sections':sections,'loader':{'dylibs':[]}}
    obj.view=MappedImage(obj.binary,[dict(va='0x0',file_size='0x1000',file_offset='0x0',protections=5)])
    # Mapping permissions per section are required, not a broad executable mapping.
    obj.view=MappedImage(obj.binary,[dict(va=s['va'],file_size=s['size'],file_offset=s['file_offset'],protections=s['protections']) for s in sections])
    obj.declared={1:dict(name='_objc_msgSend',kind='undefined',n_desc='0x0')}
    obj.import_gaps=[];obj.imports=[dict(symbol_index=1,va='0x700',kind='symbol',name='_objc_msgSend',symbol_kind='undefined',slot_kind='non_lazy_pointer',slot_size=8)]
    class Obj:
        def target(self,site):return 0x800
        def relocation(self,site):return dict(kind='bind',symbol='_objc_msgSend',import_addend=0,weak_import=False,library_ordinal=0,library='self',resolution='declared_symbol')
    obj.objc=Obj()
    return obj


class SelectorStubTests(unittest.TestCase):
    def test_exact_owned_path(self):
        c=context();r=c.resolve(0x100,c.binary[0x100:0x104],0x200,'B')
        self.assertEqual(r['selector'],'ownedRun');self.assertEqual(r['return_contract'],'unknown')
        self.assertEqual(r['selector_reference_va'],'0x600');self.assertEqual(r['import_slot_va'],'0x700')

    def test_decoder_negative_and_signed_boundaries(self):
        self.assertEqual(m.branch(0x100,bytes.fromhex('ffffff97')),(0xfc,'BL'))
        self.assertIsNone(m.branch(0,bytes.fromhex('ffffff17')))
        for site,raw in [(1,b'\0'*4),(0,b'\0'*3),(0,bytes.fromhex('c0035fd6'))]:self.assertIsNone(m.branch(site,raw))

    def test_every_stub_word_mutation_rejected(self):
        for offset in range(0x200,0x220,4):
            c=context();b=bytearray(c.binary);b[offset:offset+4]=b'\0'*4;c.binary=bytes(b)
            with self.subTest(offset=offset),self.assertRaises(ValueError):c.resolve(0x100,c.binary[0x100:0x104],0x200,'B')

    def test_source_section_symbol_and_bind_negatives(self):
        mutations=[lambda c:setattr(c.objc,'relocation',lambda s:dict(kind='bind',symbol='_objc_msgSend',import_addend=0,inline_addend=7,weak_import=False,library_ordinal=0,library='self',resolution='declared_symbol')),lambda c:c.declared[1].update(n_desc='0xfe00'),lambda c:c.declared[1].update(n_desc='0x40'),lambda c:c.import_gaps.append('limit'),lambda c:c.imports.append(c.imports[0]),
                   lambda c:c.imports[0].update(name='_objc_other'),lambda c:c.parsed['sections'][1].update(name='__text'),
                   lambda c:c.parsed['sections'].append(c.parsed['sections'][2]),
                   lambda c:setattr(c.objc,'relocation',lambda s:dict(kind='bind',symbol='_objc_msgSend',import_addend=1,weak_import=False)),
                   lambda c:setattr(c.objc,'relocation',lambda s:dict(kind='bind',symbol='_objc_msgSend',import_addend=0,weak_import=True))]
        for mutation in mutations:
            c=context();mutation(c)
            with self.assertRaises(ValueError):c.resolve(0x100,c.binary[0x100:0x104],0x200,'B')
        c=context()
        with self.assertRaises(ValueError):c.resolve(0x100,b'\0'*4,0x200,'B')
        with self.assertRaises(ValueError):c.resolve(0x100,c.binary[0x100:0x104],0x200,'BL')

    def test_redaction_and_unknown_policy(self):
        section={'policy':m.POLICY,'receipts':[{'sites':[{'selector':'secret'}]}]}
        def redact(s):
            s=copy.deepcopy(s);s['receipts'][0]['sites'][0]['selector']='REDACTED';return s
        r=m.redact(section,redact);self.assertEqual(r['receipts'][0]['sites'],[])
        self.assertEqual(r['receipts'][0]['reason'],'context_redacted')
        with self.assertRaises(Error):m.summary({'policy':'unknown'})

    def test_no_receipt_never_infers(self):
        class Project:
            def images(self):return []
        report={'images':[{'image_id':'a'}],'leads':[{'lead':{'image_id':'a','id':'x'},'function':None}]}
        r=m.build(Project(),report);self.assertEqual(r['receipts'][0]['status'],'unavailable')
        self.assertEqual(r['status'],'partial')

    def test_budgets_and_stale_receipts(self):
        class Project:
            def images(self): return [{'image_id':'a','arch':'arm64'}]
        report={'images':[{'image_id':'a','import_program_sha256':'p'}],
                'leads':[{'lead':{'image_id':'a','id':str(n),'query_job':'b'*32},'function':{'entry_va':'0x100'}} for n in range(5)]}
        result={'status':'partial','data':{'instructions':[{'addr':'0x100','bytes':'40000014'}]*1000,
                                          'origin':{'extent':{}}}}
        with patch.object(m.evidence,'open_image'),patch.object(m.metadata,'verified_slice',return_value=b'x'), \
             patch.object(m.evidence,'focused_query',return_value=result),patch.object(m,'ImageContext',return_value=context()):
            rows=m.build(Project(),report)['receipts']
        self.assertEqual([len(r['sites']) for r in rows],[16,16,16,16,0])
        self.assertEqual(rows[0]['omitted_instructions'],488)
        self.assertEqual(rows[0]['omitted_sites'],496)
        self.assertEqual(rows[-1]['omitted_sites'],512)
        with patch.object(m.evidence,'open_image',side_effect=Error('stale','stale')):
            rows=m.build(Project(),report)['receipts']
        self.assertTrue(all(r['reason']=='stale' and not r['sites'] for r in rows))

    def test_negative_library_inline_and_format_fields(self):
        changes=[{'inline_addend':1},{'library':'elsewhere'},{'library_ordinal':-2},
                 {'pointer_format':'DYLD_CHAINED_PTR_64'},
                 {'pointer_format':'DYLD_CHAINED_PTR_ARM64E','inline_addend':0}]
        for change in changes:
            c=context();base=c.objc.relocation(0x700);base.update(change)
            c.objc.relocation=lambda site:base
            with self.subTest(change=change),self.assertRaises(ValueError):
                c.resolve(0x100,c.binary[0x100:0x104],0x200,'B')
