"""Objective-C declarations resolve through bounded file mappings."""
import hashlib
import json
import struct
import unittest
from unittest.mock import patch

from macscope import cli, dyld, engine, import_state, macho, objc, storage
from macscope.errors import Error
from macscope.schema import validate_envelope
from test_core import TemporaryCase
from test_macho import command, image


BASE = 0x100000000


def fixture(*, relative=False, invalid_selector=False, other_flags=0):
    def section(name,offset):
        return struct.pack("<16s16s2Q8I",name,b"__TEXT",BASE+offset,8,offset,3,0,0,0,0,0,0)

    segment = struct.pack("<16s4Q4I",b"__TEXT",BASE,0x1000,0,0x800,7,5,2,0)
    segment += section(b"__objc_classlist",0x300)+section(b"__objc_selrefs",0x308)
    data = bytearray(image(commands=[command(0x19,segment)]))
    data.extend(bytes(0x800-len(data)))
    struct.pack_into("<2Q",data,0x300,BASE+0x400,BASE+(0x900 if invalid_selector else 0x520))
    struct.pack_into("<5Q",data,0x400,0,0,0,0,(BASE+0x440)|3)
    struct.pack_into("<4I3Q",data,0x440,0x80,8,24,0,0,BASE+0x500,BASE+0x480)
    if relative:
        struct.pack_into("<2I3i",data,0x480,0x8000000C|other_flags,1,
                         0x308-0x488,0x540-0x48C,0x600-0x490)
    else:
        struct.pack_into("<2I3Q",data,0x480,24|other_flags,1,BASE+0x520,BASE+0x540,BASE+0x600)
    data[0x500:0x50B] = b"OwnedProbe\0"
    data[0x520:0x526] = b"probe\0"
    data[0x540:0x548] = b"v16@0:8\0"
    return bytes(data)


def owned_empty_ivar_fixture(encoding=b"\0\0"):
    data = bytearray(property_fixture())
    struct.pack_into("<Q",data,0x3B0,BASE+0x600)
    struct.pack_into("<II",data,0x600,32,1)
    struct.pack_into("<3Q2I",data,0x608,BASE+0x680,BASE+0x790,BASE+0x7A0,2,4)
    struct.pack_into("<i",data,0x680,12)
    data[0x790:0x796] = b"owned\0"
    data[0x7A0:0x7A0+len(encoding)] = encoding
    return data


def property_fixture(*, image_flags=0x40, image_version=0, protocol_size=96, bad_property=False):
    sections = [(b"__objc_classlist",0x300), (b"__objc_catlist",0x308),
                (b"__objc_protolist",0x310), (b"__objc_imageinfo",0x318)]
    segment = struct.pack("<16s4Q4I",b"__TEXT",BASE,0x1000,0,0x900,7,5,len(sections),0)
    for name, offset in sections:
        segment += struct.pack("<16s16s2Q8I",name,b"__TEXT",BASE+offset,8,offset,3,0,0,0,0,0,0)
    data = bytearray(image(commands=[command(0x19,segment)]))
    data.extend(bytes(0x900-len(data)))
    struct.pack_into("<3Q2I",data,0x300,BASE+0x340,BASE+0x448,BASE+0x480,image_version,image_flags)
    struct.pack_into("<5Q",data,0x340,BASE+0x3C8,0,0,0,BASE+0x380)
    struct.pack_into("<5Q",data,0x3C8,0,0,0,0,BASE+0x400)
    struct.pack_into("<I",data,0x400,1)
    struct.pack_into("<Q",data,0x398,BASE+0x700)
    struct.pack_into("<2Q",data,0x448,BASE+0x710,BASE+0x340)
    struct.pack_into("<Q",data,0x488,BASE+0x720)
    struct.pack_into("<I",data,0x4C0,protocol_size)
    for offset, name in ((0x700,b"Owned\0"), (0x710,b"Extra\0"), (0x720,b"Contract\0"),
                         (0x730,b"Ti,R,N\0")):
        data[offset:offset+len(name)] = name
    sites = (0x3C0,0x440,0x470,0x478,0x4B8,0x4D8)
    for index, site in enumerate(sites):
        address = 0x500+index*24
        name = 0x750+index*8
        struct.pack_into("<Q",data,site,BASE+address)
        struct.pack_into("<2I2Q",data,address,16,1,0 if bad_property and index == 0 else BASE+name,BASE+0x730)
        data[name:name+3] = f"p{index}\0".encode()
    return bytes(data)


def chained_fixture(*, prefix_fixups=1, extra_class=False):
    """Project-owned bytes with unrelated relocations before the ObjC page."""
    source = fixture(relative=True)
    bias = ((0x400+prefix_fixups*8+4095)//4096)*4096
    payload_offset = bias+(8192 if extra_class else 4096)
    pages = payload_offset//4096
    sections = b"".join(struct.pack("<16s16s2Q8I",name,b"__TEXT",BASE+bias+offset,
                                   8,bias+offset,3,0,0,0,0,0,0)
                        for name,offset in ((b"__objc_classlist",0x300),
                                            (b"__objc_nlclslist" if extra_class else b"__objc_selrefs",0x308)))
    page_sites = {}
    values = {0x400+index*8:0x80 for index in range(prefix_fixups)}
    for offset in (0x300,0x308,0x420,0x458,0x460):
        values[bias+offset] = struct.unpack_from("<Q",source,offset)[0]-BASE+bias
    if extra_class:
        values[bias+0x308] = bias+4096+0x400
        for offset in (0x420,0x458,0x460):
            values[bias+4096+offset] = struct.unpack_from('<Q',source,offset)[0]-BASE+bias+4096
    for site in sorted(values):
        page_sites.setdefault(site//4096,[]).append(site)
    starts = [page_sites[page][0]%4096 if page in page_sites else 0xFFFF for page in range(pages)]
    payload = struct.pack("<7I",0,32,0,0,0,1,0)+bytes(4)+struct.pack("<2I",1,8)
    payload += struct.pack("<IHHQIH",22+pages*2,4096,6,0,0,pages)
    payload += struct.pack("<"+"H"*pages,*starts)
    length = payload_offset+len(payload)
    segment = struct.pack("<16s4Q4I",b"__TEXT",BASE,(length+4095)//4096*4096,0,length,7,5,2,0)
    data = bytearray(image(commands=[command(0x19,segment+sections),
                                    command(0x80000034,struct.pack("<2I",payload_offset,len(payload)))]))
    data.extend(bytes(length-len(data)))
    data[bias+0x300:bias+0x800] = source[0x300:0x800]
    if extra_class:
        data[bias+4096+0x300:bias+4096+0x800] = source[0x300:0x800]
    data[payload_offset:] = payload
    for sites in page_sites.values():
        for index,site in enumerate(sites):
            step = (sites[index+1]-site)//4 if index+1 < len(sites) else 0
            struct.pack_into("<Q",data,site,values[site] | step<<51)
    return bytes(data),bias


def class_list_fixture(addresses):
    """Move the owned raw-pointer list so slot-count tests need no mock parser."""
    data = bytearray(fixture())
    data.extend(bytes(0x1000-len(data)))
    data.extend(struct.pack('<'+'Q'*len(addresses),*addresses))
    struct.pack_into('<Q',data,64,(len(data)+4095)//4096*4096)  # segment vmsize
    struct.pack_into('<Q',data,80,len(data))  # segment filesize
    struct.pack_into('<QQI',data,136,BASE+0x1000,len(addresses)*8,0x1000)
    return bytes(data)


def legacy_objc_fixture(stream,kind='rebase'):
    data = bytearray(fixture())
    count,size = struct.unpack_from('<II',data,16)
    fields = [0]*10
    index = {'rebase':0,'bind':2}[kind]
    fields[index:index+2] = [0x780,len(stream)]
    extra = command(0x80000022,struct.pack('<10I',*fields))
    data[32+size:32+size+len(extra)] = extra
    struct.pack_into('<II',data,16,count+1,size+len(extra))
    data[0x780:0x780+len(stream)] = stream
    return bytes(data)


def overlapping_zero_fill(binary,address,*,size=1):
    data = bytearray(binary)
    count,command_size = struct.unpack_from('<II',data,16)
    extra = command(0x19,struct.pack('<16s4Q4I',b'__BSS',address,size,0,0,3,3,0,0))
    data[32+command_size:32+command_size+len(extra)] = extra
    struct.pack_into('<II',data,16,count+1,command_size+len(extra))
    return bytes(data)


def metadata_mapping_fixtures():
    yield 'raw',fixture(),0
    yield 'legacy',legacy_objc_fixture(bytes.fromhex('11 20 80 06 51 20 a0 08 51 20 d8 08 51 00')),0
    binary,bias = chained_fixture()
    yield 'chained',binary,bias


class ObjCCoverageTests(TemporaryCase):
    def stage(self,binary,name='workspace',project=None):
        project = project or self.project(name)
        source = macho.inspect_bytes(binary)
        image_data = dict(source['slices'][0],artifact_sha256=source['artifact_sha256'],input_name='owned')
        import_state.stage_inputs(project,image_data,binary)
        with project.db(False) as db:
            db.execute('INSERT INTO images(id,arch,metadata,imported) VALUES(?,?,?,1)',
                       (image_data['image_id'],image_data['arch'],storage.canonical(image_data).decode()))
        return project,image_data

    def query(self,project,*args):
        return cli.execute(cli.parser().parse_args(['objc','classes','--project',str(project.path),*args]))

    def test_true_zero_and_empty_partial_have_distinct_diagnostics(self):
        binary,_ = chained_fixture()
        project,image_data = self.stage(binary)
        result = self.query(project,'--name-contains','Absent')
        validate_envelope(result)
        self.assertEqual((result['status'],result['coverage']['known_total'],result['data']),('complete',0,[]))
        self.assertIn('completely visited',' '.join(result['diagnostics']))
        with patch.object(objc,'MAX_CLASS_POINTERS',0):
            partial = self.query(project,'--name-contains','Absent')
        validate_envelope(partial)
        messages = ' '.join(partial['diagnostics'])
        self.assertEqual((partial['status'],partial['coverage']['known_total'],partial['data']),('partial',None,[]))
        self.assertNotIn('invalid_class_record',partial['coverage']['truncation_reason'])
        for text in ('does not prove absence','cannot bypass','exhausted_work','unique_pointer_sites=0/0',
                     image_data['sha256'],'otool -arch arm64 -ov','xcrun dyld_info -arch arm64 -objc',
                     'A class-object address is not a class-list slot',
                     'Mapped class-list slot 0x100001300 is available; its mapping alone does not prove',
                     'objc methods --class-slot 0x100001300'):
            self.assertIn(text,messages)
        self.assertIn('does not prove absence',cli.render(partial,'text').decode())
        self.assertEqual(json.loads(cli.render(partial,'json')),partial)

    def test_partial_preserves_match_and_suggests_real_slot_not_class_object(self):
        project,_ = self.stage(class_list_fixture([BASE+0x400,BASE+0xDEAD]))
        result = self.query(project,'--name-contains','Owned')
        self.assertEqual((result['status'],result['coverage']['known_total']),('partial',None))
        self.assertEqual([r['name'] for r in result['data']],['OwnedProbe'])
        messages = ' '.join(result['diagnostics'])
        self.assertIn('objc methods --class-slot 0x100001000',messages)
        self.assertNotIn('objc methods --class-slot 0x100000400',messages)
        self.assertIn('class/metaclass declarations',messages)
        self.assertIn('malformed_metadata',messages)
        empty = self.query(project,'--name-contains','Absent')
        self.assertEqual(empty['data'],[])
        self.assertIn('objc methods --class-slot 0x100001000',' '.join(empty['diagnostics']))
        self.assertIn('does not prove a matching class name',' '.join(empty['diagnostics']))

    def test_partial_pagination_and_changed_filter_cursor(self):
        data = bytearray(class_list_fixture([BASE+0x400,BASE+0x800,BASE+0xDEAD]))
        data[0x800:0x828] = data[0x400:0x428]
        project,_ = self.stage(bytes(data))
        first = self.query(project,'--limit','1')
        cursor = first['coverage']['next_cursor']
        self.assertIsNotNone(cursor)
        second = self.query(project,'--limit','1','--cursor',cursor)
        again = self.query(project,'--limit','1','--cursor',cursor)
        self.assertEqual(second,again)
        all_rows = self.query(project)['data']
        self.assertEqual(first['data']+second['data'],all_rows)
        self.assertIsNone(second['coverage']['next_cursor'])
        self.assertIsNone(second['coverage']['known_total'])
        with self.assertRaises(Error) as caught:
            self.query(project,'--name-contains','Owned','--cursor',cursor)
        self.assertEqual(caught.exception.code,'stale_cursor')

    def test_metadata_query_is_read_only_and_does_not_launch_tools(self):
        binary,_ = chained_fixture()
        project,_ = self.stage(binary)
        def fingerprints():
            return {str(p.relative_to(project.path)):hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in project.path.rglob('*') if p.is_file()}
        before = fingerprints()
        with patch.object(engine,'dependencies',side_effect=AssertionError('engine probe')), \
             patch('subprocess.Popen',side_effect=AssertionError('subprocess launch')):
            self.query(project,'--name-contains','Owned')
        self.assertEqual(fingerprints(),before)

    def test_image_arch_ambiguity_and_changed_image_cursor(self):
        data = bytearray(class_list_fixture([BASE+0x400,BASE+0x800]))
        data[0x800:0x828] = data[0x400:0x428]
        project,arm = self.stage(bytes(data))
        struct.pack_into('<II',data,4,0x01000007,3)  # Routing test, not the A1 native fixture.
        _,x86 = self.stage(bytes(data),project=project)
        self.error('image_selector',self.query,project)
        first = self.query(project,'--arch','arm64','--limit','1')
        self.assertEqual(first['data'][0]['image_id'],arm['image_id'])
        self.assertEqual(self.query(project,'--image',x86['image_id'])['data'][0]['arch'],'x86_64')
        self.error('stale_cursor',self.query,project,'--arch','x86_64','--cursor',first['coverage']['next_cursor'])
        data[0x500:0x50B] = b'OtherProbe\0'
        self.stage(bytes(data),project=project)
        self.error('image_selector',self.query,project,'--arch','x86_64')

    def test_class_slot_fallback_cannot_bypass_ambiguous_required_bytes(self):
        for kind,binary,bias in metadata_mapping_fixtures():
            # Include a string suffix and its NUL, not just its first byte.
            for offset in (0x300,0x420,0x440,0x448,0x500,0x505,0x50A):
                with self.subTest(kind=kind,offset=hex(offset)):
                    data = overlapping_zero_fill(binary,BASE+bias+offset)
                    project,_ = self.stage(data,name=f'{kind}-{offset}')
                    classes = self.query(project,'--name-contains','OwnedProbe')
                    methods = cli.execute(cli.parser().parse_args([
                        'objc','methods','--project',str(project.path),'--class-slot',hex(BASE+bias+0x300)]))
                    for response in (classes,methods):
                        validate_envelope(response)
                        self.assertEqual((response['status'],response['data']),('partial',[]))
                        self.assertIsNone(response['coverage']['known_total'])

    def test_ambiguous_optional_superclass_retains_verified_name_and_partial_methods(self):
        for kind,binary,bias in metadata_mapping_fixtures():
            data = overlapping_zero_fill(binary,BASE+bias+0x408)
            project,_ = self.stage(data,name=kind)
            classes = self.query(project)
            methods = cli.execute(cli.parser().parse_args([
                'objc','methods','--project',str(project.path),'--class-slot',hex(BASE+bias+0x300)]))
            self.assertEqual(classes['data'][0]['name'],'OwnedProbe')
            self.assertEqual(classes['data'][0]['superclass'],{'origin':'unresolved'})
            self.assertEqual(methods['data'][0]['name'],'probe')
            for response in (classes,methods):
                self.assertEqual(response['status'],'partial')
                self.assertIsNone(response['coverage']['known_total'])
                self.assertIn('unresolved_superclass',response['coverage']['truncation_reason'])

    def test_cli_reports_scoped_success_and_budget_failure_without_engine(self):
        project = self.project()
        binary,_ = chained_fixture()
        source = macho.inspect_bytes(binary)
        image_data = dict(source["slices"][0],artifact_sha256=source["artifact_sha256"],input_name="owned")
        import_state.stage_inputs(project,image_data,binary)
        with project.db(False) as db:
            db.execute("INSERT INTO images(id,arch,metadata,imported) VALUES(?,?,?,1)",
                       (image_data["image_id"],image_data["arch"],storage.canonical(image_data).decode()))
        args = cli.parser().parse_args(["objc","classes","--project",str(project.path)])
        with patch.object(engine,"dependencies",side_effect=AssertionError("unexpected engine probe")), \
             patch.object(dyld,"MAX_FIXUPS",1):
            result = cli.execute(args)
            self.assertEqual(result["status"],"complete")
            self.assertEqual(result["data"][0]["name"],"OwnedProbe")
            self.assertEqual(result["coverage"]["known_total"],1)
            with patch.object(objc,"MAX_CLASS_POINTERS",0):
                result = cli.execute(args)
            self.assertEqual(result["status"],"partial")
            self.assertEqual(result["coverage"]["status"],"partial")
            self.assertIsNone(result["coverage"]["known_total"])
            self.assertIn("class_pointer_limit",result["coverage"]["truncation_reason"])


class ObjCMetadataTests(unittest.TestCase):
    def inventory(self, scope, **kwargs):
        return objc.inventory(fixture(**kwargs),{"offset":"0x0"},scope)

    def test_absolute_and_relative_method_records(self):
        for relative in (False,True):
            classes,gaps = self.inventory("classes",relative=relative)
            self.assertFalse(gaps)
            self.assertEqual(classes[0]["name"],"OwnedProbe")
            self.assertEqual(classes[0]["instance_size"],24)
            methods,gaps = self.inventory("methods",relative=relative)
            self.assertFalse(gaps)
            self.assertEqual(methods[0]["implementation_va"],hex(BASE+0x600))
            self.assertEqual(methods[0]["type_encoding"],"v16@0:8")
            self.assertEqual(methods[0]["selector_reference_va"],hex(BASE+0x308) if relative else None)
            self.assertEqual(methods[0]["encoding"],"relative" if relative else "absolute")

    def test_exact_class_slot_resolves_methods_past_the_chained_fixup_cap(self):
        binary,bias = chained_fixture()
        image_data = {"offset":"0x0"}
        with patch.object(dyld,"MAX_FIXUPS",1):
            self.assertIn("fixup_limit",dyld.fixups(binary,image_data)[2])
            methods,gaps = objc.inventory(binary,image_data,"methods")
            self.assertEqual(gaps,[])
            self.assertEqual(methods[0]["name"],"probe")
            methods,gaps = objc.selected_methods(binary,image_data,BASE+bias+0x300)
            self.assertEqual(gaps,[])
            method, = methods
            self.assertEqual((method["name"],method["class_slot"],method["implementation_va"]),
                             ("probe",hex(BASE+bias+0x300),hex(BASE+bias+0x600)))
        with self.assertRaises(Error) as caught:
            objc.selected_methods(binary,image_data,BASE+bias+0x308)
        self.assertEqual(caught.exception.code,"objc_class_slot")

    def test_class_discovery_after_ten_thousand_unrelated_fixups(self):
        binary,bias = chained_fixture(prefix_fixups=10001)
        _,rows,gaps = dyld.fixups(binary,{"offset":"0x0"})
        self.assertEqual((len(rows),gaps),(10000,["fixup_limit"]))
        for scope in ("classes","methods","selectors"):
            with self.subTest(scope=scope), patch.object(dyld,"chained_page",wraps=dyld.chained_page) as lookup:
                records,gaps = objc.inventory(binary,{"offset":"0x0"},scope)
            self.assertEqual(gaps,[])
            self.assertTrue(records)
            self.assertEqual(lookup.call_count,1)
            self.assertEqual(records[0]["name"],"OwnedProbe" if scope=="classes" else "probe")
        self.assertEqual(objc.inventory(binary,{"offset":"0x0"},"classes")[0][0]["list_entry_va"],
                         hex(BASE+bias+0x300))

    def test_unrelated_malformed_page_does_not_hide_valid_metadata(self):
        binary,_ = chained_fixture()
        data = bytearray(binary)
        struct.pack_into("<Q",data,0x400,0x80 | 4095<<51)
        with self.assertRaises(Error):
            dyld.fixups(bytes(data),{"offset":"0x0"})
        rows,gaps = objc.inventory(bytes(data),{"offset":"0x0"},"classes")
        self.assertEqual((rows[0]["name"],gaps),("OwnedProbe",[]))

    def test_malformed_metadata_page_never_uses_partial_fixup_rows(self):
        binary,bias = chained_fixture()
        data = bytearray(binary)
        # The class slot itself is valid, but a later pointer in its page is not.
        struct.pack_into("<Q",data,bias+0x460,1<<44)
        rows,gaps = objc.inventory(bytes(data),{"offset":"0x0"},"classes")
        self.assertEqual(rows,[])
        self.assertIn("fixups_fixup_pointer",gaps)
        self.assertIn("invalid_class_record",gaps)

    def test_cached_page_does_not_bypass_per_slot_segment_validation(self):
        binary,bias = chained_fixture()
        data = bytearray(binary)
        count,size = struct.unpack_from("<II",data,16)
        overlapping = command(0x19,struct.pack("<16s4Q4I",b"__BSS",BASE+bias+0x420,8,0,0,3,3,0,0))
        data[32+size:32+size+len(overlapping)] = overlapping
        struct.pack_into("<II",data,16,count+1,size+len(overlapping))
        for query in (lambda: objc.inventory(bytes(data),{"offset":"0x0"},"classes"),
                      lambda: objc.selected_methods(bytes(data),{"offset":"0x0"},BASE+bias+0x300)):
            rows,gaps = query()
            self.assertEqual(rows,[])
            self.assertIn("fixups_fixup_address_unmapped",gaps)

    def test_cached_page_never_overwrites_an_earlier_slot_failure(self):
        binary,bias = chained_fixture()
        data = bytearray(binary)
        count,size = struct.unpack_from("<II",data,16)
        overlapping = command(0x19,struct.pack("<16s4Q4I",b"__BSS",BASE+bias+0x420,8,0,0,3,3,0,0))
        data[32+size:32+size+len(overlapping)] = overlapping
        struct.pack_into("<II",data,16,count+1,size+len(overlapping))
        data = bytes(data)
        view = objc.ObjCImage(data,{"offset":"0x0"},macho.thin(data),scoped=True)
        with self.assertRaises(ValueError):
            view.target(BASE+bias+0x420)
        self.assertEqual(view.target(BASE+bias+0x300),BASE+bias+0x400)
        with self.assertRaises(ValueError):
            view.target(BASE+bias+0x420)

    def test_page_eviction_preserves_requested_results_and_bounds_memory(self):
        binary,bias = chained_fixture()
        view = objc.ObjCImage(binary,{"offset":"0x0"},objc.thin(binary),scoped=True)
        with patch.object(objc,"MAX_SCOPED_FIXUPS",5):
            self.assertEqual(view.target(BASE+0x400),BASE+0x80)
            self.assertEqual(view.cached_fixups,1)
            self.assertEqual(view.target(BASE+bias+0x300),BASE+bias+0x400)
            self.assertEqual(view.cached_fixups,5)
            self.assertEqual(len(view.page_cache),1)
            self.assertEqual(view.target(BASE+0x400),BASE+0x80)
            self.assertEqual(view.page_queries,2)
            self.assertEqual(view.gaps,set())

    def test_redecoded_page_does_not_double_count_cache_rows(self):
        binary,bias = chained_fixture()
        view = objc.ObjCImage(binary,{"offset":"0x0"},objc.thin(binary),scoped=True)
        view.relocation(BASE+bias+0x300)
        view.relocation(BASE+bias+0xffc)  # Eight-byte slot straddles the page.
        self.assertEqual(view.page_queries,2)
        self.assertEqual(view.cached_fixups,5)
        self.assertEqual(view.cached_fixups,sum(len(rows) for rows in view.page_cache.values()))

    def test_scoped_limits_remain_explicit_partial_diagnostics(self):
        binary,_ = chained_fixture()
        for limit,reason in (("MAX_CLASS_POINTERS","class_pointer_limit"),
                             ("MAX_CLASS_CHAIN_NODES","fixups_fixup_work_limit"),
                             ("MAX_SCOPED_PAGES","fixup_page_limit"),
                             ("MAX_SCOPED_FIXUPS","fixup_cache_limit")):
            with self.subTest(limit=limit), patch.object(objc,limit,0):
                rows,gaps = objc.inventory(binary,{"offset":"0x0"},"classes")
                self.assertEqual(rows,[])
                self.assertIn(reason,gaps)
        with patch.object(objc,"MAX_SELECTED_POINTERS",0):
            _,bias = chained_fixture()
            rows,gaps = objc.selected_methods(binary,{"offset":"0x0"},BASE+bias+0x300)
            self.assertEqual(rows,[])
            self.assertIn("selected_pointer_limit",gaps)

    def test_class_budget_does_not_reduce_other_inventory_budgets(self):
        binary,_ = chained_fixture()
        with patch.object(objc,'MAX_CLASS_POINTERS',0), patch.object(objc,'MAX_CLASS_CHAIN_NODES',0):
            for scope in ('methods','selectors'):
                rows,gaps = objc.inventory(binary,{'offset':'0x0'},scope)
                self.assertTrue(rows)
                self.assertEqual(gaps,[])
        with patch.object(objc,'MAX_INVENTORY_POINTERS',0):
            rows,gaps = objc.inventory(binary,{'offset':'0x0'},'methods')
            self.assertEqual(rows,[])
            self.assertIn('metadata_pointer_limit',gaps)

    def test_slot_and_unique_pointer_budgets_share_repeated_class_scope(self):
        binary = class_list_fixture([BASE+0x400]*2049)
        view = objc.ObjCImage(binary,{'offset':'0x0'},macho.thin(binary),scoped=True,discovery=True)
        rows = view.classes()
        self.assertEqual((len(rows),view.class_slots,len(view.selected_sites)),(1,2048,2051))
        self.assertEqual(view.gaps,{'class_limit'})
        self.assertEqual(view.chain_work.used,0)
        self.assertNotIn('invalid_class_record',view.gaps)

    def test_budget_after_valid_match_keeps_name_when_superclass_unavailable(self):
        binary,_ = chained_fixture()
        with patch.object(objc,'MAX_CLASS_POINTERS',3):
            diagnostics=[]
            rows,gaps = objc.inventory(binary,{'offset':'0x0'},'classes',diagnostics=diagnostics)
        self.assertEqual([r['name'] for r in rows],['OwnedProbe'])
        self.assertEqual(rows[0]['superclass'],{'origin':'unresolved'})
        self.assertEqual(gaps,['class_pointer_limit','unresolved_superclass'])
        self.assertIn('unique_pointer_sites=3/3',' '.join(diagnostics))

    def test_cache_hits_do_not_spend_chain_work(self):
        binary,bias = chained_fixture()
        view = objc.ObjCImage(binary,{'offset':'0x0'},macho.thin(binary),scoped=True,discovery=True)
        for offset in (0x300,0x308,0x420,0x458,0x460,0x408,0x300):
            view.relocation(BASE+bias+offset)
        self.assertEqual((view.chain_work.used,view.page_queries,len(view.selected_sites)),(5,1,6))

    def test_evicted_page_redecode_is_charged_but_retained_slot_is_not(self):
        binary,bias = chained_fixture(prefix_fixups=2)
        view = objc.ObjCImage(binary,{'offset':'0x0'},macho.thin(binary),scoped=True,discovery=True)
        with patch.object(objc,'MAX_SCOPED_FIXUPS',5):
            view.relocation(BASE+0x400)
            view.relocation(BASE+bias+0x300)
            self.assertEqual(view.chain_work.used,7)
            view.relocation(BASE+0x400)
            self.assertEqual(view.chain_work.used,7)
            view.relocation(BASE+0x408)
            self.assertEqual((view.chain_work.used,view.page_queries),(9,3))
            self.assertEqual(view.cached_fixups,2)

    def test_failed_page_work_is_counted_without_publishing_any_rows(self):
        binary,bias = chained_fixture()
        data = bytearray(binary)
        struct.pack_into('<Q',data,bias+0x460,1<<44)
        view = objc.ObjCImage(bytes(data),{'offset':'0x0'},macho.thin(data),scoped=True,discovery=True)
        with self.assertRaises(objc.ResolutionFailure):
            view.relocation(BASE+bias+0x300)
        self.assertEqual((view.chain_work.used,view.cached_fixups),(5,0))
        with self.assertRaises(objc.ResolutionFailure):
            view.relocation(BASE+bias+0x300)
        self.assertEqual(view.chain_work.used,5)
        with self.assertRaises(objc.ResolutionFailure):
            view.relocation(BASE+bias+0x308)
        self.assertEqual(view.chain_work.used,10)

    def test_work_limit_stops_inside_page_without_relabeling_as_corruption(self):
        binary,bias = chained_fixture()
        with patch.object(objc,'MAX_CLASS_CHAIN_NODES',4), \
             patch.object(dyld,'ordinary_pointer',wraps=dyld.ordinary_pointer) as decode:
            view = objc.ObjCImage(binary,{'offset':'0x0'},macho.thin(binary),scoped=True,discovery=True)
            self.assertEqual(view.classes(),[])
        self.assertEqual((view.chain_work.used,decode.call_count,view.cached_fixups),(4,4,0))
        self.assertEqual(view.gaps,{'fixups_fixup_work_limit'})

    def test_chain_work_exhaustion_after_verified_class_keeps_the_match(self):
        binary,_ = chained_fixture(extra_class=True)
        with patch.object(objc,'MAX_CLASS_CHAIN_NODES',5):
            view = objc.ObjCImage(binary,{'offset':'0x0'},macho.thin(binary),scoped=True,discovery=True)
            rows = view.classes()
        self.assertEqual([row['name'] for row in rows],['OwnedProbe'])
        self.assertEqual(view.chain_work.used,5)
        self.assertEqual(view.class_slots,2)
        self.assertEqual(view.gaps,{'fixups_fixup_work_limit'})

    def test_production_chain_budget_bounds_repeated_failed_decodes(self):
        binary,_ = chained_fixture(prefix_fixups=384)
        data = bytearray(binary)
        # Last node on the first page fails. Each new requested site must
        # validate that page again, and all failed work counts cumulatively.
        struct.pack_into('<Q',data,0xFF8,1<<44)
        view = objc.ObjCImage(bytes(data),{'offset':'0x0'},macho.thin(data),scoped=True,discovery=True)
        with patch.object(dyld,'ordinary_pointer',wraps=dyld.ordinary_pointer) as decode:
            for offset in range(0,3000,4):
                with self.assertRaises(objc.ResolutionFailure):
                    view.relocation(BASE+offset)
                if 'fixups_fixup_work_limit' in view.gaps:
                    break
        self.assertEqual((view.chain_work.limit,view.chain_work.used,decode.call_count),(262144,262144,262144))
        self.assertEqual(view.cached_fixups,0)
        self.assertLess(view.page_queries,objc.MAX_SCOPED_PAGES)

    def test_external_class_binding_is_missing_local_evidence_not_corrupt_metadata(self):
        binary,bias = chained_fixture()
        data = bytearray(binary)
        payload = bias+4096
        table = len(data)-payload
        data.extend(struct.pack('<I',0)+b'_OBJC_CLASS_$_External\0')
        struct.pack_into('<3I',data,payload+8,table,table+4,1)
        struct.pack_into('<I',data,276,len(data)-payload)
        struct.pack_into('<Q',data,80,len(data))
        value, = struct.unpack_from('<Q',data,bias+0x300)
        struct.pack_into('<Q',data,bias+0x300,(1<<63)|(value&(((1<<12)-1)<<51)))
        rows,gaps = objc.inventory(bytes(data),{'offset':'0x0'},'classes')
        self.assertEqual((rows,gaps),([],['external_class_pointer']))

    def test_late_class_is_retained_until_the_shared_slot_ceiling(self):
        for count,expected in ((2047,2),(2048,1)):
            data = bytearray(class_list_fixture([BASE+0x400]*count+[BASE+0x800]))
            data[0x800:0x828] = data[0x400:0x428]
            rows,gaps = objc.inventory(bytes(data),{'offset':'0x0'},'classes')
            self.assertEqual(len(rows),expected)
            self.assertEqual(gaps,[] if expected==2 else ['class_limit'])

    def test_unsupported_layout_is_not_labeled_invalid_class(self):
        binary,bias = chained_fixture()
        for offset,fmt,value in ((bias+4096+46,'H',7),(bias+4096,'I',1)):
            data = bytearray(binary)
            struct.pack_into('<'+fmt,data,offset,value)
            rows,gaps = objc.inventory(bytes(data),{'offset':'0x0'},'classes')
            self.assertEqual(rows,[])
            self.assertNotIn('invalid_class_record',gaps)
            self.assertTrue(all(objc.diagnostic_kind(gap)=='unsupported_layout' for gap in gaps),gaps)

    def test_misaligned_and_non_file_backed_slots_fail_closed(self):
        for address,offset in ((BASE+0x301,0x301),(BASE+0x900,0x900)):
            data = bytearray(fixture())
            struct.pack_into('<Q',data,136,address)
            struct.pack_into('<I',data,152,offset)
            # Test the metadata layer with a parsed section contract; the public
            # Mach-O parser may reject these before Objective-C discovery.
            parsed = macho.thin(fixture())
            parsed['sections'][0].update(va=hex(address),file_offset=hex(offset))
            view = objc.ObjCImage(bytes(data),{'offset':'0x0'},parsed,discovery=True)
            self.assertEqual(view.classes(),[])
            self.assertIn('invalid_pointer_section',view.gaps)

    def test_raw_class_discovery_rejects_overlapping_unbacked_mappings(self):
        for offset in (0x300,0x420,0x458):
            data = bytearray(fixture())
            count,size = struct.unpack_from('<II',data,16)
            extra = command(0x19,struct.pack('<16s4Q4I',b'__BSS',BASE+offset,8,0,0,3,3,0,0))
            data[32+size:32+size+len(extra)] = extra
            struct.pack_into('<II',data,16,count+1,size+len(extra))
            rows,gaps = objc.inventory(bytes(data),{'offset':'0x0'},'classes')
            self.assertEqual(rows,[])
            self.assertIn('fixups_fixup_address_unmapped',gaps)

    def test_selected_methods_validate_all_consumed_mapping_ranges(self):
        for kind,binary,bias in metadata_mapping_fixtures():
            # Method header, pointer/relative record, selector and type strings
            # including their terminators, and the executable entrypoint.
            for offset in (0x480,0x488,0x520,0x523,0x525,0x540,0x544,0x547,0x600):
                with self.subTest(kind=kind,offset=hex(offset)):
                    data = overlapping_zero_fill(binary,BASE+bias+offset)
                    classes,gaps = objc.inventory(data,{'offset':'0x0'},'classes')
                    self.assertEqual(([row['name'] for row in classes],gaps),(['OwnedProbe'],[]))
                    methods,gaps = objc.selected_methods(data,{'offset':'0x0'},BASE+bias+0x300)
                    self.assertEqual(methods,[])
                    self.assertTrue(gaps)

    def test_unrelated_or_empty_virtual_overlap_does_not_hide_metadata(self):
        for kind,binary,bias in metadata_mapping_fixtures():
            for offset,size in ((0x700,8),(0x440,0),(0x50B,1)):
                with self.subTest(kind=kind,offset=hex(offset),size=size):
                    data = overlapping_zero_fill(binary,BASE+bias+offset,size=size)
                    classes,gaps = objc.inventory(data,{'offset':'0x0'},'classes')
                    self.assertEqual(([row['name'] for row in classes],gaps),(['OwnedProbe'],[]))
                    methods,gaps = objc.selected_methods(data,{'offset':'0x0'},BASE+bias+0x300)
                    self.assertEqual(([row['name'] for row in methods],gaps),(['probe'],[]))

    def test_late_ambiguous_class_slot_does_not_discard_earlier_verified_class(self):
        binary = class_list_fixture([BASE+0x400,BASE+0x400])
        data = overlapping_zero_fill(binary,BASE+0x1008)
        rows,gaps = objc.inventory(data,{'offset':'0x0'},'classes')
        self.assertEqual([row['name'] for row in rows],['OwnedProbe'])
        self.assertIn('fixups_fixup_address_unmapped',gaps)

    def test_legacy_complete_and_truncated_evidence_keep_their_scope(self):
        binary = legacy_objc_fixture(bytes.fromhex('11 20 80 06 51 20 a0 08 51 20 d8 08 51 00'))
        rows,gaps = objc.inventory(binary,{'offset':'0x0'},'classes')
        self.assertEqual(([r['name'] for r in rows],gaps),(['OwnedProbe'],[]))
        methods,gaps = objc.selected_methods(binary,{'offset':'0x0'},BASE+0x300)
        self.assertEqual(([r['name'] for r in methods],gaps),(['probe'],[]))
        with patch.object(dyld,'MAX_FIXUPS',1):
            rows,gaps = objc.inventory(binary,{'offset':'0x0'},'classes')
        self.assertEqual(rows,[])
        self.assertIn('fixups_fixup_limit',gaps)
        self.assertIn('incomplete_relocation_evidence',gaps)
        self.assertNotIn('invalid_class_record',gaps)

    def test_unsupported_legacy_operations_are_not_labeled_malformed(self):
        for kind,stream,reason in (
                ('bind',b'\xd0\0','fixups_bind_opcode_0xd0'),
                ('rebase',bytes.fromhex('12 20 80 06 51 00'),'fixups_rebase_type_2')):
            diagnostics=[]
            rows,gaps = objc.inventory(legacy_objc_fixture(stream,kind),{'offset':'0x0'},'classes',
                                       diagnostics=diagnostics)
            self.assertEqual(rows,[])
            self.assertIn(reason,gaps)
            self.assertEqual(objc.diagnostic_kind(reason),'unsupported_layout')
            self.assertIn('unsupported_layout',' '.join(diagnostics))
            self.assertNotIn('malformed_metadata',' '.join(diagnostics))

    def test_selector_declaration_and_reference_are_separate(self):
        rows,gaps = self.inventory("selectors",relative=True)
        self.assertFalse(gaps)
        self.assertEqual({row["name"] for row in rows},{"probe"})
        self.assertEqual({row["origin"] for row in rows},{"method_declaration","selector_reference"})

    def test_invalid_selector_and_unsupported_format_keep_partial_coverage(self):
        self.assertEqual(self.inventory("methods",other_flags=0x10000),
                         ([],["unsupported_method_list_format"]))
        rows,gaps = self.inventory("selectors",relative=True,invalid_selector=True)
        self.assertFalse(rows)
        self.assertEqual(gaps,["invalid_method_record","unresolved_selector_reference"])

    def test_property_owners_and_optional_class_fields(self):
        rows,gaps = objc.inventory(property_fixture(),{"offset":"0x0"},"properties")
        self.assertFalse(gaps)
        self.assertEqual([(row["name"],row["owner_kind"],row["property_kind"]) for row in rows],
                         [("p0","class","instance"), ("p1","class","class"),
                             ("p2","category","instance"), ("p3","category","class"),
                             ("p4","protocol","instance"), ("p5","protocol","class")])
        self.assertEqual({row["attributes"] for row in rows},{"Ti,R,N"})
        self.assertEqual({row["address_space"] for row in rows},{"ram"})
        self.assertEqual(rows[2]["category_class"]["name"],"Owned")
        self.assertEqual(rows[-1]["protocol_name"],"Contract")
        older,gaps = objc.inventory(property_fixture(image_flags=0,protocol_size=72),{"offset":"0x0"},"properties")
        self.assertFalse(gaps)
        self.assertEqual([row["name"] for row in older],["p0","p1","p2","p4"])
        uncertain,gaps = objc.inventory(property_fixture(image_version=1),{"offset":"0x0"},"properties")
        self.assertEqual(gaps,["category_class_properties_layout_unavailable"])
        self.assertEqual([row["name"] for row in uncertain],["p0","p1","p2","p4","p5"])

    def test_malformed_property_counts_against_the_scan_limit(self):
        with patch.object(objc,"MAX_PROPERTIES",1):
            rows,gaps = objc.inventory(property_fixture(bad_property=True),{"offset":"0x0"},"properties")
        self.assertFalse(rows)
        self.assertEqual(gaps,["invalid_property_record","property_limit"])

    def test_verified_empty_ivar_retains_independent_evidence(self):
        good, gaps = objc.inventory(bytes(owned_empty_ivar_fixture(b"i\0")),{"offset":"0x0"},"ivars")
        self.assertEqual(gaps,[])
        self.assertNotIn("encoding_evidence",good[0])
        data=bytes(owned_empty_ivar_fixture()); diagnostics=[]
        rows,gaps=objc.selected_ivars(data,{"offset":"0x0"},BASE+0x300,diagnostics=diagnostics)
        self.assertEqual(gaps,["ivar_type_unavailable"])
        row,=rows
        self.assertEqual((row["name"],row["type_encoding"],row["declared_offset_bytes"]),("owned","",12))
        expected=dict(good[0],type_encoding="",class_slot=hex(BASE+0x300),encoding_evidence={
            "status":"unavailable","reason_code":"empty_recorded_encoding",
            "pointer_va":hex(BASE+0x618),"storage_va":hex(BASE+0x7A0),"bytes":"00",
            "scope":"recorded_metadata_not_inferred_type"})
        self.assertEqual(row,expected)
        self.assertTrue(any("row retained with unknown type" in d for d in diagnostics))
        view=objc.ObjCImage(data,{"offset":"0x0"},macho.thin(data))
        with self.assertRaises(ValueError): view.view.string(BASE+0x7A0)

    def test_empty_ivar_negative_and_offset_controls(self):
        for kind in ["null_type","unmapped","unterminated","empty_name","missing_name","alignment"]:
            data=owned_empty_ivar_fixture()
            if kind=="null_type": struct.pack_into("<Q",data,0x618,0)
            if kind=="unmapped": struct.pack_into("<Q",data,0x618,BASE+0x900)
            if kind=="unterminated": data[0x7A0:]=b"x"*(len(data)-0x7A0)
            if kind=="empty_name": data[0x790]=0
            if kind=="missing_name": struct.pack_into("<Q",data,0x610,0)
            if kind=="alignment": struct.pack_into("<I",data,0x620,32)
            with self.subTest(kind=kind):
                rows,gaps=objc.inventory(bytes(data),{"offset":"0x0"},"ivars")
                self.assertEqual(rows,[]); self.assertIn("invalid_ivar_record",gaps)
        data=owned_empty_ivar_fixture(); struct.pack_into("<Q",data,0x608,BASE+0x900)
        rows,gaps=objc.inventory(bytes(data),{"offset":"0x0"},"ivars")
        self.assertEqual(gaps,["ivar_offset_unavailable","ivar_type_unavailable"])
        self.assertEqual(rows[0]["offset_storage_va"],hex(BASE+0x900))
        self.assertIsNone(rows[0]["declared_offset_bytes"])
        data=owned_empty_ivar_fixture(); struct.pack_into("<Q",data,0x618,BASE+0x8FF)
        rows,gaps=objc.inventory(bytes(data),{"offset":"0x0"},"ivars")
        self.assertEqual(len(rows),1); self.assertEqual(gaps,["ivar_type_unavailable"])

    def test_empty_ivar_pointer_mapping_and_size_rejections(self):
        data=bytes(owned_empty_ivar_fixture())
        ambiguous=overlapping_zero_fill(data,BASE+0x7A0)
        rows,gaps=objc.inventory(ambiguous,{"offset":"0x0"},"ivars")
        self.assertEqual(rows,[]); self.assertIn("invalid_ivar_record",gaps)
        original=objc.ObjCImage.target
        def external(view, site, *args, **kwargs):
            if site==BASE+0x618:
                raise objc.ResolutionFailure("external_class_pointer","owned external control")
            return original(view,site,*args,**kwargs)
        with patch.object(objc.ObjCImage,"target",external):
            rows,gaps=objc.inventory(data,{"offset":"0x0"},"ivars")
        self.assertEqual(rows,[]); self.assertIn("invalid_ivar_record",gaps)
        oversized=owned_empty_ivar_fixture()
        oversized.extend(bytes(0x2000-len(oversized)))
        struct.pack_into("<Q",oversized,64,0x2000)
        struct.pack_into("<Q",oversized,80,0x2000)
        oversized[0x7A0:0x7A0+4098]=b"x"*4097+b"\0"
        rows,gaps=objc.inventory(bytes(oversized),{"offset":"0x0"},"ivars")
        self.assertEqual(rows,[]); self.assertIn("invalid_ivar_record",gaps)

    def test_ivar_offset_width_alignment_and_unavailable_storage(self):
        data = bytearray(property_fixture())
        struct.pack_into("<Q",data,0x3B0,BASE+0x600)
        struct.pack_into("<II",data,0x600,32,3)
        struct.pack_into("<3Q2I",data,0x608,BASE+0x680,BASE+0x790,BASE+0x7A0,0xffffffff,8)
        struct.pack_into("<3Q2I",data,0x628,BASE+0x900,BASE+0x7B0,BASE+0x7A0,2,4)
        struct.pack_into("<3Q2I",data,0x648,0,0,BASE+0x7C0,2,4)
        struct.pack_into("<II",data,0x680,12,0xdeadbeef)
        data[0x790:0x796] = b"first\0"
        data[0x7A0:0x7A2] = b"q\0"
        data[0x7B0:0x7B7] = b"second\0"
        data[0x7C0:0x7C3] = b"b5\0"
        rows,gaps = objc.inventory(bytes(data),{"offset":"0x0"},"ivars")
        self.assertEqual(gaps,["ivar_offset_unavailable"])
        first, second, anonymous = rows
        self.assertEqual((first["name"],first["class_name"],first["type_encoding"]),("first","Owned","q"))
        self.assertEqual((first["declared_offset_bytes"],first["alignment_bytes"],first["size_bytes"]),(12,8,8))
        self.assertEqual(first["offset_status"],"recorded")
        self.assertEqual(second["offset_storage_va"],hex(BASE+0x900))
        self.assertIsNone(second["declared_offset_bytes"])
        self.assertEqual(second["offset_status"],"unavailable")
        self.assertIsNone(anonymous["name"])
        self.assertIsNone(anonymous["declared_offset_bytes"])
        self.assertEqual(anonymous["offset_status"],"anonymous_bitfield")
        with patch.object(objc,"MAX_IVARS",1):
            rows,gaps = objc.inventory(bytes(data),{"offset":"0x0"},"ivars")
        self.assertEqual((rows,gaps),([first],["ivar_limit"]))
