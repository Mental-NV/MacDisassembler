"""Static Objective-C declarations and selector references in owned Mach-O images."""
from collections import OrderedDict

from . import dyld
from .errors import Error
from .macho import thin
from .macho_view import MappedImage


MAX_CLASSES = 2048
MAX_METHODS = 10000
MAX_PROPERTIES = 10000
MAX_IVARS = 10000
MAX_SELECTORS = 10000
MAX_SELECTED_POINTERS = 1024
MAX_INVENTORY_POINTERS = 65536
MAX_SCOPED_PAGES = 1024
MAX_SCOPED_FIXUPS = 65536
CLASS_LISTS = {"__objc_classlist", "__objc_nlclslist"}
CATEGORY_LISTS = {"__objc_catlist", "__objc_nlcatlist"}
PROTOCOL_LISTS = {"__objc_protolist"}
IMAGE_HAS_CATEGORY_CLASS_PROPERTIES = 0x40
CLASS_SYMBOL = "_OBJC_CLASS_$_"
CLASS_DATA_MASK = 0x0F007FFFFFFFFFF8


class ObjCImage:
    def __init__(self, data, image, parsed, *, scoped=False, pointer_limit=None):
        self.view = MappedImage(data,parsed["segments"])
        self.sections = parsed["sections"]
        self.scoped_lookup = (data,image,parsed) if scoped and any(
            row["kind"] == "chained_fixups" for row in parsed["loader"]["linkedit"]) else None
        _,rows,gaps = ({},[],[]) if self.scoped_lookup else dyld.fixups(data,image,parsed=parsed)
        self.gaps = {"fixups_"+reason for reason in gaps}
        self.pointer_gaps = bool(gaps)
        self.pointer_limit = MAX_SELECTED_POINTERS if pointer_limit is None else pointer_limit
        self.pointer_limit_reason = "selected_pointer_limit" if pointer_limit is None else "metadata_pointer_limit"
        self.selected_sites = set()
        self.page_cache = OrderedDict()
        self.page_queries = 0
        self.cached_fixups = 0
        self.pointers = {int(row["va"],16):row for row in rows if row["kind"]=="rebase"}
        # A bind remains external even when a legacy lazy slot also has a rebase.
        self.pointers.update((int(row["va"],16),row) for row in rows if row["kind"]=="bind")

    def relocation(self, site):
        if self.scoped_lookup is not None:
            if site not in self.selected_sites:
                if len(self.selected_sites) >= self.pointer_limit:
                    self.gaps.add(self.pointer_limit_reason)
                    raise ValueError("Objective-C pointer lookup limit reached")
                self.selected_sites.add(site)
                # A cached page can span a second overlapping virtual segment,
                # even when that segment has no file bytes. Validate each slot.
                try:
                    dyld.slot_segment(self.scoped_lookup[2],site)
                except Error as error:
                    self.gaps.add("fixups_"+error.code)
                    self.pointers[site] = None
                    raise ValueError("Pointer has an ambiguous segment mapping") from error
            if site not in self.pointers:
                self.pointers[site] = None
                page = next((key for key in self.page_cache if key[0] <= site and site+8 <= key[1]),None)
                if page is not None:
                    self.page_cache.move_to_end(page)
                    self.pointers[site] = self.page_cache[page].get(site,{})
                else:
                    if self.page_queries >= MAX_SCOPED_PAGES:
                        self.gaps.add("fixup_page_limit")
                        raise ValueError("Objective-C chained page lookup limit reached")
                    self.page_queries += 1
                    data,image,parsed = self.scoped_lookup
                    try:
                        info,rows,gaps = dyld.chained_page(data,image,parsed,site)
                    except Error as error:
                        self.gaps.add("fixups_"+error.code)
                    else:
                        self.gaps.update("fixups_"+reason for reason in gaps)
                        if not gaps:
                            if len(rows) > MAX_SCOPED_FIXUPS:
                                self.gaps.add("fixup_cache_limit")
                                raise ValueError("Objective-C chained page exceeds the cache limit")
                            # Retain requested-slot results separately. Eviction
                            # must not discard failures or make lookup order
                            # change whether a pointer is trusted.
                            page = tuple(int(value,16) for value in info["page_range"])
                            previous = self.page_cache.pop(page,None)
                            if previous is not None:
                                self.cached_fixups -= len(previous)
                            while self.page_cache and self.cached_fixups+len(rows) > MAX_SCOPED_FIXUPS:
                                _,old = self.page_cache.popitem(last=False)
                                self.cached_fixups -= len(old)
                            pointers = {int(row["va"],16):row for row in rows}
                            self.page_cache[page] = pointers
                            self.cached_fixups += len(rows)
                            self.pointers[site] = pointers.get(site,{})
        pointer = self.pointers.get(site,{})
        if pointer is None:
            raise ValueError("Pointer lacks complete relocation evidence")
        return pointer

    def target(self, site):
        pointer = self.relocation(site)
        if pointer:
            if pointer["kind"]=="bind":
                raise ValueError("External pointer has no local target")
            return int(pointer["target_va"],16)
        raw, = self.view.unpack("<Q",site)
        if raw and self.pointer_gaps:
            raise ValueError("Pointer lacks complete relocation evidence")
        return raw

    def sites(self, names, limit, reason):
        seen = 0
        for section in self.sections:
            if section["name"] not in names:
                continue
            va,size = int(section["va"],16),int(section["size"],16)
            if section["file_offset"] is None or size%8:
                self.gaps.add("invalid_pointer_section")
                continue
            try:
                self.view.mapping(va,size)
            except ValueError:
                self.gaps.add("invalid_pointer_section")
                continue
            for site in range(va,va+size,8):
                if seen==limit:
                    self.gaps.add(reason)
                    return
                seen += 1
                yield site

    def ro(self, address):
        self.view.mapping(address,40)
        bits = self.target(address+32)
        if bits >> 63:
            raise ValueError("Class data requires a runtime RW pointer")
        ro = bits & CLASS_DATA_MASK
        self.view.mapping(ro,40)
        return ro

    def class_ref(self, site):
        binding = self.relocation(site)
        if binding.get("kind")=="bind":
            symbol = binding["symbol"]
            return {"name":symbol.removeprefix(CLASS_SYMBOL) if symbol.startswith(CLASS_SYMBOL) else None,
                    "symbol":symbol,"library":binding["library"],"va":None,"origin":"external_bind"}
        address = self.target(site)
        if not address:
            return None
        return {"name":self.view.string(self.target(self.ro(address)+24)), "va":hex(address),
                "origin":"class_metadata"}

    def class_record(self, site, address):
        ro = self.ro(address)
        flags,_,size = self.view.unpack("<III",ro)
        if flags&1:
            raise ValueError("Class list points to metaclass")
        row = {"name":self.view.string(self.target(ro+24)), "class_va":hex(address),
               "metadata_va":hex(ro),"instance_size":size,"flags":hex(flags),
               "list_entry_va":hex(site),"origin":"objc_class_list"}
        try:
            row["superclass"] = self.class_ref(address+8)
        except ValueError:
            row["superclass"] = {"origin":"unresolved"}
            self.gaps.add("unresolved_superclass")
        return row

    def classes(self):
        rows = {}
        for site in self.sites(CLASS_LISTS,MAX_CLASSES,"class_limit"):
            try:
                address = self.target(site)
                if address not in rows:
                    rows[address] = self.class_record(site,address)
            except ValueError:
                self.gaps.add("invalid_class_record")
        return list(rows.values())

    def methods(self, list_site, class_name, class_method, category, remaining):
        address = self.target(list_site)
        if not address:
            return
        if address&3:
            self.gaps.add("unsupported_method_list_pointer")
            return
        flags,count = self.view.unpack("<II",address)
        small = bool(flags&0x80000000)
        direct = bool(flags&0x40000000)
        stride = 12 if small else 24
        if flags&0x3FFF0000 or (flags&0xFFFC)!=stride:
            self.gaps.add("unsupported_method_list_format")
            return
        self.view.mapping(address+8,count*stride)
        if count>remaining:
            self.gaps.add("method_limit")
        for index in range(min(count,remaining)):
            site = address+8+index*stride
            try:
                binding = {}
                selector_ref = None
                if small:
                    sel_delta,type_delta,imp_delta = self.view.unpack("<iii",site)
                    if not imp_delta:
                        raise ValueError("Relative method has no implementation displacement")
                    selector_ref = None if direct else hex(site+sel_delta)
                    selector = site+sel_delta if direct else self.target(site+sel_delta)
                    types = site+4+type_delta if type_delta else 0
                    imp = site+8+imp_delta
                else:
                    selector = self.target(site)
                    types = self.target(site+8)
                    binding = self.relocation(site+16)
                    imp = 0 if binding.get("kind")=="bind" else self.target(site+16)
                name = self.view.string(selector)
                encoding = self.view.string(types) if types else None
                if imp and not (self.view.mapping(imp,1)[2]&4):
                    raise ValueError("Method implementation is not executable")
                yield {"name":name,"class_name":class_name,"category":category,
                       "method_kind":"class" if class_method else "instance",
                       "implementation_va":hex(imp) if imp else None,"type_encoding":encoding,
                       "implementation_symbol":binding.get("symbol"),
                       "implementation_library":binding.get("library"),
                       "record_va":hex(site),"selector_va":hex(selector),
                       "selector_reference_va":selector_ref,
                       "origin":"objc_method_list","encoding":"relative" if small else "absolute"}
            except ValueError:
                self.gaps.add("invalid_method_record")

    def method_rows(self, classes, *, include_categories=True):
        rows = []
        for record in classes:
            address = int(record["class_va"],16)
            try:
                ro = int(record["metadata_va"],16)
                rows.extend(self.methods(ro+32,record["name"],False,None,MAX_METHODS-len(rows)))
                meta = self.target(address)
                if meta:
                    rows.extend(self.methods(self.ro(meta)+32,record["name"],True,None,MAX_METHODS-len(rows)))
            except ValueError:
                self.gaps.add("invalid_method_list")
        if not include_categories:
            return rows
        for address, category, target in self.categories():
            name = target["name"] if target else None
            try:
                for offset,is_class in ((16,False),(24,True)):
                    rows.extend(self.methods(address+offset,name,is_class,category,MAX_METHODS-len(rows)))
            except ValueError:
                self.gaps.add("invalid_category_record")
        return rows

    def categories(self):
        seen = set()
        for site in self.sites(CATEGORY_LISTS,MAX_CLASSES,"category_limit"):
            try:
                address = self.target(site)
                if address in seen:
                    continue
                seen.add(address)
                category = self.view.string(self.target(address))
                target = self.class_ref(address+8)
                if not target or not target["name"]:
                    self.gaps.add("unresolved_category_class")
                yield address, category, target
            except ValueError:
                self.gaps.add("invalid_category_record")

    def category_class_properties(self):
        sections = [section for section in self.sections if section["name"] == "__objc_imageinfo"]
        try:
            if len(sections) != 1:
                raise ValueError("Missing or ambiguous Objective-C image info")
            section, = sections
            address = int(section["va"],16)
            offset, _, _ = self.view.mapping(address,8)
            if section["size"] != "0x8" or section["file_offset"] != hex(offset):
                raise ValueError("Invalid Objective-C image info mapping")
            version, flags = self.view.unpack("<II",address)
            if version != 0:
                raise ValueError("Unsupported Objective-C image info version")
            return bool(flags & IMAGE_HAS_CATEGORY_CLASS_PROPERTIES)
        except ValueError:
            self.gaps.add("category_class_properties_layout_unavailable")
            return False

    def property_lists(self, classes):
        for record in classes:
            address = int(record["class_va"],16)
            owner = {"owner_kind":"class", "owner_va":hex(address), "class_name":record["name"]}
            yield int(record["metadata_va"],16)+64, owner, "instance"
            try:
                meta = self.target(address)
                if meta:
                    ro = self.ro(meta)
                    if not (self.view.unpack("<I",ro)[0] & 1):
                        raise ValueError("Class has no verified metaclass")
                    yield ro+64, owner, "class"
            except ValueError:
                self.gaps.add("invalid_property_metaclass")

        categories = list(self.categories())
        class_properties = categories and self.category_class_properties()
        for address, category, target in categories:
            owner = {"owner_kind":"category", "owner_va":hex(address), "category":category,
                     "class_name":target["name"] if target else None, "category_class":target}
            yield address+40, owner, "instance"
            if class_properties:
                yield address+48, owner, "class"

        seen = set()
        for site in self.sites(PROTOCOL_LISTS,MAX_CLASSES,"protocol_limit"):
            try:
                address = self.target(site)
                if not address:
                    raise ValueError("Protocol record is missing")
                if address in seen:
                    continue
                seen.add(address)
                size, = self.view.unpack("<I",address+64)
                if size < 72 or size % 8:
                    raise ValueError("Invalid Objective-C protocol size")
                self.view.mapping(address,size)
                name_va = self.target(address+8)
                if not name_va:
                    raise ValueError("Protocol name is missing")
                name = self.view.string(name_va)
                owner = {"owner_kind":"protocol", "owner_va":hex(address), "protocol_name":name}
                yield address+56, owner, "instance"
                if size >= 96:
                    yield address+88, owner, "class"
            except ValueError:
                self.gaps.add("invalid_property_protocol")

    def declaration_sites(self, site, stride, kind):
        try:
            address = self.target(site)
            if not address:
                return range(0)
            if address & 7:
                self.gaps.add(f"unsupported_{kind}_list_pointer")
                return range(0)
            entry_size,count = self.view.unpack("<II",address)
            if entry_size != stride:
                self.gaps.add(f"unsupported_{kind}_list_format")
                return range(0)
            first, end = address+8, address+8+count*stride
            self.view.mapping(first,end-first)
            return range(first,end,stride)
        except ValueError:
            self.gaps.add(f"invalid_{kind}_list")
            return range(0)

    def property_rows(self, classes):
        rows = []
        remaining = MAX_PROPERTIES
        for site, owner, kind in self.property_lists(classes):
            records = self.declaration_sites(site,16,"property")
            visited = records[:remaining]
            for record in visited:
                try:
                    name, attributes = self.target(record), self.target(record+8)
                    if not name or not attributes:
                        raise ValueError("Property name or attributes are missing")
                    rows.append(dict(owner,name=self.view.string(name),attributes=self.view.string(attributes),
                                     property_kind=kind,address_space="ram",record_va=hex(record),name_va=hex(name),
                                     attributes_va=hex(attributes),origin="objc_property_list"))
                except ValueError:
                    self.gaps.add("invalid_property_record")
            remaining -= len(visited)
            if len(visited) < len(records):
                self.gaps.add("property_limit")
                break
        return rows

    def ivar_offset(self, site, *, anonymous):
        binding = self.pointers.get(site,{})
        result = {"declared_offset_bytes":None,"offset_storage_va":None,"offset_status":"unavailable"}
        if binding.get("kind") == "bind":
            self.gaps.add("ivar_offset_unavailable")
            return dict(result,offset_status="external_bind",offset_symbol=binding["symbol"],
                        offset_library=binding["library"])
        try:
            address = self.target(site)
            if not address:
                if anonymous:
                    return dict(result,offset_status="anonymous_bitfield")
                raise ValueError("Ivar offset storage is missing")
            result["offset_storage_va"] = hex(address)
            value, = self.view.unpack("<i",address)
            if value < 0:
                raise ValueError("Negative initial ivar offset")
            return dict(result,declared_offset_bytes=value,offset_status="recorded")
        except ValueError:
            self.gaps.add("ivar_offset_unavailable")
            return result

    def ivar_rows(self, classes):
        rows = []
        remaining = MAX_IVARS
        for owner in classes:
            records = self.declaration_sites(int(owner["metadata_va"],16)+48,32,"ivar")
            visited = records[:remaining]
            for record in visited:
                try:
                    name, encoding = self.target(record+8), self.target(record+16)
                    if not encoding:
                        raise ValueError("Ivar type encoding is missing")
                    type_encoding = self.view.string(encoding)
                    anonymous = not name and type_encoding.startswith("b") and type_encoding[1:].isdecimal()
                    if not name and not anonymous:
                        raise ValueError("Ivar name is missing")
                    alignment,size = self.view.unpack("<II",record+24)
                    if alignment > 31 and alignment != 0xffffffff:
                        raise ValueError("Invalid ivar alignment")
                    rows.append({"name":self.view.string(name) if name else None, "type_encoding":type_encoding,
                                 "class_name":owner["name"], "class_va":owner["class_va"], "address_space":"ram",
                                 "record_va":hex(record), "name_va":hex(name) if name else None, "type_encoding_va":hex(encoding),
                                 "alignment_raw":hex(alignment), "alignment_bytes":8 if alignment==0xffffffff else 1<<alignment,
                                 "size_bytes":size, "origin":"objc_ivar_list", **self.ivar_offset(record,anonymous=anonymous)})
                except ValueError:
                    self.gaps.add("invalid_ivar_record")
            remaining -= len(visited)
            if len(visited) < len(records):
                self.gaps.add("ivar_limit")
                break
        return rows

    def selectors(self, methods):
        rows = [{"name":m["name"],"selector_va":m["selector_va"],"record_va":m["record_va"],
                 "origin":"method_declaration"} for m in methods[:MAX_SELECTORS]]
        for site in self.sites({"__objc_selrefs"},MAX_SELECTORS,"selector_limit"):
            if len(rows)==MAX_SELECTORS:
                self.gaps.add("selector_limit")
                break
            try:
                address = self.target(site)
                rows.append({"name":self.view.string(address),"selector_va":hex(address),
                             "record_va":hex(site),"origin":"selector_reference"})
            except ValueError:
                self.gaps.add("unresolved_selector_reference")
        return rows


def selected_methods(data, image, class_slot):
    parsed = thin(data)
    matches = [row for row in parsed["sections"] if row["name"] in CLASS_LISTS
               and row["file_offset"] is not None
               and (start := int(row["va"],16)) <= class_slot < start+int(row["size"],16)
               and (class_slot-start)%8 == 0 and class_slot+8 <= start+int(row["size"],16)]
    if len(matches) != 1:
        raise Error("objc_class_slot", "Select one aligned, file-backed Objective-C class list entry", 3)
    section, = matches
    try:
        objc = ObjCImage(data,image,parsed,scoped=True)
        offset,_,_ = objc.view.mapping(class_slot,8)
        if offset != int(section["file_offset"],16)+class_slot-int(section["va"],16):
            raise ValueError("Class list segment and section mappings disagree")
    except ValueError:
        return [], ["invalid_macho_mapping"]
    if objc.pointer_gaps:
        return [], sorted(objc.gaps)
    try:
        address = objc.target(class_slot)
        if not address:
            raise ValueError("Class list entry is empty")
        selected = objc.class_record(class_slot,address)
    except ValueError:
        return [], sorted(objc.gaps | {"invalid_class_record"})
    rows = objc.method_rows([selected],include_categories=False)
    return [dict(row,class_slot=hex(class_slot)) for row in rows],sorted(objc.gaps)


def inventory(data, image, scope):
    parsed = thin(data)
    names = {s["name"] for s in parsed["sections"]}
    lists = CLASS_LISTS if scope == "ivars" else (
        CLASS_LISTS|CATEGORY_LISTS|(PROTOCOL_LISTS if scope == "properties" else {"__objc_selrefs"}))
    if not names&lists:
        return [], []
    try:
        # Resolve only metadata-relevant pages. An unrelated image-wide fixup
        # inventory cap must not hide classes, methods or selector references.
        objc = ObjCImage(data,image,parsed,scoped=True,pointer_limit=MAX_INVENTORY_POINTERS)
    except ValueError:
        return [], ["invalid_macho_mapping"]
    classes = objc.classes()
    if scope=="classes":
        return classes,sorted(objc.gaps)
    if scope=="properties":
        rows = objc.property_rows(classes)
        return rows,sorted(objc.gaps)
    if scope=="ivars":
        rows = objc.ivar_rows(classes)
        return rows,sorted(objc.gaps)
    methods = objc.method_rows(classes)
    return (methods if scope=="methods" else objc.selectors(methods)),sorted(objc.gaps)
