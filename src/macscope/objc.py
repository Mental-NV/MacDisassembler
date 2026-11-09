"""Static Objective-C declarations and selector references in owned Mach-O images."""
from . import dyld
from .macho import thin
from .macho_view import MappedImage


MAX_CLASSES = 2048
MAX_METHODS = 10000
MAX_SELECTORS = 10000
CLASS_LISTS = {"__objc_classlist", "__objc_nlclslist"}
CATEGORY_LISTS = {"__objc_catlist", "__objc_nlcatlist"}
CLASS_SYMBOL = "_OBJC_CLASS_$_"
CLASS_DATA_MASK = 0x0F007FFFFFFFFFF8


class ObjCImage:
    def __init__(self, data, image, parsed):
        self.view = MappedImage(data,parsed["segments"])
        self.sections = parsed["sections"]
        _,rows,gaps = dyld.fixups(data,image,parsed=parsed)
        self.gaps = {"fixups_"+reason for reason in gaps}
        self.pointer_gaps = bool(gaps)
        self.pointers = {int(row["va"],16):row for row in rows if row["kind"]=="rebase"}
        # A bind remains external even when a legacy lazy slot also has a rebase.
        self.pointers.update((int(row["va"],16),row) for row in rows if row["kind"]=="bind")

    def target(self, site):
        pointer = self.pointers.get(site)
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
        binding = self.pointers.get(site,{})
        if binding.get("kind")=="bind":
            symbol = binding["symbol"]
            return {"name":symbol.removeprefix(CLASS_SYMBOL) if symbol.startswith(CLASS_SYMBOL) else None,
                    "symbol":symbol,"library":binding["library"],"va":None,"origin":"external_bind"}
        address = self.target(site)
        if not address:
            return None
        return {"name":self.view.string(self.target(self.ro(address)+24)), "va":hex(address),
                "origin":"class_metadata"}

    def classes(self):
        rows = {}
        for site in self.sites(CLASS_LISTS,MAX_CLASSES,"class_limit"):
            try:
                address = self.target(site)
                if address in rows:
                    continue
                ro = self.ro(address)
                flags,_,size = self.view.unpack("<III",ro)
                if flags&1:
                    raise ValueError("Class list points to metaclass")
                rows[address] = {"name":self.view.string(self.target(ro+24)), "class_va":hex(address),
                                 "metadata_va":hex(ro),"instance_size":size,"flags":hex(flags),
                                 "list_entry_va":hex(site),"origin":"objc_class_list"}
                try:
                    rows[address]["superclass"] = self.class_ref(address+8)
                except ValueError:
                    rows[address]["superclass"] = {"origin":"unresolved"}
                    self.gaps.add("unresolved_superclass")
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
                    binding = self.pointers.get(site+16,{})
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

    def method_rows(self, classes):
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
                name = target["name"] if target else None
                for offset,is_class in ((16,False),(24,True)):
                    rows.extend(self.methods(address+offset,name,is_class,category,MAX_METHODS-len(rows)))
            except ValueError:
                self.gaps.add("invalid_category_record")
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


def inventory(data, image, scope):
    parsed = thin(data)
    names = {s["name"] for s in parsed["sections"]}
    if not names&(CLASS_LISTS|CATEGORY_LISTS|{"__objc_selrefs"}):
        return [], []
    try:
        objc = ObjCImage(data,image,parsed)
    except ValueError:
        return [], ["invalid_macho_mapping"]
    classes = objc.classes()
    if scope=="classes":
        return classes,sorted(objc.gaps)
    methods = objc.method_rows(classes)
    return (methods if scope=="methods" else objc.selectors(methods)),sorted(objc.gaps)
