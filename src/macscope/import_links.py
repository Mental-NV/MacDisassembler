"""Verify declared calls through ordinary Mach-O stubs to pinned bundle exports."""
from collections import defaultdict
from functools import cached_property
import posixpath

from . import dyld, export_trie, metadata
from .direct_signatures import arm64_direct_target
from .dispatch_returns import direct_target, signed
from .errors import Error
from .macho import thin
from .scalar_signatures import arm_stub


POLICY = "macscope-pinned-declared-imports/1"
MAX_LINKS = 16
STUB_WIDTH = {"arm64": 12, "x86_64": 6}
MH_TWOLEVEL = 0x80
MH_FORCE_FLAT = 0x100
S_SYMBOL_STUBS = 0x8


def section_at(image, address, segment, name):
    sections = [row for row in image["sections"] if row["segment"] == segment and row["name"] == name
                and row["protections"] & 4
                and int(row["va"], 16) <= address < int(row["va"], 16) + int(row["size"], 16)]
    return sections[0] if len(sections) == 1 else None


def stub_slot(binary, image, address, section):
    width = STUB_WIDTH[image["arch"]]
    if (int(section["flags"], 16) & 0xff != S_SYMBOL_STUBS or section["reserved2"] != width
            or (address - int(section["va"], 16)) % width):
        return None
    offset = metadata.mapped_location(image, address, width, from_file=False)
    if offset is None or offset + width > len(binary):
        return None
    if image["arch"] == "arm64":
        return arm_stub(binary, image, address)
    raw = binary[offset:offset + width]
    if raw[:2] != b"\xff\x25":
        return None
    slot = address + width + signed(raw[2:])
    if not 0 <= slot < 1 << 64:
        return None
    return hex(slot), [{"va": hex(address), "bytes": raw.hex()}]


def call_bytes(binary, image, instruction, callsite, stub_va):
    width, decode = (4, arm64_direct_target) if image["arch"] == "arm64" else (5, direct_target)
    offset = metadata.mapped_location(image, callsite, width, from_file=False)
    if (instruction is None or instruction.get("flow") != "UNCONDITIONAL_CALL" or offset is None
            or section_at(image, callsite, "__TEXT", "__text") is None
            or section_at(image, callsite + width - 1, "__TEXT", "__text") is None):
        return None
    raw = binary[offset:offset + width]
    if raw.hex() != instruction["bytes"] or decode(callsite, raw) != stub_va:
        return None
    data = image["loader"]["data_in_code"]
    if data["status"] != "complete" or any(
        (start := int(row["slice_file_offset"], 16)) < offset + width and offset < start + row["length"]
        for row in data["records"]
    ):
        return None
    return raw.hex()


def relative_paths(library, rpaths, caller):
    if not caller:
        return []
    directory = posixpath.dirname(caller["relative_path"])
    if library.startswith("@rpath/"):
        candidates = [rpath + "/" + library.removeprefix("@rpath/") for rpath in rpaths]
    else:
        candidates = [library]
    paths = set()
    for candidate in candidates:
        token, _, rest = candidate.partition("/")
        if token == "@loader_path" or (token == "@executable_path" and caller["main_executable"]):
            path = posixpath.normpath(posixpath.join(directory, rest))
            if path.startswith("Contents/"):
                paths.add(path)
    return sorted(paths)


def strong_bind(image, row, offset):
    # Compare the raw ordinal to an ordinary load command, not just the displayed name.
    ordinal = row.get("library_ordinal", 0)
    libraries = [d for d in image["loader"]["dylibs"] if d["kind"] != "id"]
    flags = int(image["flags"], 16)
    symbol = row.get("symbol", "")
    return (flags & MH_TWOLEVEL and not flags & MH_FORCE_FLAT
            and row.get("resolution") == "declared_symbol" and row["slice_file_offset"] == hex(offset)
            and row.get("stream") != "weak_bind"
            and not row["weak_import"] and row["import_addend"] == row.get("inline_addend", 0) == 0
            and not row.get("authenticated") and symbol.isascii() and symbol.isprintable() and "\\" not in symbol
            and 1 <= ordinal <= len(libraries)
            and libraries[ordinal - 1]["kind"] == "load" and libraries[ordinal - 1]["path"] == row["library"])


class ImageLinkage:
    def __init__(self, binary, image, snapshot):
        self.binary = binary
        self.image = thin(binary, include_section_linkage=True)
        if self.image["arch"] != image["arch"]:
            raise Error("import_image_mismatch", "Slice architecture differs from the committed image")
        self.container = image
        self.bundle = snapshot["image"].get("bundle_image")
        self.snapshot = snapshot

    @cached_property
    def bindings(self):
        try:
            _, rows, gaps = dyld.fixups(self.binary, self.container, parsed=self.image)
        except Error as error:
            return {}, error.code
        result = defaultdict(list)
        for row in rows:
            if row["kind"] == "bind":
                result[row["va"]].append(row)
        return result, "import_bind_coverage_incomplete" if gaps else None

    def provider(self, pin):
        names = [row["path"] for row in self.image["loader"]["dylibs"] if row["kind"] == "id"]
        if not self.bundle or len(names) != 1:
            return None
        entries = defaultdict(list)
        for function in self.snapshot["functions"]:
            va = function["entry_va"]
            if va is not None and not function["is_thunk"] and not function["is_external"]:
                entries[va].append(function["function_id"])
        try:
            _, rows, gaps = export_trie.exports(self.binary, self.container)
            error = "provider_export_coverage_incomplete" if gaps else None
        except Error as failure:
            rows, error = [], failure.code
        exports = {}
        for row in rows:
            address = row.get("va")
            in_text = (address is not None and section_at(self.image, int(address, 16), "__TEXT", "__text")
                       and metadata.mapped_location(self.image, int(address, 16), 1, from_file=False) is not None)
            ids = entries.get(address, []) if in_text else []
            exports[row["name_hex"]] = (row, ids)
        return {"pin": pin, "name": names[0], "path": self.bundle["relative_path"],
                "exports": exports, "error": error}

    def call(self, edge, section, instruction):
        row = {key: edge[key] for key in ("callsite", "caller_function_id", "callee_function_id")}
        row["stub_va"] = edge["reported_target"]
        callsite, stub_va = int(row["callsite"], 16), int(row["stub_va"], 16)
        raw = call_bytes(self.binary, self.image, instruction, callsite, stub_va)
        if raw is None:
            return dict(row, reason="import_call_bytes_unverified")
        row["call_bytes"] = raw
        stub = stub_slot(self.binary, self.image, stub_va, section)
        if stub is None:
            return dict(row, reason="import_stub_unsupported")
        slot, code = stub
        row.update(bind_va=slot, stub_instructions=code)
        bindings, error = self.bindings
        if error:
            return dict(row, reason=error)
        candidates = bindings.get(slot, ())
        if len(candidates) != 1:
            return dict(row, reason="import_bind_missing" if not candidates else "import_bind_ambiguous")
        binding = candidates[0]
        library = binding["library"]
        if library and not library.startswith("@"):
            return None  # External install names are outside this bundle view.
        row["binding"] = binding
        offset = metadata.mapped_location(self.image, int(slot, 16), 8, from_file=False)
        if offset is None or not strong_bind(self.image, binding, offset):
            return dict(row, reason="import_binding_unverified")
        paths = relative_paths(library, self.image["loader"]["rpaths"], self.bundle)
        return dict(row, bundle_paths=paths, reason=None if paths else "import_bundle_path_unverified")

    def calls(self, function):
        instructions = {row["addr"]: row for row in function.get("instructions", ())}
        rows, sites = [], set()
        for edge in function["call_trace"]["edges"]:
            site, target = edge["callsite"], edge["reported_target"]
            if (edge["resolution"] != "direct" or edge["caller_function_id"] != function["function_id"]
                    or site in sites or not target or not metadata.VA.fullmatch(target)):
                continue
            section = section_at(self.image, int(target, 16), "__TEXT", "__stubs")
            if section is None:
                continue
            sites.add(site)
            row = self.call(edge, section, instructions.get(site))
            if row is not None:
                if len(rows) == MAX_LINKS:
                    return rows, ["import_link_limit"]
                rows.append(row)
        return rows, []


def destination(row, caller, providers):
    if row["reason"]:
        return dict(row, status="unresolved", target=None)
    binding = row["binding"]
    matches = [provider for provider in providers if provider["name"] == binding["library"]
               and provider["path"] in row["bundle_paths"] and provider["pin"]["arch"] == caller["arch"]
               and provider["pin"]["image_id"] != caller["image_id"]]
    if not matches:
        return dict(row, status="unresolved", target=None, reason="import_provider_unmatched")
    if len(matches) > 1:
        return dict(row, status="unresolved", target=None, reason="import_provider_ambiguous",
                    candidate_image_ids=sorted(provider["pin"]["image_id"] for provider in matches))
    provider = matches[0]
    symbol = binding["symbol"].encode("ascii").hex()
    export, ids = provider["exports"].get(symbol, (None, []))
    if provider["error"] or export is None or export["kind"] != "regular" or export["weak_definition"] or len(ids) != 1:
        return dict(row, status="unresolved", target=None,
                    reason=provider["error"] or ("import_export_missing" if export is None else "import_export_unverified"))
    return dict(row, status="declared_match", export=export,
                target=dict(provider["pin"], function_id=ids[0], entry_va=export["va"]))
