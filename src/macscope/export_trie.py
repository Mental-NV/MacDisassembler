"""Read declared dyld exports from the immutable Mach-O slice."""
from .errors import Error
from .macho_load import MAX_TABLE_ROWS, uleb


MAX_TRIE_BYTES = 4 * 1024 * 1024
MAX_WALK_BYTES = 8 * 1024 * 1024
MAX_NODES = 20000
MAX_NAME_BYTES = 4096
KINDS = {0: "regular", 1: "thread_local", 2: "absolute"}


class TrieLimit(ValueError):
    pass


def name_bytes(data, start, end):
    stop = data.find(b"\0", start, min(end, start + MAX_NAME_BYTES + 1))
    if stop < 0:
        if end - start > MAX_NAME_BYTES:
            raise TrieLimit("export_trie_name_limit")
        raise ValueError("Unterminated export trie string")
    return data[start:stop], stop + 1


def unslid(base, value):
    if base is None:
        return None
    delta = value - (1 << 64) if value >= (1 << 63) else value
    address = base + delta
    if not 0 <= address < (1 << 64):
        raise ValueError("Export address is outside the 64-bit address space")
    return hex(address)


def terminal(data, start, end, name, base, libraries):
    flags, at = uleb(data, start, end)
    kind = KINDS.get(flags & 3)
    row = {
        "name": name.decode("utf-8", "backslashreplace"), "name_hex": name.hex(),
        "flags": hex(flags), "weak_definition": bool(flags & 4), "va": None,
    }
    # Bit 0x20 has different meanings across header and dyld revisions.
    if kind is None or flags & ~0x1f:
        return dict(row, kind="unsupported"), "export_trie_unsupported_flags"
    value, at = uleb(data, at, end)
    if flags & 8:
        if kind != "regular" or flags & 0x10 or not 1 <= value <= len(libraries):
            raise ValueError("Invalid re-export flags or library ordinal")
        imported, at = name_bytes(data, at, end)
        imported = imported or name
        row.update(kind="reexport", library_ordinal=value, library_path=libraries[value - 1],
                   import_name=imported.decode("utf-8", "backslashreplace"),
                   import_name_hex=imported.hex())
    elif kind == "absolute":
        if flags & 0x10:
            raise ValueError("Absolute export cannot have a resolver")
        row.update(kind=kind, absolute_value=hex(value))
    else:
        row.update(kind=kind, image_offset=hex(value), va=unslid(base, value))
        if flags & 0x10:
            if kind != "regular":
                raise ValueError("Thread-local export cannot have a resolver")
            resolver, at = uleb(data, at, end)
            row.update(kind="stub_and_resolver", resolver_image_offset=hex(resolver),
                       resolver_va=unslid(base, resolver))
    if at != end:
        raise ValueError("Unexpected bytes in export trie terminal")
    gap = "export_trie_base_unavailable" if base is None and "image_offset" in row else None
    return row, gap


def decode(data, offset, size, base, libraries, container_offset):
    end = offset + size
    pending = [(offset, b"")]
    active, spans, names, gaps = set(), {}, set(), set()
    rows = []
    nodes = walk_bytes = 0
    try:
        while pending:
            node, prefix = pending.pop()
            if prefix is None:
                active.remove(node)
                continue
            if node in active:
                raise ValueError("Cyclic export trie")
            nodes += 1
            if nodes > MAX_NODES:
                raise TrieLimit("export_trie_node_limit")
            length, start = uleb(data, node, end)
            payload_end = start + length
            if payload_end >= end:
                raise ValueError("Export trie terminal exceeds its node extent")
            child_count = data[payload_end]
            at = payload_end + 1
            children, initials = [], set()
            for _ in range(child_count):
                edge, at = name_bytes(data, at, end)
                child, at = uleb(data, at, end)
                if not edge or edge[0] in initials or not 0 < child < size:
                    raise ValueError("Invalid export trie edge or child offset")
                initials.add(edge[0])
                name = prefix + edge
                if len(name) > MAX_NAME_BYTES:
                    raise TrieLimit("export_trie_name_limit")
                walk_bytes += len(name)
                if walk_bytes > MAX_WALK_BYTES:
                    raise TrieLimit("export_trie_walk_limit")
                children.append((offset + child, name))
            spans[node] = at
            if length:
                if not prefix or prefix in names:
                    raise ValueError("Empty or duplicate export trie name")
                if len(rows) >= MAX_TABLE_ROWS:
                    raise TrieLimit("export_trie_row_limit")
                walk_bytes += length
                if walk_bytes > MAX_WALK_BYTES:
                    raise TrieLimit("export_trie_walk_limit")
                row, gap = terminal(data, start, payload_end, prefix, base, libraries)
                if gap:
                    gaps.add(gap)
                rows.append(dict(row, slice_file_offset=hex(node),
                                 container_file_offset=hex(container_offset + node)))
                names.add(prefix)
            active.add(node)
            pending.append((node, None))
            pending.extend(reversed(children))
    except TrieLimit as limit:
        gaps.add(str(limit))
    ranges = sorted(spans.items())
    if any(stop > following for (_, stop), (following, _) in zip(ranges, ranges[1:])):
        raise ValueError("Overlapping export trie nodes")
    return rows, sorted(gaps)


def read_exports(data, loader, container_offset):
    modern = [row for row in loader["linkedit"] if row["kind"] == "export_trie"]
    legacy = [row for row in loader["dyld_streams"] if row["kind"] == "export_trie"]
    extents = {(int(row["slice_file_offset"], 16), int(row["size"], 16))
               for row in modern + legacy if row["size"] != "0x0"}
    if len(extents) > 1:
        raise Error("export_trie_extent", "Conflicting dyld export trie extents")
    if not extents:
        # An explicit modern command with a zero extent declares an empty trie.
        return None, [], [] if modern else ["export_trie_not_present"]
    (offset, size), = extents
    sources = [source for source, rows in (("LC_DYLD_EXPORTS_TRIE", modern), ("dyld_info", legacy))
               if any(row["size"] != "0x0" for row in rows)]
    extent = {"sources": sources, "slice_file_offset": hex(offset), "size": hex(size)}
    if size > MAX_TRIE_BYTES:
        return extent, [], ["export_trie_byte_limit"]
    base = loader["preferred_image_base"]
    libraries = [row["path"] for row in loader["dylibs"] if row["kind"] != "id"]
    try:
        rows, gaps = decode(data, offset, size, int(base, 16) if base is not None else None,
                            libraries, container_offset)
    except ValueError as error:
        raise Error("export_trie_malformed", str(error)) from error
    return extent, rows, gaps


def require_engine_trie(data, loader):
    for key in ("linkedit", "dyld_streams"):
        if sum(row["kind"] == "export_trie" for row in loader[key]) > 1:
            raise Error("export_trie_extent", "Duplicate export trie load commands")
    _, _, gaps = read_exports(data, loader, 0)
    for reason in gaps:
        if reason.endswith("_limit"):
            raise Error("export_trie_limit", f"Export trie exceeds engine admission limits: {reason}", 7)
    if "export_trie_unsupported_flags" in gaps:
        raise Error("export_trie_unsupported_flags", "Unsupported export trie terminal flags for engine work", 3)


def exports(data, image):
    from .macho import thin

    return read_exports(data, thin(data)["loader"], int(image["offset"], 16))
