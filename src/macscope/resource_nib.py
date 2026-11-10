"""Read selected AppKit NIBArchive declarations as bounded binary data."""
from collections import defaultdict
import hashlib
from pathlib import Path
import struct

from . import bundle
from .errors import Error


POLICY = "macscope-resource-nib/1"
MAGIC = b"NIBArchive"
HEADER = struct.Struct("<10I")
HEADER_SIZE = len(MAGIC) + HEADER.size
MAX_BYTES = 4 * 1024 * 1024
MAX_OBJECTS = 20000
MAX_VALUES = 100000
MAX_TEXT = 4096
VALUE_WIDTHS = (1, 2, 4, 8, 0, 0, 4, 8, None, 0, 4)
DATA, REFERENCE = 8, 10
CONNECTIONS = {"NSNibOutletConnector": "outlet", "NSNibControlConnector": "action"}
ARRAYS = {"NSArray", "NSMutableArray"}


class Table:
    def __init__(self, raw, start, end):
        self.raw, self.position, self.end = raw, start, end

    def take(self, size):
        start = self.position
        self.position += size
        if self.position > self.end:
            raise ValueError("Truncated archive table")
        return self.raw[start:self.position]

    def number(self):
        value = 0
        for shift in range(0, 35, 7):
            byte = self.take(1)[0]
            value |= (byte & 127) << shift
            if byte & 128:
                if value > 0xffffffff or (shift and not byte & 127):
                    raise ValueError("Invalid archive integer")
                return value
        raise ValueError("Invalid archive integer")

    def name(self, size):
        if size > MAX_TEXT:
            raise Error("resource_nib_limit", "Nib archive name exceeds the text limit", 7)
        return self.take(size).decode("utf-8")

    def done(self):
        if self.position != self.end:
            raise ValueError("Archive table has unaccounted bytes")


def text_payload(raw):
    if len(raw) > MAX_TEXT:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def parse(raw):
    if not raw.startswith(MAGIC):
        raise Error("resource_nib_format", "Select a compiled NIBArchive file", 3)
    try:
        version, coder, objects, start_objects, keys, start_keys, values, start_values, classes, start_classes = (
            HEADER.unpack_from(raw, len(MAGIC)))
        if version != 1 or coder not in (9, 10):
            raise Error("resource_nib_format", "Unsupported NIBArchive version", 3)
        if not HEADER_SIZE == start_objects <= start_keys <= start_values <= start_classes <= len(raw):
            raise ValueError("Invalid archive table offsets")
        if max(objects, keys, classes) > MAX_OBJECTS or values > MAX_VALUES:
            raise Error("resource_nib_limit", "Nib archive table exceeds the record limit", 7)

        table = Table(raw, start_classes, len(raw))
        class_names = []
        for _ in range(classes):
            size = table.number()
            table.take(4 * table.number())
            name = table.name(size)
            if not name.endswith("\0") or not name[:-1] or "\0" in name[:-1]:
                raise ValueError("Invalid archive class name")
            class_names.append(name[:-1])
        table.done()

        table = Table(raw, start_keys, start_values)
        names = [table.name(table.number()) for _ in range(keys)]
        table.done()

        table = Table(raw, start_values, start_classes)
        fields = []
        for _ in range(values):
            key = names[table.number()]
            kind = table.take(1)[0]
            if kind >= len(VALUE_WIDTHS):
                raise Error("resource_nib_value_type", "Unsupported NIBArchive value type", 3)
            payload = table.take(table.number() if kind == DATA else VALUE_WIDTHS[kind])
            value = None
            if kind == REFERENCE:
                value = int.from_bytes(payload, "little")
                if value >= objects:
                    raise ValueError("Invalid archive object reference")
            elif kind == DATA and key == "NS.bytes":
                value = text_payload(payload)
            fields.append((key, kind, value))
        table.done()

        table = Table(raw, start_objects, start_keys)
        nodes = []
        field_uses = 0
        for _ in range(objects):
            name = class_names[table.number()]
            start, count = table.number(), table.number()
            if start + count > len(fields):
                raise ValueError("Invalid archive object value range")
            field_uses += count
            if field_uses > MAX_VALUES:
                raise Error("resource_nib_limit", "Nib archive exceeds the object field limit", 7)
            properties = defaultdict(list)
            for key, kind, value in fields[start:start + count]:
                properties[key].append((kind, value))
            nodes.append((name, properties))
        table.done()
    except (ValueError, IndexError, struct.error) as error:
        raise Error("resource_nib_invalid", "Malformed NIBArchive tables or references", 5) from error
    return nodes, {"version": version, "coder_version": coder, "objects": objects,
                   "keys": keys, "values": values, "classes": classes}


def field(nodes, index, key, kind):
    if index is None:
        return None
    candidates = nodes[index][1].get(key, ())
    if len(candidates) == 1 and candidates[0][0] == kind:
        return candidates[0][1]
    return None


def string(nodes, index):
    if index is None or nodes[index][0] not in ("NSString", "NSMutableString"):
        return None
    return field(nodes, index, "NS.bytes", DATA)


def endpoint(nodes, index):
    if index is None:
        return None
    name = nodes[index][0]
    result = {"object_index": index, "archive_class": name}
    if name == "NSCustomObject":
        result["declared_class"] = string(nodes, field(nodes, index, "NSClassName", REFERENCE))
    return result


def connections(nodes):
    data = field(nodes, 0, "IB.objectdata", REFERENCE) if nodes else None
    if data is None or nodes[data][0] != "NSIBObjectData":
        return [], {"nib_object_data_unavailable"}
    array = field(nodes, data, "NSConnections", REFERENCE)
    if array is None or nodes[array][0] not in ARRAYS:
        return [], {"nib_connections_unavailable"}
    properties = nodes[array][1]
    gaps = {"nib_connection_storage_unsupported"} if properties.keys() - {"NSInlinedValue", "UINibEncoderEmptyKey"} else set()
    rows = []
    members = properties.get("UINibEncoderEmptyKey", ())
    if len(members) > MAX_OBJECTS:
        raise Error("resource_nib_limit", "Nib archive exceeds the connection record limit", 7)
    for ordinal, (value_type, index) in enumerate(members):
        if value_type != REFERENCE:
            gaps.add("nib_connection_member_unavailable")
            continue
        name = nodes[index][0]
        kind = CONNECTIONS.get(name)
        label = string(nodes, field(nodes, index, "NSLabel", REFERENCE))
        source = endpoint(nodes, field(nodes, index, "NSSource", REFERENCE))
        destination = endpoint(nodes, field(nodes, index, "NSDestination", REFERENCE))
        reason = ("nib_connection_class_unsupported" if kind is None else "nib_connection_fields_unavailable"
                  if not label or source is None or destination is None else None)
        if reason:
            gaps.add(reason)
        rows.append({"kind": kind or "unknown_connection", "ordinal": ordinal, "object_index": index,
                     "archive_class": name, "label": label, "source": source, "destination": destination,
                     "status": "partial" if reason else "declared", "reason": reason})
    return rows, gaps


def button_labels(nodes):
    rows, gaps = [], set()
    for index, (name, _) in enumerate(nodes):
        if name != "NSButton":
            continue
        cell = field(nodes, index, "NSCell", REFERENCE)
        if cell is None or nodes[cell][0] != "NSButtonCell":
            gaps.add("nib_button_cell_unavailable")
            continue
        for key in ("NSContents", "NSAlternateContents"):
            if key not in nodes[cell][1]:
                continue
            label = string(nodes, field(nodes, cell, key, REFERENCE))
            if label is None:
                gaps.add("nib_button_label_unavailable")
            rows.append({"kind": "button_label", "control": endpoint(nodes, index), "cell": endpoint(nodes, cell),
                         "field": key, "label": label, "status": "partial" if label is None else "declared"})
    return rows, gaps


def read(path, requested, kind):
    relative = bundle.exact_path(requested, bundle.MAX_DEPTH + 1, "resource_file", "Select an exact bundle-relative nib file")
    if relative.suffix.lower() != ".nib":
        raise Error("resource_nib_type", "Select a .nib resource file", 2)
    try:
        raw = bundle.read_resource(path, relative, MAX_BYTES)
    except Error as error:
        if error.code == "input_limit":
            raise Error("resource_nib_limit", "Nib archive exceeds the input byte limit", 7) from error
        raise
    nodes, archive = parse(raw)
    rows, gaps = [], set()
    if kind in ("all", "connections"):
        rows, gaps = connections(nodes)
    if kind in ("all", "labels"):
        labels, label_gaps = button_labels(nodes)
        rows.extend(labels)
        gaps.update(label_gaps)
    source = {"policy": POLICY, "bundle_name": Path(path).name, "relative_path": requested,
              "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "archive": archive}
    return source, rows, sorted(gaps)
