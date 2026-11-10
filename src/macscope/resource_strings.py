"""Decode one flat localization table without loading an application or archive."""
import codecs
import hashlib
from pathlib import Path
import re
import struct
from xml.parsers import expat
from xml.etree import ElementTree

from . import bundle
from .errors import Error


POLICY = "macscope-resource-strings/1"
MAX_BYTES = 1024 * 1024
MAX_KEYS = 16384
MAX_CHARACTERS = 1024 * 1024
TOKENS = re.compile(r'\s+|//[^\r\n]*|/\*.*?\*/|"(?:[^"\\]|\\[\s\S])*"|[A-Za-z0-9_.$/:-]+|[=;{}]', re.DOTALL)
ESCAPE = re.compile(r'\\(U[0-9a-fA-F]{4}|[0-7]{1,3}|[\s\S])')
ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}


def tokens(text):
    position = 0
    while position < len(text):
        token = TOKENS.match(text, position)
        if token is None:
            raise ValueError("Unexpected localization token")
        position = token.end()
        value = token[0]
        if not value.isspace() and not value.startswith(("//", "/*")):
            yield value


def unescape(match):
    value = match[1]
    if value.startswith("U"):
        if len(value) != 5:
            raise ValueError("Incomplete Unicode escape")
        return chr(int(value[1:], 16))
    if value[0] in "01234567":
        number = int(value, 8)
        if number > 127:
            raise Error("resource_strings_unsupported", "Non-ASCII octal escapes are unsupported", 3)
        return chr(number)
    return ESCAPES.get(value, value)


def atom(value):
    if value in (None, "=", ";", "{", "}"):
        raise ValueError("Expected a localization string")
    if value.startswith('"'):
        value = ESCAPE.sub(unescape, value[1:-1])
        # OpenStep Unicode escapes represent UTF-16 code units.
        return value.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
    return value


def text_pairs(text):
    stream = iter(tokens(text))
    current = next(stream, None)
    wrapped = current == "{"
    if wrapped:
        current = next(stream, None)
    while current is not None and current != "}":
        key = atom(current)
        separator = next(stream, None)
        value = key
        if separator == "=":
            value = atom(next(stream, None))
            separator = next(stream, None)
        if separator != ";":
            raise ValueError("Expected a localization entry terminator")
        yield key, value
        current = next(stream, None)
    if (wrapped and (current != "}" or next(stream, None) is not None)) or (not wrapped and current is not None):
        raise ValueError("Unexpected end of localization dictionary")


def xml_pairs(raw, encoding):
    builder = ElementTree.TreeBuilder()
    depth = 0

    def start(tag, attributes):
        nonlocal depth
        allowed = (("plist",), ("dict",), ("key", "string"))
        if depth >= len(allowed) or tag not in allowed[depth]:
            raise ValueError("Expected a flat plist dictionary")
        builder.start(tag, attributes)
        depth += 1

    def end(tag):
        nonlocal depth
        builder.end(tag)
        depth -= 1

    def reject_entity(*_):
        raise ValueError("XML entity declarations are unsupported")

    def check_encoding(_, declared, __):
        if declared is not None:
            declared = declared.lower().replace("-", "")
            detected = encoding.replace("-", "")
            if declared != detected and not (declared == "utf16" and detected.startswith("utf16")):
                raise ValueError("XML encoding disagrees with the input bytes")

    parser = expat.ParserCreate()
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = builder.data
    parser.EntityDeclHandler = reject_entity
    parser.XmlDeclHandler = check_encoding
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.Parse(raw, True)
    root = builder.close()
    if len(root) != 1:
        raise ValueError("Expected a flat plist dictionary")
    dictionary = root[0]
    if len(dictionary) % 2 or (root.text or "").strip() or (dictionary.text or "").strip() or (dictionary.tail or "").strip():
        raise ValueError("Invalid plist dictionary layout")
    for key, value in zip(dictionary[::2], dictionary[1::2]):
        if (key.tag != "key" or value.tag != "string" or len(key) or len(value)
                or (key.tail or "").strip() or (value.tail or "").strip()):
            raise ValueError("Expected a plist key and string")
        yield key.text or "", value.text or ""


def binary_pairs(raw):
    offset_width, ref_width, total, root, table = struct.unpack(">6xBBQQQ", raw[-32:])
    if (not 1 <= offset_width <= 8 or not 1 <= ref_width <= 8 or root >= total
            or table < 8 or table + total * offset_width != len(raw) - 32):
        raise ValueError("Invalid binary plist trailer")
    if total > 2 * MAX_KEYS + 1:
        raise Error("resource_strings_limit", "Binary localization table exceeds the object limit", 7)
    offsets = [int.from_bytes(raw[pos:pos + offset_width], "big")
               for pos in range(table, len(raw) - 32, offset_width)]
    order = sorted(offsets)
    if order[0] < 8 or order[-1] >= table or len(set(order)) != total:
        raise ValueError("Invalid binary plist offsets")
    ends = dict(zip(order, order[1:] + [table]))

    def object_body(ref):
        if ref >= total:
            raise ValueError("Invalid binary plist object reference")
        offset = offsets[ref]
        end = ends[offset]
        kind, count = divmod(raw[offset], 16)
        position = offset + 1
        if count == 15:
            if position >= end or not 0x10 <= raw[position] <= 0x13:
                raise ValueError("Invalid binary plist count")
            width = 1 << (raw[position] - 0x10)
            position += 1
            if position + width > end:
                raise ValueError("Truncated binary plist count")
            count = int.from_bytes(raw[position:position + width], "big")
            position += width
        return kind, count, position, end

    def string(ref):
        kind, count, start, end = object_body(ref)
        width = 2 if kind == 6 else 1
        if kind not in (5, 6) or start + count * width > end:
            raise ValueError("Expected a bounded binary plist string")
        return raw[start:start + count * width].decode("utf-16-be" if kind == 6 else "ascii")

    kind, count, start, end = object_body(root)
    if kind != 13 or start + 2 * count * ref_width > end:
        raise ValueError("Expected a flat binary plist dictionary")
    if count > MAX_KEYS:
        raise Error("resource_strings_limit", "Localization table exceeds the key limit", 7)
    values = start + count * ref_width
    for key_pos in range(start, values, ref_width):
        value_pos = key_pos + count * ref_width
        yield (string(int.from_bytes(raw[key_pos:key_pos + ref_width], "big")),
               string(int.from_bytes(raw[value_pos:value_pos + ref_width], "big")))


def parse(raw):
    try:
        if raw.startswith(b"bplist00"):
            encoding, format_name, pairs = None, "binary-plist", binary_pairs(raw)
        else:
            encoding = "utf-8"
            if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
                encoding = "utf-16-le" if raw.startswith(codecs.BOM_UTF16_LE) else "utf-16-be"
                text = raw[2:].decode(encoding)
            else:
                text = raw.decode("utf-8-sig")
            if "\0" in text:
                raise ValueError("Unexpected null byte in localization text")
            if text.lstrip().startswith("<"):
                format_name, pairs = "xml-plist", xml_pairs(raw, encoding)
            else:
                format_name, pairs = "openstep-strings", text_pairs(text)
        values = {}
        characters = 0
        for key, value in pairs:
            if key in values:
                raise Error("resource_strings_duplicate", "Localization table contains a duplicate key", 5)
            characters += len(key) + len(value)
            if len(values) >= MAX_KEYS or characters > MAX_CHARACTERS:
                raise Error("resource_strings_limit", "Localization table exceeds its decoded size or key limit", 7)
            values[key] = value
    except (ValueError, LookupError, expat.ExpatError, struct.error) as error:
        raise Error("resource_strings_invalid", "Invalid or unsupported flat localization table", 5) from error
    return values, format_name, encoding


def read(path, requested):
    relative = bundle.exact_path(requested, bundle.MAX_DEPTH + 1, "resource_file",
                                 "Select an exact bundle-relative localization file")
    if relative.suffix.lower() != ".strings":
        raise Error("resource_strings_type", "Select a .strings resource file", 2)
    try:
        raw = bundle.read_resource(path, relative, MAX_BYTES)
    except Error as error:
        if error.code == "input_limit":
            raise Error("resource_strings_limit", "Localization file exceeds the input byte limit", 7) from error
        raise
    values, format_name, encoding = parse(raw)
    return {"policy": POLICY, "bundle_name": Path(path).name, "relative_path": requested,
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "format": format_name,
            "encoding": encoding}, values
