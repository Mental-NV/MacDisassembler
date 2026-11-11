"""Bounded presentation of Objective-C encodings, never ABI/type application."""
import json
import re


LEGACY_POLICY = "objc-type-encoding/v1"
POLICY = "objc-type-encoding/v2"
POLICIES = (LEGACY_POLICY, POLICY)
MAX_INPUT = 4096
MAX_DEPTH = 32
MAX_NODES = 256
MAX_ARGUMENTS = 64
MAX_DIGITS = 10
MAX_RESULT_BYTES = 65536
SCALARS = dict(zip("cislqCISLQfdDBv", (
    "char", "int", "short", "long", "long long", "unsigned char", "unsigned int",
    "unsigned short", "unsigned long", "unsigned long long", "float", "double",
    "long double", "bool", "void")))
QUALIFIERS = dict(zip("rnNoORV", ("const", "in", "inout", "out", "bycopy", "byref", "oneway")))
IDENTIFIER = r"[A-Za-z_$][A-Za-z0-9_$]*"
OBJECT_NAME = re.compile(r"[A-Za-z_$][A-Za-z0-9_$.]*(?:<" + IDENTIFIER + r">)*")
PROTOCOLS = re.compile(r"(?:<" + IDENTIFIER + r">)+")


class DecodeFailure(ValueError):
    def __init__(self, status, reason, position):
        self.status, self.reason, self.position = status, reason, position


def quoted(value):
    """Quoted names are data, including control characters or source punctuation."""
    return json.dumps(value, ensure_ascii=True)


class Parser:
    def __init__(self, text, policy=POLICY):
        if policy not in POLICIES:
            raise ValueError("Unsupported Objective-C decoder policy")
        self.text, self.pos, self.nodes = text, 0, 0
        self.policy = policy

    def fail(self, reason, status="invalid"):
        raise DecodeFailure(status, reason, self.pos)

    def peek(self):
        return self.text[self.pos:self.pos + 1]

    def number(self, *, optional=False, signed=False):
        start = self.pos
        if signed and self.peek() in ("+", "-"):
            self.pos += 1
        first = self.pos
        while self.peek() and self.peek() in "0123456789":
            self.pos += 1
            if self.pos - first > MAX_DIGITS:
                self.fail("decimal_width_limit", "limited")
        if self.pos == first:
            if optional and first == start:
                return None
            self.fail("expected_decimal")
        return int(self.text[start:self.pos])

    def name(self):
        # The runtime encoding grammar encloses names in quotes; it does not
        # define source-language backslash escapes. Preserve all inner text.
        self.pos += 1
        end = self.text.find('"', self.pos)
        if end < 0:
            self.fail("unterminated_name")
        value = self.text[self.pos:end]
        self.pos = end + 1
        return value

    def type(self, depth=0, aggregate_close=None, *, opaque_target=False):
        start = self.pos
        if depth >= MAX_DEPTH:
            self.fail("nesting_limit", "limited")
        if self.nodes >= MAX_NODES:
            self.fail("type_node_limit", "limited")
        self.nodes += 1
        qualifiers = []
        while self.peek() in QUALIFIERS:
            qualifier = QUALIFIERS[self.peek()]
            if qualifier in qualifiers:
                self.fail("duplicate_qualifier")
            qualifiers.append(qualifier)
            self.pos += 1
        code = self.peek()
        if not code:
            self.fail("expected_type")
        self.pos += 1
        row = {"code": code}
        if code in SCALARS:
            row.update(kind="scalar", display=SCALARS[code])
        elif code in "*#:":
            row.update(kind={"*": "cstring", "#": "class", ":": "selector"}[code],
                       display={"*": "char *", "#": "Class", ":": "SEL"}[code])
        elif code == "@":
            if self.peek() == "?":
                self.pos += 1
                row.update(kind="block", display="block (signature unavailable)", signature=None)
            else:
                name = self.name() if self.peek() == '"' else None
                if name is not None and aggregate_close is not None and self.peek() not in ('"', aggregate_close):
                    # In {T="first"@"second"i}, the quote can introduce
                    # the next field rather than an object class. Both parses
                    # fit the optional-field-name grammar. Do not choose by
                    # capitalization or assume Clang's all-named convention.
                    self.fail("ambiguous_object_or_field_name", "unsupported")
                display = "id"
                if name is not None:
                    if OBJECT_NAME.fullmatch(name):
                        display = name + " *"
                    elif PROTOCOLS.fullmatch(name):
                        display = "id" + name
                    else:
                        display = "object " + quoted(name)
                row.update(kind="object", name=name, display=display)
        elif code == "^":
            target = self.type(depth + 1, aggregate_close, opaque_target=True)
            row.update(kind="pointer", pointee=target, display="pointer to " + target["display"])
        elif code == "[":
            count = self.number()
            element = self.type(depth + 1)
            if self.peek() != "]":
                self.fail("unterminated_array")
            self.pos += 1
            row.update(kind="array", count=count, element=element,
                       display=f"array[{count}] of " + element["display"])
        elif code in "{(":
            kind, close = ("struct", "}") if code == "{" else ("union", ")")
            first = self.pos
            while self.peek() and self.peek() not in ("=", close):
                if self.peek() in '{}()[]"':
                    self.fail("invalid_aggregate_name")
                self.pos += 1
            name = self.text[first:self.pos]
            if not name:
                self.fail("missing_aggregate_name")
            fields = None
            if self.peek() == "=":
                self.pos += 1
                fields = []
                while self.peek() and self.peek() != close:
                    field_name = self.name() if self.peek() == '"' else None
                    fields.append({"name": field_name, "type": self.type(depth + 1, close)})
            if self.peek() != close:
                self.fail("unterminated_aggregate")
            self.pos += 1
            label = "anonymous" if name == "?" else name if re.fullmatch(IDENTIFIER, name) else quoted(name)
            row.update(kind=kind, name=name, fields=fields, opaque=fields is None,
                       display=kind + " " + label)
        elif code == "?" and opaque_target and not qualifiers and self.policy == POLICY:
            row.update(kind="unknown", display="unknown pointee (signature unavailable)", signature=None)
        elif code == "b":
            width = self.number()
            row.update(kind="bitfield", width=width, display=f"bitfield[{width}]")
        else:
            self.fail("unknown_type" if code == "?" else "unsupported_type_code", "unsupported")
        row.update(qualifiers=qualifiers, encoding_span=[start, self.pos])
        if qualifiers:
            row["display"] = " ".join(qualifiers) + " " + row["display"]
        return row


def base_result(encoding, policy=None):
    policy = POLICY if policy is None else policy
    if policy not in POLICIES:
        raise ValueError("Unsupported Objective-C decoder policy")
    result = {"policy": policy, "source": "objc_type_encoding", "status": "decoded",
              "diagnostics": []}
    if encoding is None:
        return dict(result, status="unavailable", diagnostics=["type_encoding_missing"])
    if not isinstance(encoding, str) or not encoding:
        return dict(result, status="invalid", diagnostics=["empty_or_nontext_encoding"])
    if len(encoding) > MAX_INPUT:
        return dict(result, status="limited", diagnostics=["input_length_limit"])
    return result


def failed(result, error):
    # Do not expose a partial tree as a usable full declaration.
    return dict(result, status=error.status, diagnostics=[error.reason], error_offset=error.position)


def finish(result, **fields):
    decoded = dict(result, **fields)
    if len(json.dumps(decoded, ensure_ascii=True).encode('ascii')) > MAX_RESULT_BYTES:
        return dict(result, status="limited", diagnostics=["decoded_output_limit"])
    return decoded


def decode_ivar(encoding, *, policy=None):
    result = base_result(encoding, policy)
    if result["status"] != "decoded":
        return result
    parser = Parser(encoding, result["policy"])
    try:
        value = parser.type()
        if parser.pos != len(encoding):
            parser.fail("trailing_type_data")
    except DecodeFailure as error:
        return failed(result, error)
    return finish(result, type=value)


def decode_method(encoding, selector, method_kind, *, policy=None):
    result = base_result(encoding, policy)
    if result["status"] != "decoded":
        return result
    parser = Parser(encoding, result["policy"])
    try:
        return_type = parser.type()
        frame = parser.number(optional=True)
        arguments = []
        while parser.pos < len(encoding):
            if len(arguments) >= MAX_ARGUMENTS:
                parser.fail("argument_limit", "limited")
            value = parser.type()
            offset = parser.number(optional=True, signed=True)
            arguments.append({"type": value, "encoded_offset": offset})
        if (len(arguments) < 2 or arguments[0]["type"]["kind"] not in ("object", "class")
                or arguments[1]["type"]["kind"] != "selector"):
            parser.fail("invalid_hidden_arguments")
        if any(arg["type"]["code"] == "v" for arg in arguments):
            parser.fail("void_argument")
        if method_kind not in ("instance", "class"):
            parser.fail("invalid_method_kind")
        explicit = arguments[2:]
        if (not isinstance(selector, str) or selector.count(":") != len(explicit)
                or explicit and not selector.endswith(":")):
            parser.fail("selector_arity")
        parts = selector[:-1].split(":") if explicit else [selector]
        if any(not re.fullmatch(IDENTIFIER, part) and not (explicit and part == "") for part in parts):
            parser.fail("unsupported_selector_spelling", "unsupported")
        arguments[0].update(role="receiver", name="self")
        arguments[1].update(role="selector", name="_cmd")
        for index, arg in enumerate(explicit, 1):
            arg.update(role="explicit", name=f"arg{index}", name_origin="generated")
        declaration = ("+" if method_kind == "class" else "-") + " (" + return_type["display"] + ")"
        declaration += (" ".join(f"{part}:({arg['type']['display']}){arg['name']}"
                                for part, arg in zip(parts, explicit))
                        if explicit else selector)
    except DecodeFailure as error:
        return failed(result, error)
    return finish(result, return_type=return_type, encoded_frame_size=frame,
                  arguments=arguments, declaration=declaration)


def decode_row(row, scope):
    encoding = row.get("type_encoding")
    decoded = (decode_method(encoding, row["name"], row["method_kind"])
               if scope == "methods" else decode_ivar(encoding))
    return dict(row, decoded_types=decoded)
