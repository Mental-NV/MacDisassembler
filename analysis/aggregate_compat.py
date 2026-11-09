"""Mechanical lowering for a bounded subset of Ghidra's printed C dialect."""
import re


POLICY = "macscope-ghidra-aggregate-compat/5"
MEMORY_STORES = frozenset(("STORE_LE16", "STORE_LE32", "STORE_LE64"))
ARM_VECTORS = frozenset(("NEON_rev64", "NEON_ext"))
BYTE_VECTORS = ARM_VECTORS | {"pshufb"}
COMMENT = re.compile(r"/\*[^*]*(?:\*(?!/)[^*]*)*\*/")
NAME = r"[A-Za-z_][A-Za-z0-9_]*"
SCALAR = r"(?:long|ulong|int|uint|bool|char|byte|void|undefined[1248])"
VECTOR_POINTER_DECL = r"undefined1\s*\(\s*\*\s*{}\s*\)\s*\[16\]"
VECTOR_POINTER = re.compile(r"\b" + VECTOR_POINTER_DECL.format(f"({NAME})"))
PARAMETER = rf"(?:{SCALAR}\s*(?:\*\s*)?param_[0-9]+|{VECTOR_POINTER_DECL.format('param_[0-9]+')})"
HEADER = re.compile(
    rf"\s*(undefined1\s*\[(?:12|16)\]|{SCALAR})\s+({NAME})\s*"
    rf"\((\s*(?:{PARAMETER}(?:\s*,\s*{PARAMETER})*)?\s*)\)\s*\{{(.*)\}}\s*",
    re.S,
)
WORD = re.compile(
    r"\s+|'(?:[^'\\\n]|\\[0nrt'\\])'|0[xX][0-9a-fA-F]+[UL]*|[0-9]+[UL]*|\._[0-9]+_[0-9]+_|"
    + NAME + r"|[{}\[\]();.=<>!+,:&|^~*/%?\-]",
)
LOCAL = re.compile(r"(?:[a-z]{1,3}Var[0-9]+|[a-z]+Stack_[0-9a-f]+|local_[0-9a-f]+|param_[0-9]+|LAB_[0-9a-f]+)")
WORDS = set("long ulong int uint bool char byte void undefined1 undefined2 undefined4 undefined8 "
            "if else while do for goto return break continue switch case default true false "
            "SCARRY8 SBORROW8 SEXT816 ZEXT816 SUB168 CONCAT88".split()) | MEMORY_STORES | BYTE_VECTORS
CALL = re.compile(rf"\b({NAME})\s*\(")
RAW_ARRAY = re.compile(r"\bundefined1\s+([a-z]{1,3}Var[0-9]+)\s*\[(12|16)\]\s*;")
UNDEFINED_STACK = re.compile(r"\bundefined[1248]\s+([a-z]+Stack_[0-9a-f]+)\s*;")
VECTOR_CAST = r"\*\s*\(\s*undefined1\s*\(\s*\*\s*\)\s*\[16\]\s*\)\s*"
VECTOR_CALL = re.compile(r"\b(NEON_rev64|NEON_ext|pshufb)\s*\(")
VECTOR_CAST_LOAD = VECTOR_CAST + r"(?:param_[0-9]+|\([^;{}]+\))"


class Unsupported(ValueError):
    """An output outside the frozen mechanical compatibility rules."""


def source_parts(text, name):
    if not isinstance(text, str) or not 0 < len(text) <= 16384:
        raise Unsupported("unbounded_source")
    text = COMMENT.sub(" ", text)
    match = HEADER.fullmatch(text)
    if not match or match[2] != name:
        raise Unsupported("unsupported_declaration")
    if not match[3].strip():
        raise Unsupported("unsupported_parameters")
    return match[1], match[3], match[4], 1 + match[3].count(",")


def check_tokens(body, names):
    cursor = depth = 0
    for token in WORD.finditer(body):
        word = token[0]
        if token.start() != cursor:
            raise Unsupported("unsupported_token")
        if re.fullmatch(NAME, word) and word not in WORDS and word not in names and not LOCAL.fullmatch(word):
            if word == "code" or word.startswith("PTR_"):
                raise Unsupported("unresolved_indirect_linkage")
            raise Unsupported("unknown_identifier:" + word)
        depth += (word == "{") - (word == "}")
        if depth < 0:
            raise Unsupported("unbalanced_body")
        cursor = token.end()
    if cursor != len(body) or depth:
        raise Unsupported("unsupported_token")


def bounds(offset, width, capacity):
    if len(offset) > 2 or len(width) > 2:
        raise Unsupported("invalid_aggregate_subfield")
    offset, width = int(offset), int(width)
    if not 0 <= offset < capacity or not 1 <= width <= capacity - offset:
        raise Unsupported("invalid_aggregate_subfield")
    return offset, width


def call_arguments(body, start):
    arguments = []
    depth = 0
    for token in WORD.finditer(body, start):
        word = token[0]
        if depth == 0 and word in (",", ")"):
            arguments.append(body[start:token.start()].strip())
            if word == ")":
                return arguments, token.end()
            start = token.end()
        elif word in ("(", "["):
            depth += 1
        elif word in (")", "]"):
            depth -= 1
        elif word in (";", "{", "}"):
            break
    raise Unsupported("unsupported_vector_call")


def lower_vector_calls(body, arrays, parameters):
    pointers = sorted(set(VECTOR_POINTER.findall(body) + VECTOR_POINTER.findall(parameters)))
    pointer = "(?:" + "|".join(pointers) + ")" if pointers else r"(?!)"
    address = rf"(?:\*\s*{pointer}|{pointer}\s*\[\s*-?[0-9]+\s*\])"

    def operand(text):
        text = text.strip()
        if arrays.get(text) == 16 or re.fullmatch(r"CONCAT88\([^;{}]+\)", text):
            return text
        if re.fullmatch(address, text) or re.fullmatch(VECTOR_CAST_LOAD, text):
            return f"gh_load_vector({text})"
        raise Unsupported("unsupported_vector_operand")

    pieces, end = [], 0
    for match in VECTOR_CALL.finditer(body):
        if match.start() < end:
            raise Unsupported("nested_vector_call")
        args, finish = call_arguments(body, match.end())
        name = match[1]
        if name == "NEON_rev64" and len(args) == 2 and args[1] == "1":
            adjusted = (operand(args[0]), "1")
        elif name == "NEON_ext" and len(args) == 4 and args[3] == "1":
            if not re.fullmatch(r"0[xX][0-9a-fA-F]|0|[1-9]|1[0-5]", args[2]):
                raise Unsupported("unsupported_vector_extract_offset")
            adjusted = (operand(args[0]), operand(args[1]), str(int(args[2], 0)), "1")
        elif name == "pshufb" and len(args) == 2:
            adjusted = tuple(map(operand, args))
        else:
            raise Unsupported("unsupported_vector_call")
        pieces += [body[end:match.start()], f"{name}({', '.join(adjusted)})"]
        end = finish
    body = "".join([*pieces, body[end:]])
    body = re.sub(rf"(?<![\w*])({address})\s*=(?!=)\s*([^;{{}}]+);",
                  lambda m: f"gh_store_vector({m[1]}, {m[2].strip()});", body)
    return body


def lower_function(text, name, functions, aggregate_required):
    return_type, params, body, arity = source_parts(text, name)
    result_width = int(return_type.split("[")[1][:-1]) if "[" in return_type else None
    if aggregate_required and result_width is None:
        raise Unsupported("aggregate_abi_unverified")
    check_tokens(body, functions)
    declarations = set(RAW_ARRAY.findall(body))
    arrays = {variable: int(width) for variable, width in declarations}
    if len(arrays) != len(declarations):
        raise Unsupported("ambiguous_aggregate_width")
    if any(intrinsic in body for intrinsic in BYTE_VECTORS):
        body = lower_vector_calls(body, arrays, params)
    undefined = set(UNDEFINED_STACK.findall(body))
    body = RAW_ARRAY.sub(r"gh_bits \1 = {0};", body)
    body = UNDEFINED_STACK.sub("", body)
    if arrays:
        name_pattern = "(?:" + "|".join(sorted(arrays)) + ")"
        slot = rf"\b({name_pattern})(?:\._([0-9]+)_([0-9]+)_|\[([0-9]+)\])"

        def coordinates(match):
            offset, width = (match[2], match[3]) if match[4] is None else (match[4], "1")
            return bounds(offset, width, arrays[match[1]])

        def store(match):
            offset, width = coordinates(match)
            expression = match[5].strip()
            if expression in undefined:
                return f"gh_undef(&{match[1]}, {offset}, {width});"
            return f"gh_set(&{match[1]}, {offset}, {width}, ({expression}));"

        body = re.sub(slot + r"\s*=(?!=)\s*([^;{}]+);", store, body)

        def read(match):
            offset, width = coordinates(match)
            if width not in (1, 2, 4, 8):
                raise Unsupported("unsupported_aggregate_read_width")
            return f"((uint{width*8}_t)gh_read({match[1]}, {offset}, {width}))"

        body = re.sub(slot, read, body)
        # An explicitly sign-extended operand establishes the wide multiplication
        # form. Untyped aggregate division and other operators stay unlowered.
        wide_arrays = [variable for variable, width in sorted(arrays.items()) if width == 16]
        if wide_arrays:
            wide = "|".join(wide_arrays)
            body = re.sub(rf"\b({wide})\s*\*\s*(?=SEXT816\()", r"gh_signed(\1) * ", body)
    else:
        name_pattern = r"(?!)"

    def fit(expression, width):
        return expression if width == 16 else f"gh_low_bytes({expression}, {width})"

    def value(expression):
        expression = expression.strip()
        if re.fullmatch(name_pattern, expression):
            return expression
        shift = re.fullmatch(rf"({name_pattern})\s*<<\s*(0[xX][0-9a-fA-F]{{1,2}}|0|[1-9][0-9]{{0,2}})", expression)
        if shift:
            bits = int(shift[2], 0)
            if bits % 8 or not 0 <= bits < 128:
                raise Unsupported("unsupported_aggregate_shift")
            return fit(f"gh_shift({shift[1]}, {bits // 8})", arrays[shift[1]])
        call = CALL.match(expression)
        if call and (call[1] in functions or call[1] in BYTE_VECTORS or call[1] == "CONCAT88"):
            return expression
        if re.match(r"(?:ZEXT816|SEXT816)\s*\(", expression):
            return f"gh_known(({expression}))"
        raise Unsupported("unsupported_aggregate_expression")

    body = re.sub(rf"\b({name_pattern})\s*=(?!=)\s*([^;{{}}]+);",
                  lambda m: f"{m[1]} = {fit(value(m[2]), arrays[m[1]])};", body)
    if result_width is not None:
        body = re.sub(r"\breturn\s+([^;{}]+);", lambda m: f"return {fit(value(m[1]), result_width)};", body)
        return_type = "gh_bits"
    if any(re.search(rf"\b{re.escape(stack)}\b", body) for stack in undefined):
        raise Unsupported("undefined_stack_value_consumed")
    if re.search(r"\._[0-9]+_[0-9]+_", body):
        raise Unsupported("unrecognized_aggregate_object")
    # Preserve printed argument types and arity. Clang checks direct calls.
    return f"{return_type} {name}({params})\n{{{body}}}\n", arity


def lower_closure(root, records, expected_arity, *, aggregate_required=True):
    """Resolve direct calls to their captured definitions, with no oracle stubs."""
    emitted, active = {}, set()

    def visit(name):
        if name in emitted:
            return
        if name in active:
            raise Unsupported("recursive_dependency")
        if len(emitted) + len(active) >= 32:
            raise Unsupported("dependency_limit")
        active.add(name)
        body = source_parts(records[name], name)[2]
        lowered, arity = lower_function(records[name], name, records.keys(), aggregate_required and name == root)
        if name == root and arity != expected_arity:
            raise Unsupported("unsupported_root_arity")
        for call in dict.fromkeys(CALL.findall(body)):
            if call in records:
                visit(call)
        active.remove(name)
        emitted[name] = lowered

    visit(root)
    return "\n".join(emitted.values()), list(emitted)
