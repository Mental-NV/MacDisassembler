"""Mechanical lowering for a bounded subset of Ghidra's printed C dialect."""
import re


POLICY = "macscope-ghidra-aggregate-compat/4"
MEMORY_STORES = frozenset(("STORE_LE16", "STORE_LE32", "STORE_LE64"))
BYTE_VECTORS = frozenset(("NEON_rev64", "NEON_ext"))
COMMENT = re.compile(r"/\*[^*]*(?:\*(?!/)[^*]*)*\*/")
NAME = r"[A-Za-z_][A-Za-z0-9_]*"
SCALAR = r"(?:long|ulong|int|uint|bool|char|byte|void|undefined[1248])"
HEADER = re.compile(
    rf"\s*(undefined1\s*\[(?:12|16)\]|{SCALAR})\s+({NAME})\s*\(([^()]*)\)\s*\{{(.*)\}}\s*",
    re.S,
)
ARGUMENT = re.compile(rf"\s*{SCALAR}\s*(?:\*\s*)?(param_[0-9]+)\s*")
WORD = re.compile(
    r"\s+|'(?:[^'\\\n]|\\[0nrt'\\])'|0[xX][0-9a-fA-F]+[UL]*|[0-9]+[UL]*|\._[0-9]+_[0-9]+_|"
    + NAME + r"|[{}\[\]();.=<>!+,:&|^~*/%?\-]",
)
LOCAL = re.compile(r"(?:[a-z]{1,3}Var[0-9]+|[a-z]+Stack_[0-9a-f]+|local_[0-9a-f]+|param_[0-9]+|LAB_[0-9a-f]+)")
WORDS = set("long ulong int uint bool char byte void undefined1 undefined2 undefined4 undefined8 "
            "if else while do for goto return break continue switch case default true false "
            "SCARRY8 SBORROW8 SEXT816 ZEXT816 SUB168".split()) | MEMORY_STORES | BYTE_VECTORS
CALL = re.compile(rf"\b({NAME})\s*\(")
RAW_ARRAY = re.compile(r"\bundefined1\s+([a-z]{1,3}Var[0-9]+)\s*\[(12|16)\]\s*;")
UNDEFINED_STACK = re.compile(r"\bundefined[1248]\s+([a-z]+Stack_[0-9a-f]+)\s*;")
VECTOR_POINTER = re.compile(r"\bundefined1\s*\(\s*\*\s*([a-z]{1,3}Var[0-9]+)\s*\)\s*\[16\]\s*;")
VECTOR_CAST = r"\*\s*\(\s*undefined1\s*\(\s*\*\s*\)\s*\[16\]\s*\)\s*"
VECTOR_ARG = r"([^,;{}]+?)"


class Unsupported(ValueError):
    """An output outside the frozen mechanical compatibility rules."""


def source_parts(text, name):
    if not isinstance(text, str) or not 0 < len(text) <= 16384:
        raise Unsupported("unbounded_source")
    text = COMMENT.sub(" ", text)
    match = HEADER.fullmatch(text)
    if not match or match[2] != name:
        raise Unsupported("unsupported_declaration")
    args = match[3].split(",")
    if not all(ARGUMENT.fullmatch(arg) for arg in args):
        raise Unsupported("unsupported_parameters")
    return match[1], match[3], match[4], len(args)


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


def lower_vector_calls(body, arrays):
    pointers = sorted(set(VECTOR_POINTER.findall(body)))
    pointer = "(?:" + "|".join(pointers) + ")" if pointers else r"(?!)"
    address = rf"(?:\*\s*{pointer}|{pointer}\s*\[\s*-?[0-9]+\s*\])"

    def operand(text):
        text = text.strip()
        if arrays.get(text) == 16:
            return text
        if re.fullmatch(address, text) or re.fullmatch(VECTOR_CAST + r"(?:param_[0-9]+|\([^;{}]+\))", text):
            return f"gh_load_vector({text})"
        raise Unsupported("unsupported_vector_operand")

    def extract(match):
        index = int(match[3], 0)
        if not 0 <= index < 16:
            raise Unsupported("unsupported_vector_extract_offset")
        return f"NEON_ext({operand(match[1])}, {operand(match[2])}, {index}, 1)"

    body = re.sub(rf"\bNEON_rev64\s*\(\s*{VECTOR_ARG}\s*,\s*1\s*\)",
                  lambda m: f"NEON_rev64({operand(m[1])}, 1)", body)
    body = re.sub(rf"\bNEON_ext\s*\(\s*{VECTOR_ARG}\s*,\s*{VECTOR_ARG}\s*,\s*"
                  r"(0[xX][0-9a-fA-F]{1,2}|0|[1-9][0-9]?)\s*,\s*1\s*\)", extract, body)
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
        body = lower_vector_calls(body, arrays)
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
        if call and (call[1] in functions or call[1] in BYTE_VECTORS):
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
