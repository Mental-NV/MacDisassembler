"""Verify a bounded set of compiler-emitted dispatch tables for evaluator use."""
import re

from aggregate_compat import Unsupported, source_parts
from audit_core_data_references import NUM, references
from audit_core_instructions import expected_branch
from macscope.dispatch_tables import UnverifiedDispatch, table_entries
from macscope.macho import thin


VA = r"0x[0-9a-f]+"

# Match from function entry through the back edge or the indirect call.
# A colon names an instruction address. A leading question mark allows omission.
# Branch destinations are checked against the named addresses separately.
SHAPES = {
    ("arm64", "linear"): r"""
sub sp, sp, #NUM
stp x29, x30, \[sp, #(?P<frame>NUM)\]
add x29, sp, #(?P=frame)
sturb w0, (?P<selector>\[x29, #NUM\])
str x1, (?P<left>\[sp, #NUM\])
str x2, (?P<right>\[sp, #NUM\])
str xzr, \[sp\]
b (?P<enter>VA)
guard: ldr x8, \[sp\]
subs x8, x8, #(?P<count>NUM)
b\.hs (?P<fail>VA)
b (?P<test>VA)
tag: ldr x8, \[sp\]
lsl x9, x8, #(?P<shift>NUM)
tag_base: adrp x8, VA
add x8, x8, #NUM
ldrsb w8, \[x8, x9\]
ldursb w9, (?P=selector)
subs w8, w8, w9
b\.ne (?P<next>VA)
b (?P<load>VA)
slot: ldr x9, \[sp\]
ptr_base: adrp x8, VA
add x8, x8, #NUM
add x8, x8, x9, lsl #(?P=shift)
ldr x8, \[x8, #(?P<field>NUM)\]
ldr x0, (?P=left)
ldr x1, (?P=right)
call: blr x8
stur x0, \[x29, #NUM\]
stur x1, \[x29, #NUM\]
b (?P<done>VA)
advance: b (?P<increment>VA)
step: ldr x8, \[sp\]
add x8, x8, #(?:0x)?1
str x8, \[sp\]
b (?P<back>VA)
""",
    ("x86_64", "linear"): r"""
pushq %rbp
movq %rsp, %rbp
subq \$NUM, %rsp
movb %dil, %al
movb %al, (?P<selector>NUM\(%rbp\))
movq %rsi, (?P<left>NUM\(%rbp\))
movq %rdx, (?P<right>NUM\(%rbp\))
movq \$(?:0x)?0, (?P<index>NUM\(%rbp\))
guard: cmpq \$(?P<count>NUM), (?P=index)
jae (?P<fail>VA)
movq (?P=index), %rcx
tag_base: leaq NUM\(%rip\), %rax
shlq \$(?P<shift>NUM), %rcx
addq %rcx, %rax
movsbl \(%rax\), %eax
movsbl (?P=selector), %ecx
cmpl %ecx, %eax
jne (?P<next>VA)
movq (?P=index), %rcx
ptr_base: leaq NUM\(%rip\), %rax
shlq \$(?P=shift), %rcx
addq %rcx, %rax
movq (?P<field>NUM)\(%rax\), %rax
movq (?P=left), %rdi
movq (?P=right), %rsi
call: callq \*%rax
movq %rax, NUM\(%rbp\)
movl %edx, NUM\(%rbp\)
jmp (?P<done>VA)
advance: jmp (?P<increment>VA)
step: movq (?P=index), %rax
addq \$(?:0x)?1, %rax
movq %rax, (?P=index)
jmp (?P<back>VA)
""",
    ("arm64", "masked"): r"""
mov x8, x0
mov x0, #(?:0x)?0
sub w9, w8, #(?P<bias>NUM)
mov w8, #NUM
?movk w8, #NUM, lsl #16
cmp w9, #(?P<last>NUM)
b\.hi (?P<fail>VA)
mov w10, #(?P<mask>NUM)
lsr w10, w10, w9
tbz w10, #(?:0x)?0, (?P=fail)
stp x29, x30, \[sp, #-0x10\]!
mov x29, sp
and x8, x9, #0xff
ptr_base: adrp x9, VA
add x9, x9, #NUM
ldr x8, \[x9, x8, lsl #3\]
ldr x8, \[x8, #(?P<field>NUM)\]
mov x0, x1
mov x1, x2
call: blr x8
""",
    ("x86_64", "masked"): r"""
movl %edi, %ecx
addb \$-(?P<bias>NUM), %cl
cmpb \$(?P<count>NUM), %cl
setb %al
movb \$(?P<mask>NUM), %dil
shrb %cl, %dil
andb %al, %dil
cmpb \$(?:0x)?1, %dil
jne (?P<fail>VA)
pushq %rbp
movq %rsp, %rbp
movzbl %cl, %eax
ptr_base: leaq NUM\(%rip\), %rcx
movq \(%rcx,%rax,8\), %rax
movq %rsi, %rdi
movq %rdx, %rsi
call: callq \*(?P<field>NUM)\(%rax\)
""",
}


def compile_shape(shape):
    lines = []
    for line in shape.strip().splitlines():
        optional = line.startswith("?")
        line = line.removeprefix("?")
        label, separator, expression = line.partition(": ")
        address = rf"(?P<{label}>{VA})" if separator else VA
        instruction = address + " " + (expression if separator else line) + r"\n"
        lines.append(rf"(?:{instruction})?" if optional else instruction)
    return re.compile("".join(lines).replace("NUM", NUM).replace("VA", VA))


SHAPES = {key: compile_shape(shape) for key, shape in SHAPES.items()}


def machine_layout(instructions, arch):
    listing = []
    entry = end = next(iter(instructions), None)
    for address, (raw, mnemonic, operands) in instructions.items():
        if address != end or not raw:
            raise Unsupported("noncontiguous_dispatch_instructions")
        end = address + len(raw)
        operand = re.split(r";|##|\s+<", operands, maxsplit=1)[0].strip()
        listing.append(f"{address:#x} {mnemonic} {operand}".rstrip() + "\n")
    listing = "".join(listing)
    for kind in ("linear", "masked"):
        pattern = SHAPES.get((arch, kind))
        match = pattern.match(listing) if pattern else None
        if match:
            break
    else:
        raise Unsupported("unsupported_dispatch_instruction_shape")

    fields = {key: int(value, 0) for key, value in match.groupdict().items() if re.fullmatch(NUM, value)}
    call = fields["call"]
    suffix = list(instructions.items())[listing.count("\n", 0, match.end()):]
    exits = {address for address, _ in suffix}
    if fields["fail"] not in exits:
        raise Unsupported("unverified_dispatch_failure_edge")
    # After the guarded region there must be no edge that can reenter it.
    for _, (_, mnemonic, operands) in suffix:
        branch = expected_branch(arch, mnemonic, operands)
        computed = (mnemonic.startswith(("br", "blr")) if arch == "arm64"
                    else mnemonic.startswith(("j", "call")) and operands.startswith("*"))
        if computed or (branch and not safe_exit_branch(branch, exits, entry, end)):
            raise Unsupported("unverified_dispatch_exit_flow")

    refs, _ = references(instructions, arch)
    bases = {int(row["origin_instruction_va"], 16): int(row["target_va"], 16) for row in refs}
    base = bases.get(fields["ptr_base"])
    field = fields["field"]
    if arch == "arm64" and kind == "linear" and base is not None:
        base -= field  # The linear ARM reference includes the final field offset.
    if base is None or base % 8 or field != 8:
        raise Unsupported("unverified_dispatch_table_address")

    if kind == "linear":
        if (fields.get("enter", fields["guard"]) != fields["guard"]
                or fields.get("test", fields.get("tag")) != fields.get("tag")
                or fields.get("load", fields.get("slot")) != fields.get("slot")
                or fields["next"] != fields["advance"] or fields["increment"] != fields["step"]
                or fields["back"] != fields["guard"] or fields["done"] not in exits
                or fields["shift"] != 4 or not 1 <= fields["count"] <= 32
                or bases.get(fields["tag_base"]) != base):
            raise Unsupported("unverified_dispatch_scan")
        tag_operand = instructions[fields["tag_base"]][2]
        tag_symbol = re.search(r"<([A-Za-z_]\w*)>$", tag_operand)
        if arch == "arm64" and int(tag_operand.split()[1], 16) != base:
            tag_symbol = None
        return {"kind": kind, "base_va": base, "call_va": call, "field": field,
                "stride": 16, "count": fields["count"],
                "tag_symbol": tag_symbol[1] if tag_symbol else None}
    count = fields["last"] + 1 if arch == "arm64" else fields["count"]
    width = 32 if arch == "arm64" else 8
    if (not 0 <= fields["bias"] <= 255 or not 1 <= count <= width
            or not 0 < fields["mask"] < (1 << count)):
        raise Unsupported("unverified_dispatch_index_domain")
    return {"kind": kind, "base_va": base, "call_va": call, "field": field,
            "stride": 8, "count": count, "bias": fields["bias"], "mask": fields["mask"]}


def safe_exit_branch(branch, exits, entry, end):
    kind, target = branch
    return target is not None and (target in exits if kind == "jump" else not entry <= target < end)


def table_targets(binary, instructions):
    """Return evaluator-only table evidence from exact decoded code and Mach-O bytes."""
    image = thin(binary)
    layout = machine_layout(instructions, image["arch"])
    try:
        slots = table_entries(binary, image, layout)
    except UnverifiedDispatch as error:
        raise Unsupported(str(error)) from error
    return dict(layout, base_va=hex(base), call_va=hex(layout["call_va"]), slots=slots)


POINTER_LABEL = r"PTR_[A-Za-z0-9_]+_([0-9a-f]+)"
INDEX = r"[a-z]{1,3}Var[0-9]+|local_[0-9a-f]+"
INDIRECT_ARGUMENTS = r"\(\s*(param_[0-9]+)\s*,\s*(param_[0-9]+)\s*\)"
LINEAR_CALL = re.compile(
    rf"\(\*\(code \*\)\(&{POINTER_LABEL}\)\[(({INDEX})\s*\*\s*({NUM}))\]\)"
    + INDIRECT_ARGUMENTS
)
LINEAR_TAG = re.compile(rf"\(&(?!PTR_)([A-Za-z_]\w*)\)\[(({INDEX})\s*\*\s*({NUM}))\]")
MASKED_CALL = re.compile(
    rf"\(\*\*\(code \*\*\)\(\(&{POINTER_LABEL}\)\[((?:\(ulong\))?(?:{INDEX})"
    rf"(?:\s*&\s*0xff)?)\]\s*\+\s*({NUM})\)\)" + INDIRECT_ARGUMENTS
)
TWO_WORDS = r"(?:long|ulong|undefined8)\s+param_[0-9]+\s*,\s*(?:long|ulong|undefined8)\s+param_[0-9]+"
HELPER = re.compile(r"\bgh_dispatch_(?:call|tag)\b")


def only_match(pattern, body):
    matches = list(pattern.finditer(body))
    if len(matches) != 1:
        raise Unsupported("unsupported_printed_dispatch_expression")
    return matches[0]


def bound_source(record, sources, names_by_address, layout):
    """Replace only verified data accesses and the single printed computed call."""
    root = record["name"]
    result, parameters, body, arity = source_parts(sources[root], root)
    if "[" not in result:
        raise Unsupported("aggregate_abi_unverified")
    if arity != 3 or HELPER.search(body):
        raise Unsupported("unsupported_dispatch_declaration")
    base = int(layout["base_va"], 16)
    field = layout["field"]
    slots = layout["slots"]
    dependencies = []
    for slot in slots:
        name = names_by_address.get(slot["target_va"])
        if name not in sources:
            raise Unsupported("missing_dispatch_definition")
        ret, args, _, _ = source_parts(sources[name], name)
        if "[" not in ret or not re.fullmatch(TWO_WORDS, args.strip()):
            raise Unsupported("unverified_dispatch_target_abi")
        dependencies.append(name)
    helpers = {}
    if layout["kind"] == "linear":
        call = only_match(LINEAR_CALL, body)
        label, expression, variable, scale, left, right = call.groups()
        factor = layout["stride"] // 8
        if int(label, 16) != base + field or int(scale, 0) != factor:
            raise Unsupported("printed_dispatch_pointer_disagrees")
        tag = only_match(LINEAR_TAG, body)
        symbol, tag_expression, tag_variable, tag_scale = tag.groups()
        if (symbol not in (layout["tag_symbol"], f"DAT_{base:x}") or variable != tag_variable
                or int(tag_scale, 0) != layout["stride"] or tag.end() > call.start()):
            raise Unsupported("printed_dispatch_tag_disagrees")
    else:
        call = only_match(MASKED_CALL, body)
        label, expression, offset, left, right = call.groups()
        factor = 1
        if int(label, 16) != base or int(offset, 0) != field:
            raise Unsupported("printed_dispatch_pointer_disagrees")

    cases = [f"    case {slot['index'] * factor}: return {name}(left, right);"
             for slot, name in zip(slots, dependencies)]
    helpers["gh_dispatch_call"] = (
        "\n".join(["static gh_bits gh_dispatch_call(ulong index, undefined8 left, undefined8 right) {",
                   "  switch (index) {", *cases, "    default: abort();", "  }", "}"]),
        dependencies,
    )
    body = body[:call.start()] + f"gh_dispatch_call({expression}, {left}, {right})" + body[call.end():]
    if layout["kind"] == "linear":
        cases = [f"    case {slot['index'] * layout['stride']}: return (char){slot['tag']};"
                 for slot in slots]
        helpers["gh_dispatch_tag"] = (
            "\n".join(["static char gh_dispatch_tag(ulong index) {", "  switch (index) {",
                       *cases, "    default: abort();", "  }", "}"]),
            (),
        )
        body = body[:tag.start()] + f"gh_dispatch_tag({tag_expression})" + body[tag.end():]
    return dict(sources, **{root: f"{result} {root}({parameters})\n{{{body}}}\n"}), helpers


def bind_dispatch(record, sources, names_by_address, layout, decoded):
    call = layout["call_va"]
    captures = [row for row in record["instructions"] if "COMPUTED_CALL" in row["flow"]]
    if (len(captures) != 1 or captures[0]["addr"] != call
            or bytes.fromhex(captures[0]["bytes"]) != decoded[int(call, 16)][0]
            or any(row["from"] == call and "CALL" in row["type"] for row in record["xrefs_from_sample"])):
        raise Unsupported("unconfirmed_captured_indirect_call")
    return bound_source(record, sources, names_by_address, layout)
