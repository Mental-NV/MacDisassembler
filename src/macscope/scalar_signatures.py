"""Binary evidence for a direct scalar result or the Darwin stack-check ABI."""
from . import dyld
from .direct_signatures import direct_edges
from .dispatch_returns import instruction_bytes, signed
from .dispatch_tables import UnverifiedDispatch
from .errors import Error
from .macho import thin


POLICY = "macscope-scalar-call-signatures/1"
MAX_SITES = 16
STACK_FAILURE = "___stack_chk_fail"
SYSTEM_LIBRARY = "/usr/lib/libSystem.B.dylib"
EAX_TESTS = (b"\x83\xf8\x00", b"\x85\xc0")
EAX_EXTEND = b"\x0f\xb6\xc0"


def sequence(code, addresses):
    return [{"va": hex(va), "bytes": code[va].hex()} for va in addresses]


def branch_target(site, code):
    raw = code[site]
    if len(raw) == 2 and (0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb):
        return site + 2 + signed(raw[1:])
    if len(raw) == 5 and raw[0] == 0xe9:
        return site + 5 + signed(raw[1:])
    if len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return site + 6 + signed(raw[2:])
    return None


def extended_result(code, function):
    """Check the entire leaf, with a single exit and no path around MOVZX."""
    tail = list(code)[-3:]
    if len(tail) >= 2 and code[tail[-2]] == EAX_EXTEND:
        tail = tail[-2:]
    if [code[va] for va in tail] not in ([EAX_EXTEND, b"\xc3"], [EAX_EXTEND, b"\x5d", b"\xc3"]):
        return False
    bypass = set(tail[1:])
    for ins in function["instructions"]:
        va = int(ins["addr"], 16)
        flow = ins["flow"]
        if flow in ("CONDITIONAL_JUMP", "UNCONDITIONAL_JUMP"):
            branch = branch_target(va, code)
            if branch not in code or branch in bypass:
                return False
        elif flow != ("TERMINATOR" if va == tail[-1] else "FALL_THROUGH"):
            return False
    return True


def x86_requests(binary, image, root, functions):
    starts = image["loader"]["function_starts"]
    if not starts or starts["status"] != "complete":
        return []
    linker = set(starts["addresses"])
    records = {f["entry_va"]: f for f in functions if f["entry_va"] in linker and not f["is_external"]
               and not f["is_thunk"] and f["decompile_status"] == "complete"}
    entry = root["entry_va"]
    if entry not in records:
        return []

    references = root["xrefs_to_entry"]
    callers = {entry}
    if (not root["xrefs_to_entry_truncated"] and not root["xrefs_to_entry_error"]
            and root["xrefs_to_entry_count"] == len(references) <= MAX_SITES):
        # Resolve incoming site ownership by exact instruction address, independently of names.
        sites = {r["from"] for r in references if r["type"] == "UNCONDITIONAL_CALL"}
        if sites:
            callers.update(f["entry_va"] for f in records.values() if any(i["addr"] in sites for i in f["instructions"]))

    proofs = {}
    for caller_va in sorted(callers):
        caller = records[caller_va]
        try:
            code = instruction_bytes(binary, image, caller, 8192)
            for site, callee_va in direct_edges(code, caller, records):
                if (caller_va != entry and callee_va != entry or callee_va == caller_va
                        or callee_va in proofs or code.get(site + 5) not in EAX_TESTS):
                    continue
                callee = records[callee_va]
                try:
                    leaf = instruction_bytes(binary, image, callee, 1024)
                except UnverifiedDispatch:
                    continue
                if extended_result(leaf, callee):
                    proofs[callee_va] = {
                        "kind": "zero_extended_eax", "caller_va": caller_va, "call_va": hex(site),
                        "target_va": callee_va, "caller": sequence(code, (site, site + 5)),
                        "leaf": sequence(leaf, leaf),
                    }
        except UnverifiedDispatch:
            continue
    return list(proofs.values())


def arm_stub(binary, image, address):
    """Resolve the ordinary arm64 ADRP/LDR/BR Mach-O import stub."""
    if address % 4:
        return None
    sections = [s for s in image["sections"] if (s["segment"], s["name"]) == ("__TEXT", "__stubs")
                and s["file_offset"] is not None and int(s["va"], 16) <= address
                and address + 12 <= int(s["va"], 16) + int(s["size"], 16)]
    if len(sections) != 1:
        return None
    section, = sections
    offset = int(section["file_offset"], 16) + address - int(section["va"], 16)
    raw = binary[offset:offset + 12]
    if len(raw) != 12:
        return None
    adrp, ldr, br = (int.from_bytes(raw[i:i + 4], "little") for i in (0, 4, 8))
    if adrp & 0x9f00001f != 0x90000010 or ldr & 0xffc003ff != 0xf9400210 or br != 0xd61f0200:
        return None
    page = (adrp >> 29 & 3) | (adrp >> 5 & 0x7ffff) << 2
    page -= 1 << 21 if page & (1 << 20) else 0
    slot = (address & ~0xfff) + (page << 12) + (ldr >> 10 & 0xfff) * 8
    if not 0 <= slot < 1 << 64:
        return None
    code = {address + i: raw[i:i + 4] for i in (0, 4, 8)}
    return hex(slot), sequence(code, code)


def arm_requests(binary, image, root, functions):
    thunks = {f["entry_va"] for f in functions if f["is_thunk"] and not f["is_external"]}
    code = instruction_bytes(binary, image, root, 8192)
    facet = root["coverage"]["xrefs_from"]
    refs = root["xrefs_from_sample"]
    if facet["status"] != "complete" or facet["truncated"] or facet["error"] or facet["emitted"] != len(refs):
        return []
    calls = {}
    for ref in refs:
        if "CALL" in ref["type"]:
            calls.setdefault(ref["from"], set()).add((ref["type"], ref["to"], ref["is_external"]))
    _, fixups, gaps = dyld.fixups(binary, dict(image, offset="0x0"), parsed=image)
    if gaps:
        return []
    binds = [r for r in fixups if r["kind"] == "bind" and r["symbol"] == STACK_FAILURE
             and r["library"] == SYSTEM_LIBRARY and not r["weak_import"]
             and r["import_addend"] == r.get("inline_addend", 0) == 0]
    if len(binds) != 1:
        return []
    proofs = []
    for site, raw in code.items():
        word = int.from_bytes(raw, "little")
        if len(raw) != 4 or word >> 26 != 0b100101:
            continue
        delta = word & 0x3ffffff
        target = site + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta)
        if hex(target) not in thunks or calls.get(hex(site)) != {("UNCONDITIONAL_CALL", hex(target), False)}:
            continue
        stub = arm_stub(binary, image, target)
        if stub is not None and stub[0] == binds[0]["va"]:
            proofs.append({
                "kind": "darwin_stack_failure", "caller_va": root["entry_va"], "call_va": hex(site),
                "target_va": hex(target), "caller": sequence(code, (site,)), "stub": stub[1],
                "bind_va": stub[0],
            })
    return proofs


def request(binary, image, root, functions):
    plan = {"policy": POLICY, "image_sha256": image["sha256"], "entry_va": root["entry_va"], "requests": []}
    try:
        parsed = thin(binary)
        policy = {"x86_64": x86_requests, "arm64": arm_requests}.get(parsed["arch"])
        proofs = policy(binary, parsed, root, functions) if policy is not None else []
        if len(proofs) > MAX_SITES:
            raise UnverifiedDispatch("scalar_signature_site_limit")
        plan["requests"] = proofs
    except UnverifiedDispatch as error:
        plan["skipped_reason"] = str(error)
    except Error as error:
        plan["skipped_reason"] = error.code
    if not plan["requests"]:
        plan.setdefault("skipped_reason", "no_verified_scalar_calls")
    return plan


def decision(plan, report):
    result = {"entry_va": plan["entry_va"], "status": "skipped"}
    if not plan["requests"] and report is None:
        return dict(result, reason=plan["skipped_reason"])
    error = Error("scalar_signature_result", "Worker reported different scalar signature evidence", 10)
    if (not plan["requests"] or not isinstance(report, dict) or report.get("policy") != POLICY
            or report.get("entry_va") != plan["entry_va"] or not isinstance(report.get("results"), list)
            or len(report["results"]) != len(plan["requests"])):
        raise error
    applied, skipped = [], []
    for proof, row in zip(plan["requests"], report["results"]):
        site = {key: proof[key] for key in ("kind", "caller_va", "call_va", "target_va")}
        if not isinstance(row, dict) or any(row.get(key) != value for key, value in site.items()):
            raise error
        if row.get("status") == "applied":
            abi = {"return_storage": "EAX:4"} if proof["kind"] == "zero_extended_eax" else {
                "bind_va": proof["bind_va"], "prototype": "void (void)", "noreturn": True,
            }
            if any(row.get(key) != value for key, value in abi.items()):
                raise error
            applied.append(site | abi)
        elif row.get("status") == "skipped" and row.get("reason") in (
                "unsupported_callee_signature", "protected_callee_signature"):
            skipped.append(dict(site, reason=row["reason"]))
        else:
            raise error
    return dict(result, status="applied" if applied else "skipped", applied=applied, skipped=skipped)
