"""Machine evidence for an observed integer result forwarded through a wrapper."""
from . import callee_parameters
from .direct_signatures import arm64_direct_target, direct_edges
from .dispatch_returns import direct_target, instruction_bytes, signed
from .dispatch_tables import UnverifiedDispatch
from .errors import Error
from .macho import thin
from .scalar_signatures import sequence


POLICY = "macscope-forwarded-return/1"
RETURN_REGISTERS = {"arm64": "x0", "x86_64": "RAX"}
MAX_OBSERVER_REFS = 16
MAX_OBSERVER_INSTRUCTIONS = 8


def epilogue(arch, tail):
    if arch == "x86_64":
        if tail[-1:] != [b"\xc3"]:
            return False
        steps = tail[:-1]
        if steps[-1:] == [b"\x5d"]:
            steps = steps[:-1]
        if not steps:
            return True
        if len(steps) != 1:
            return False
        raw, = steps
        return ((len(raw) == 4 and raw[:3] == b"\x48\x83\xc4" or
                 len(raw) == 7 and raw[:3] == b"\x48\x81\xc4")
                and signed(raw[3:]) > 0 and signed(raw[3:]) % 8 == 0)

    if any(len(raw) != 4 for raw in tail):
        return False
    words = [int.from_bytes(raw, "little") for raw in tail]
    if words[-1:] != [0xd65f03c0]:
        return False
    steps = words[:-1]
    if steps and steps[0] & 0xffc07fff in (0xa9407bfd, 0xa8c07bfd):
        steps = steps[1:]  # ldp x29, x30, [sp, #offset] or post-index restore
    return not steps or len(steps) == 1 and steps[0] & 0xffc003ff == 0x910003ff


def writable_word(image, address):
    return 0 <= address < 1 << 64 and address % 8 == 0 and any(
        seg["protections"] & 2 and not seg["protections"] & 4 and int(seg["va"], 16) <= address
        and address + 8 <= int(seg["va"], 16) + int(seg["size"], 16)
        for seg in image["segments"]
    )


def observer_store(image, code, site):
    addresses = [site]
    following = site + len(code[site])
    if image["arch"] == "x86_64":
        raw = code.get(following, b"")
        if len(raw) == 7 and raw[:3] == b"\x48\x89\x05":
            target = following + 7 + signed(raw[3:])
            if writable_word(image, target):
                return addresses + [following], target
        return None

    live, bases = {0}, {}
    for _ in range(MAX_OBSERVER_INSTRUCTIONS - 1):
        address = following
        raw = code.get(address, b"")
        if len(raw) != 4:
            break
        addresses.append(address)
        following += 4
        word = int.from_bytes(raw, "little")
        register, base = word & 31, word >> 5 & 31
        if word & 0xffe0ffe0 == 0xaa0003e0:  # mov xd, xm
            source = word >> 16 & 31
            value = source in live
            live.discard(register)
            bases.pop(register, None)
            if value and register != 31:
                live.add(register)
        elif word & 0x9f000000 == 0x90000000:  # adrp
            page = (word >> 29 & 3) | (word >> 5 & 0x7ffff) << 2
            if page & (1 << 20):
                page -= 1 << 21
            live.discard(register)
            bases[register] = (address & ~0xfff) + (page << 12)
        elif word & 0xffc00000 == 0xf9400000 and base == 31:  # ldr xt, [sp, #offset]
            live.discard(register)
            bases.pop(register, None)
        elif word & 0xffc00000 == 0xf9000000:  # str xt, [xn, #offset]
            if base == 31:
                continue
            if register in live and base in bases:
                target = bases[base] + (word >> 10 & 0xfff) * 8
                if writable_word(image, target):
                    return addresses, target
            break
        else:
            break
        if not live:
            break
    return None


def requests(binary, image, root, functions):
    arch = image["arch"]
    if arch not in RETURN_REGISTERS:
        raise UnverifiedDispatch("unsupported_forwarded_return_architecture")
    decode = arm64_direct_target if arch == "arm64" else direct_target
    parameters = callee_parameters.requests(binary, image, root, functions)
    entry = root["entry_va"]
    leaves = {r["target_va"] for r in parameters if len(r["path"]) == 1}
    code = instruction_bytes(binary, image, root, 8192)
    addresses = list(code)
    transfers = [r for r in root["instructions"] if "TERMINATOR" in r["flow"] or "COMPUTED" in r["flow"]]
    if len(transfers) != 1 or transfers[0]["addr"] != hex(addresses[-1]):
        raise UnverifiedDispatch("unverified_forwarding_epilogue")
    sites = [(site, target, addresses[index:]) for site, target in direct_edges(code, root, leaves, decode)
             if (index := addresses.index(site)) >= len(addresses) - 4
             and epilogue(arch, [code[va] for va in addresses[index + 1:]])]
    if len(sites) != 1:
        raise UnverifiedDispatch("unverified_forwarding_epilogue")
    site, target, tail = sites[0]
    refs = root["xrefs_to_entry"]
    if (root["xrefs_to_entry_truncated"] or root["xrefs_to_entry_error"]
            or root["xrefs_to_entry_count"] != len(refs) or len(refs) > MAX_OBSERVER_REFS):
        raise UnverifiedDispatch("unverified_forwarded_return_observer")
    call_sites = {r["from"] for r in refs if r["type"] == "UNCONDITIONAL_CALL" and not r["from_external"]}
    if not call_sites:
        raise UnverifiedDispatch("missing_forwarded_return_observer")
    linker = set(image["loader"]["function_starts"]["addresses"])
    for caller in functions:
        if (caller["entry_va"] not in linker or caller["entry_va"] in (entry, target)
                or caller["is_external"] or caller["is_thunk"]
                or not any(r["addr"] in call_sites for r in caller["instructions"])):
            continue
        try:
            observer = instruction_bytes(binary, image, caller, 8192)
            for call, _ in direct_edges(observer, caller, {entry}, decode):
                if hex(call) not in call_sites:
                    continue
                witness = observer_store(image, observer, call)
                if witness:
                    used, stored = witness
                    return [{"target_va": target, "call_va": hex(site), "tail": sequence(code, tail),
                             "observer_va": caller["entry_va"], "observer_call_va": hex(call),
                             "observer": sequence(observer, used), "store_va": hex(used[-1]),
                             "destination_va": hex(stored), "parameters": parameters}]
        except UnverifiedDispatch:
            continue
    raise UnverifiedDispatch("missing_forwarded_return_observer")


def request(binary, image, root, functions):
    plan = {"policy": POLICY, "image_sha256": image["sha256"], "arch": image["arch"],
            "entry_va": root["entry_va"], "requests": []}
    try:
        plan["requests"] = requests(binary, thin(binary), root, functions)
    except UnverifiedDispatch as error:
        plan["skipped_reason"] = str(error)
    return plan


def decision(plan, report):
    result = {"entry_va": plan["entry_va"], "status": "skipped"}
    if not plan["requests"] and report is None:
        return dict(result, reason=plan["skipped_reason"])
    error = Error("forwarded_return_result", "Worker reported different forwarded return evidence", 10)
    if (len(plan["requests"]) != 1 or not isinstance(report, dict) or report.get("policy") != POLICY
            or report.get("entry_va") != plan["entry_va"] or not isinstance(report.get("results"), list)
            or len(report["results"]) != 1 or not isinstance(report["results"][0], dict)):
        raise error
    proof, = plan["requests"]
    row, = report["results"]
    evidence = {key: proof[key] for key in ("target_va", "call_va", "observer_va", "observer_call_va",
                                            "store_va", "destination_va")}
    if any(row.get(key) != value for key, value in evidence.items()):
        raise error
    if row.get("status") == "applied":
        storage = RETURN_REGISTERS[plan["arch"]] + ":8"
        if row.get("return_storage") != storage:
            raise error
        return dict(result, status="applied", **evidence, return_storage=storage)
    if row.get("status") == "skipped" and row.get("reason") in (
            "existing_forwarded_return", "unsupported_forwarded_signature", "unverified_forwarding_flow"):
        return dict(result, **evidence, reason=row["reason"])
    raise error
