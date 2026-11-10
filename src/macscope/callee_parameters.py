"""Bounded call graph for query-scoped, binary-derived callee parameters."""
from collections import deque

from .direct_signatures import arm64_direct_target, direct_edges
from .dispatch_returns import direct_target, instruction_bytes
from .dispatch_tables import UnverifiedDispatch
from .errors import Error
from .macho import thin


POLICY = "macscope-callee-parameters/1"
MAX_DEPTH = 2
MAX_TARGETS = 16
REGISTERS = {"arm64": tuple(f"x{i}" for i in range(8)),
             "x86_64": ("RDI", "RSI", "RDX", "RCX", "R8", "R9")}


def call_order(root, graph):
    ordered, done, visiting = [], set(), set()

    def visit(entry):
        if entry in visiting:
            raise UnverifiedDispatch("recursive_callee_graph")
        if entry in done:
            return
        visiting.add(entry)
        for child in graph.get(entry, ()):
            visit(child)
        visiting.remove(entry)
        done.add(entry)
        ordered.append(entry)

    visit(root)
    return ordered[:-1]


def requests(binary, image, root, functions):
    arch = image["arch"]
    if arch not in REGISTERS:
        raise UnverifiedDispatch("unsupported_callee_parameter_architecture")
    decode = arm64_direct_target if arch == "arm64" else direct_target
    starts = image["loader"]["function_starts"]
    if not starts or starts["status"] != "complete":
        raise UnverifiedDispatch("unverified_callee_function_starts")
    linker = set(starts["addresses"])
    records = {f["entry_va"]: f for f in functions if f["entry_va"] in linker and not f["is_external"]
               and not f["is_thunk"] and f["decompile_status"] == "complete" and not f["pseudocode_truncated"]}
    entry = root["entry_va"]
    if entry not in records:
        raise UnverifiedDispatch("unverified_callee_selection")

    paths, graph, queue = {entry: []}, {}, deque([entry])
    while queue:
        caller = queue.popleft()
        path = paths[caller]
        if len(path) == MAX_DEPTH:
            continue
        try:
            code = instruction_bytes(binary, image, records[caller], 8192)
            sites = list(direct_edges(code, records[caller], records, decode))
        except UnverifiedDispatch:
            continue
        graph[caller] = list(dict.fromkeys(target for _, target in sites))
        for site, target in sites:
            if target in paths:
                continue
            if len(paths) > MAX_TARGETS:
                raise UnverifiedDispatch("callee_parameter_target_limit")
            paths[target] = [*path, {"owner_va": caller, "call_va": hex(site), "target_va": target,
                                    "bytes": code[site].hex()}]
            queue.append(target)
    return [{"target_va": target, "path": paths[target]} for target in call_order(entry, graph)]


def request(binary, image, root, functions):
    plan = {"policy": POLICY, "image_sha256": image["sha256"], "arch": image["arch"],
            "entry_va": root["entry_va"], "requests": []}
    try:
        plan["requests"] = requests(binary, thin(binary), root, functions)
    except UnverifiedDispatch as error:
        plan["skipped_reason"] = str(error)
    if not plan["requests"]:
        plan.setdefault("skipped_reason", "no_verified_direct_callees")
    return plan


def decision(plan, report):
    result = {"entry_va": plan["entry_va"], "status": "skipped"}
    if not plan["requests"] and report is None:
        return dict(result, reason=plan["skipped_reason"])
    error = Error("callee_parameter_result", "Worker reported different callee parameter evidence", 10)
    if (not plan["requests"] or not isinstance(report, dict) or report.get("policy") != POLICY
            or report.get("entry_va") != plan["entry_va"] or not isinstance(report.get("results"), list)
            or len(report["results"]) != len(plan["requests"])):
        raise error
    registers = REGISTERS[plan["arch"]]
    applied, skipped = [], []
    for proof, row in zip(plan["requests"], report["results"]):
        target = proof["target_va"]
        if not isinstance(row, dict) or row.get("target_va") != target:
            raise error
        if row.get("status") == "applied":
            parameters = row.get("parameters")
            if (row.get("return_unchanged") is not True or not isinstance(parameters, list)
                    or not 1 <= len(parameters) <= len(registers)):
                raise error
            for index, param in enumerate(parameters):
                if (not isinstance(param, dict) or param.get("register") != registers[index]
                        or type(param.get("size")) is not int or param["size"] not in (1, 2, 4, 8)):
                    raise error
            applied.append({"target_va": target, "path": proof["path"], "parameters": parameters,
                            "return_unchanged": True})
        elif row.get("status") == "skipped" and row.get("reason") in (
                "unsupported_callee_parameters", "existing_callee_parameters"):
            skipped.append({"target_va": target, "reason": row["reason"]})
        else:
            raise error
    return dict(result, status="applied" if applied else "skipped", applied=applied, skipped=skipped)
