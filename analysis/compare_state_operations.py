#!/usr/bin/env python3
"""Measure recovered state transitions and integer formatting."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

from aggregate_compat import ARM_VECTORS, BYTE_VECTORS, POLICY, Unsupported, check_tokens, lower_closure, lower_function, source_parts
from audit_core_behavior import complete, core_extents, count_status, inventory, llvm_instructions
from audit_core_data_references import references as decoded_data_references
from compare_aggregates import COMPAT, LOWERER
from prototype_experiment import ROOT, fixture_input
from recovered_compare import SOURCE_FILES, run_candidate
from reference_coverage import xcrun
from score_discovery import verified_captures
from validate_decompiler_evidence import read_bytes, sha, write_new_json
from macscope import dyld, engine
from macscope.macho import thin


ROUTINES = (("calc_engine_input_digit", r"int|uint", 7294),
            ("calc_engine_input_op", r"char|byte|uint|undefined1", 6252),
            ("calc_engine_equals", None, 521), ("calc_engine_sign_toggle", None, 521))
HARNESS = ROOT / "analysis" / "compare_state_operations_harness.c"
FORMAT_HARNESS = ROOT / "analysis" / "compare_format_harness.c"
FORMAT = "calc_format_int64"
GUARD = re.compile(r"\bPTR____stack_chk_guard_([0-9a-f]{1,16})\b")
RETURN_ADDRESS = re.compile(r"\b(uStack_[0-9a-f]+)\s*=\s*&UNK_([0-9a-f]{1,16})\s*;")
STACK_CHECK_LIBRARY = "/usr/lib/libSystem.B.dylib"


def bind_return_address(text, binary, image, decoded, binds):
    """Verify a printed x86 CALL return PC against the imported failure stub."""
    matches = list(RETURN_ADDRESS.finditer(text))
    if not matches:
        return text, (), None
    if image["arch"] != "x86_64" or len(matches) != 1:
        raise Unsupported("unverified_stack_return_address")
    match, = matches
    variable, literal = match.groups()
    if (not re.search(rf"\bundefined8\s+{variable}\s*;", text)
            or len(re.findall(rf"\b{variable}\b", text)) != 2):
        raise Unsupported("unverified_stack_return_address")
    address = int(literal, 16)
    pc = address - 5
    raw, mnemonic, _ = decoded.get(pc, (b"", "", ""))
    if mnemonic != "callq" or len(raw) != 5 or raw[0] != 0xe8:
        raise Unsupported("unverified_stack_return_address")
    target = address + int.from_bytes(raw[1:], "little", signed=True)
    section = next((s for s in image["sections"] if s["name"] == "__stubs"
                    and int(s["va"], 16) <= target <= int(s["va"], 16) + int(s["size"], 16) - 6), None)
    if section is None:
        raise Unsupported("unverified_stack_return_address")
    offset = int(section["file_offset"], 16) + target - int(section["va"], 16)
    stub = binary[offset:offset+6]
    if len(stub) != 6 or stub[:2] != b"\xff\x25":
        raise Unsupported("unverified_stack_return_address")
    slot = target + 6 + int.from_bytes(stub[2:], "little", signed=True)
    if not any(row["symbol"] == "___stack_chk_fail" and int(row["va"], 16) == slot for row in binds):
        raise Unsupported("unverified_stack_return_address")
    replacement = f"{variable} = (ulong){hex(address)};"
    evidence = {"call_va": hex(pc), "return_va": hex(address), "stub_va": hex(target), "bind_va": hex(slot)}
    return text[:match.start()] + replacement + text[match.end():], (variable,), evidence


def compare_format(directory, record, binary, decoded, compiler, sdk, harness, references):
    name, text = record["name"], record["pseudocode"]
    try:
        return_type, params, body, _ = source_parts(text, name)
        if return_type not in ("undefined4", "undefined8") or not re.fullmatch(
            r"ulong\s+param_1\s*,\s*undefined1\s*\*\s*param_2\s*,\s*ulong\s+param_3", params.strip()
        ):
            raise Unsupported("unverified_format_signature")
        guards = {m[0]: hex(int(m[1], 16)) for m in GUARD.finditer(body)}
        if len(guards) != 1:
            raise Unsupported("ambiguous_stack_guard")
        (guard, address), = guards.items()
        image = dict(thin(binary), offset="0x0")
        _, fixups, gaps = dyld.fixups(binary, image)
        binds = [row for row in fixups if row["kind"] == "bind" and row["library"] == STACK_CHECK_LIBRARY
                 and not row["weak_import"] and row["import_addend"] == 0 and row.get("inline_addend", 0) == 0]
        targets, _ = decoded_data_references(decoded, image["arch"])
        guard_rows = [row for row in binds if row["symbol"] == "___stack_chk_guard" and row["va"] == address]
        if (gaps or len(guard_rows) != 1 or sum(row["symbol"] == "___stack_chk_fail" for row in binds) != 1
                or not any(row["target_va"] == address for row in targets)):
            raise Unsupported("unverified_stack_guard_linkage")
        text, initialized_stack, return_binding = bind_return_address(text, binary, image, decoded, binds)
        if any(intrinsic in body for intrinsic in BYTE_VECTORS):
            if (any(intrinsic in body for intrinsic in ARM_VECTORS) and image["arch"] != "arm64"
                    or "pshufb" in body and image["arch"] != "x86_64"):
                raise Unsupported("unverified_vector_architecture")
            text, _ = lower_function(text, name, {guard, "___stack_chk_fail"}, aggregate_required=False,
                                     initialized_stack=initialized_stack)
        else:
            check_tokens(source_parts(text, name)[2], {guard, "___stack_chk_fail"})
    except Unsupported as error:
        return {"status": "not_testable", "reason": str(error)}

    directory.mkdir(mode=0o700)
    (directory / "candidate.c").write_text(f"#define {guard} ((uintptr_t)&gh_stack_guard)\n" + text)
    result = run_candidate(directory, compiler, sdk, harness, references, ["-fsanitize=address", f"-DRECOVERED={name}"])
    result["guard_binding"] = guard_rows[0]
    if return_binding:
        result["return_address_binding"] = return_binding
    if "results" in result:
        result["status"] = count_status(result["results"], 1005, 10000)
    return result


def compare(directory, record, source, kind, selector, directed, compiler, sdk, harness, references):
    name = record["name"]
    try:
        return_type, args, _, _ = source_parts(source[name], name)
        parameters = r"(?:long|ulong|undefined8)\s*\*\s*param_1"
        if selector:
            parameters += rf"\s*,\s*(?:{selector})\s+param_2"
        if return_type != "void" or not re.fullmatch(parameters, args.strip()):
            raise Unsupported("unverified_state_signature")
        lowered, dependencies = lower_closure(name, source, 2 if selector else 1, aggregate_required=False)
    except Unsupported as error:
        return {"status": "not_testable", "reason": str(error)}
    directory.mkdir(mode=0o700)
    (directory / "candidate.c").write_text(lowered)
    flags = ["-fsanitize=address", "-fno-strict-aliasing", f"-DRECOVERED={name}", f"-DSTATE_KIND={kind}"]
    result = run_candidate(directory, compiler, sdk, harness, references, flags)
    result.update(lowered_sha256=sha(lowered.encode()),
                  captured_definitions={callee: sha(source[callee].encode()) for callee in dependencies})
    if "results" in result:
        result["status"] = count_status(result["results"], directed, 10000)
    return result


def run(args):
    output = args.output_dir.resolve()
    scratch = Path("/tmp").resolve()
    if output == scratch or not output.is_relative_to(scratch):
        raise ValueError("Choose a new output directory under canonical /tmp")
    references = {name: read_bytes(ROOT / name) for name in SOURCE_FILES}
    source_hashes = {name: sha(content) for name, content in references.items()}
    references[COMPAT.name] = read_bytes(COMPAT)
    harness = read_bytes(HARNESS)
    format_harness = read_bytes(FORMAT_HARNESS)
    compiler, decoder = xcrun("--find", "clang"), xcrun("--find", "llvm-objdump")
    sdk = xcrun("--sdk", "macosx", "--show-sdk-path")
    output.mkdir(mode=0o700)
    captures, decodes = [], {}
    report = {
        "schema": "macscope-recovered-state-operations/1", "policy": POLICY, "status": "failed",
        "source_sha256": source_hashes, "captures": captures,
        "matrix_report_sha256": sha(read_bytes(args.profile_matrix / "report.json")),
        "lowerer_sha256": sha(read_bytes(LOWERER)), "compat_sha256": sha(references[COMPAT.name]),
        "harness_sha256": sha(harness), "compiler_sha256": engine.digest(Path(compiler)),
        "format_harness_sha256": sha(format_harness), "format_linkage_policy": "macscope-stack-check-linkage/2",
    }
    try:
        for provenance, snapshot, truth, _, manifest in verified_captures(args.fixture_build_root, args.profile_matrix):
            if any(manifest["source"]["source_files_sha256"].get(name) != digest
                   for name, digest in source_hashes.items()):
                raise ValueError("Reference source differs from the fixture manifest")
            case, state, profile = (provenance[key] for key in ("case", "symbols", "profile"))
            extents = core_extents(truth)
            if case not in decodes:
                decodes[case] = llvm_instructions(args.fixture_build_root, case, decoder, extents)
            rows, records = inventory(snapshot, extents, decodes[case])
            names = Counter(f["name"] for f in snapshot["functions"])
            source = {f["name"]: f["pseudocode"] for f in snapshot["functions"]
                      if names[f["name"]] == 1 and complete(f)}
            results = {}
            for kind, (routine, selector, directed) in enumerate(ROUTINES, 1):
                row = results[routine] = dict(rows[routine])
                if not complete(records.get(routine)):
                    continue
                record = records[routine]
                if record["name"] not in source:
                    row.update(status="not_testable", reason="ambiguous_recovered_name")
                    continue
                directory = output / f"{case}-{state}-{profile.replace('/', '-')}-{routine}"
                row.update(compare(directory, record, source, kind, selector, directed,
                                   compiler, sdk, harness, references))
            row = results[FORMAT] = dict(rows[FORMAT])
            if complete(records.get(FORMAT)):
                _, binary, _ = fixture_input(args.fixture_build_root, case, symbols=state)
                if sha(binary) != provenance["input_sha256"]:
                    raise ValueError("Formatting linkage input differs from the captured fixture")
                directory = output / f"{case}-{state}-{profile.replace('/', '-')}-{FORMAT}"
                row.update(compare_format(directory, records[FORMAT], binary, decodes[case][FORMAT],
                                          compiler, sdk, format_harness, references))
            captures.append(dict(provenance, analysis_id=snapshot["analysis_id"], routines=results))
        rows = [row for capture in captures for row in capture["routines"].values()]
        report["counts"] = dict(Counter(row["status"] for row in rows))
        report["instruction_bytes"] = {
            "cohort": sum(row.get("llvm_instruction_bytes", 0) for row in rows),
            "completed_domains": sum(row["llvm_instruction_bytes"] for row in rows if "results" in row),
            "passed_domains": sum(row["llvm_instruction_bytes"] for row in rows if row["status"] == "passed"),
        }
        report["status"] = "passed" if rows and all(row["status"] == "passed" for row in rows) else "partial"
    finally:
        write_new_json(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("fixture-build-root", "profile-matrix", "output-dir"):
        parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--experimental-trusted-input", action="store_true")
    args = parser.parse_args()
    if not args.experimental_trusted_input:
        parser.error("Explicit --experimental-trusted-input is required")
    report = run(args)
    print(json.dumps({key: report[key] for key in ("status", "counts", "instruction_bytes")}))
    return 0 if report["status"] == "passed" else 6


if __name__ == "__main__":
    raise SystemExit(main())
