#!/usr/bin/env python3
"""evaluate.py — Phase 1 source-aware evaluation of FROZEN blind baselines.

Reads only build/workspaces/ghidra-*/baseline.json (frozen, hashed in
freeze.json) plus evaluator-side nm/link data. Never modifies baselines.

Classification (honest): the analyst (headless runs) saw binary only;
the evaluator (this script + its author) is SOURCE-AWARE. Nothing here is
a clean blind qualitative score.

Gates reported per spec section 9.1 with denominators:
  discovery recall (retained routines, O0 and O2, both archs, both symstates),
  pseudocode completion, direct-call/xref spot checks, universal parity,
  import identity, determinism, LLVM adjudication (noinline subset).
Behavioral equivalence of emitted pseudocode is NOT measured (unknown).
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EV = REPO / "build" / "evaluator"
WS = REPO / "build" / "workspaces"

# Expected routines: (source name, binary symbol). Static helpers that may
# inline are scored separately as "surviving?" rather than in the denominator.
CORE_ROUTINES = [
    "calc_add", "calc_sub", "calc_mul", "calc_div", "calc_negate",
    "calc_abs_checked", "calc_pow_checked", "calc_apply_op",
    "calc_dispatch_table", "calc_parse_digits", "calc_format_int64",
    "calc_digit_append", "calc_sign_toggle", "calc_compare_s64",
    "calc_compare_u64", "calc_state_init", "calc_engine_clear",
    "calc_engine_input_digit", "calc_engine_input_op", "calc_engine_equals",
    "calc_engine_sign_toggle", "calc_history_init", "calc_history_push",
    "calc_history_len", "calc_history_get", "calc_history_sum",
]
CORPUS_ROUTINES = [
    "corpus_fact_checked", "corpus_lut_demo", "corpus_stats_over_points",
    "corpus_chain_demo",
]
NOINLINE_SUBSET = [
    "calc_add", "calc_div", "calc_apply_op", "calc_dispatch_table",
    "calc_parse_digits", "calc_engine_input_op", "calc_engine_equals",
    "calc_history_sum",
]


def nm_map(exe):
    out = subprocess.run(["xcrun", "nm", "-a", str(exe)], capture_output=True,
                         text=True, check=True).stdout
    m = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "Tt":
            m[parts[2].lstrip("_")] = "0x" + parts[0].lstrip("0") or "0x0"
    # normalize: keep full hex
    norm = {}
    for k, v in m.items():
        norm[k] = "0x%x" % int(v, 16)
    return norm


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_freeze(repo, workspace):
    freeze = json.loads((workspace / "freeze.json").read_text())
    if freeze.get("schema") not in {"macscope-freeze/1", "macscope-freeze/2"}:
        raise ValueError("unsupported freeze schema")
    hashes = {}
    for item in freeze["artifacts"]:
        path = (repo / item["path"]).resolve()
        if not path.is_relative_to(workspace.resolve()) or path in hashes:
            raise ValueError("freeze path outside workspace or duplicated")
        if digest(path) != item["sha256"]:
            raise ValueError("freeze integrity mismatch: " + str(path))
        hashes[path] = item["sha256"]
    return hashes


def load(tag):
    path = (WS / f"ghidra-{tag}" / "baseline.json").resolve()
    data = path.read_bytes() if path.exists() else b""
    if path not in FREEZE_HASHES or hashlib.sha256(data).hexdigest() != FREEZE_HASHES[path]:
        raise ValueError("baseline is missing from freeze or changed: " + str(path))
    value = json.loads(data)
    if value.get("schema") not in {"macscope-baseline/1", "macscope-baseline/2"}:
        raise ValueError("unsupported baseline schema")
    if int(value["function_count_enumerated"]) != len(value["functions"]):
        raise ValueError("baseline function count mismatch")
    entries = [entry_va(f) for f in value["functions"]]
    if len(set(entries)) != len(entries):
        raise ValueError("duplicate baseline function entry")
    return value


def needs_attention(rec):
    return bool(rec["missing"] or rec["incomplete"] or rec["stripped_missing"]
                or rec["stripped_incomplete"] or not rec["layout_sym_eq_stripped"])


def instruction_adjudication(lines, function):
    # Scope is Ghidra-selected ranges, not independently verified body recovery.
    pattern = re.compile(r"^([0-9a-fA-F]+):\t([0-9a-fA-F ]+)\t")
    ranges = [(int(a, 16), int(b, 16)) for a, b in function["body_ranges"]]
    llvm = {}
    for line in lines:
        match = pattern.match(line)
        if match:
            address = int(match[1], 16)
            if any(lo <= address <= hi for lo, hi in ranges):
                llvm[address] = bytes.fromhex(match[2])
    ghidra = {int(i["addr"], 16): bytes.fromhex(i["bytes"]) for i in function["instructions"]}
    return {"ghidra": len(ghidra), "llvm": len(llvm), "count_agree": len(ghidra) == len(llvm),
            "instruction_boundaries_and_bytes_agree": llvm == ghidra,
            "scope": "arm64 O0, Ghidra body ranges; no independent function-body or branch-target check"}



def entry_va(f):
    return "0x%x" % int(f["entry_va"], 16)


def main(argv=None):
    global REPO, EV, WS, FREEZE_HASHES, OUTPUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", nargs="?", type=Path, default=REPO)
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    REPO = args.repo.resolve()
    build = args.build_root or REPO / "build"
    EV = build / "evaluator"
    WS = (args.workspace or build / "workspaces").resolve()
    OUTPUT = args.output or build / ("eval-review-" + __import__("uuid").uuid4().hex[:8] + ".json")
    FREEZE_HASHES = verify_freeze(REPO, WS)
    results = {"schema": "macscope-phase1-eval/1",
               "classification": "source-aware evaluation of binary-only frozen outputs (NOT blind)",
               "cases": {}}

    CASES = [
        ("DebugAnalysis", "arm64"), ("DebugAnalysis", "x86_64"),
        ("ReleaseAnalysis", "arm64"), ("ReleaseAnalysis", "x86_64"),
    ]

    for cfg, arch in CASES:
        for kind, routines in (("app", CORE_ROUTINES), ("tool", CORPUS_ROUTINES)):
            tag = f"{cfg}-{arch}-sym-{kind}"
            sym_exe = (EV / f"{cfg}-{arch}" / "CalculatorFixture.app" / "Contents"
                       / "MacOS" / "CalculatorFixture") if kind == "app" else (
                           EV / f"{cfg}-{arch}" / "CorpusFixture")
            truth = nm_map(sym_exe)
            blind = load(tag)
            if hashlib.md5(sym_exe.read_bytes()).hexdigest() != blind["executable_md5"]:
                raise ValueError("evaluator binary does not match analyzed sym input: " + tag)
            by_va = {entry_va(f): f for f in blind["functions"]}
            # layout check: stripped sibling must share image base + text range
            blind_s = load(f"{cfg}-{arch}-stripped-{kind}")
            layout_same = (
                blind["image_base"] == blind_s["image_base"]
                and [s for s in blind["sections"] if s["name"] == "__text"]
                == [s for s in blind_s["sections"] if s["name"] == "__text"])
            rec = {"truth_count": 0, "recalled": 0, "complete": 0,
                   "missing": [], "incomplete": [], "eliminated": [],
                   "stripped_recalled": 0, "stripped_complete": 0, "stripped_missing": [],
                   "stripped_incomplete": [],
                   "layout_sym_eq_stripped": layout_same}
            by_va_s = {entry_va(f): f for f in blind_s["functions"]}
            for r in routines:
                va = truth.get(r)
                if va is None:
                    rec["eliminated"].append(r)  # inlined/dead-stripped: not in denominator
                    continue
                rec["truth_count"] += 1
                f = by_va.get(va)
                if f is None:
                    rec["missing"].append((r, va))
                else:
                    rec["recalled"] += 1
                    if f["decompile_status"] == "complete" and f["pseudocode"]:
                        rec["complete"] += 1
                    else:
                        rec["incomplete"].append((r, va, f["decompile_status"]))
                fs = by_va_s.get(va)
                if fs is None:
                    rec["stripped_missing"].append((r, va))
                else:
                    rec["stripped_recalled"] += 1
                    if fs["decompile_status"] == "complete" and fs["pseudocode"]:
                        rec["stripped_complete"] += 1
                    else:
                        rec["stripped_incomplete"].append((r, va, fs["decompile_status"]))
            results["cases"][tag] = rec

    # Xref spot checks on DebugAnalysis-arm64 (sym): controlled direct calls.
    spot = {}
    d = load("DebugAnalysis-arm64-sym-app")
    byname = {}
    for f in d["functions"]:
        byname.setdefault(f["name"], []).append(f)
    eq = (byname.get("_calc_engine_equals") or [None])[0]
    if eq:
        tos = {x["to"] for x in eq["xrefs_from_sample"]
               if x.get("type") in {"UNCONDITIONAL_CALL", "CONDITIONAL_CALL"}
               and re.fullmatch(r"0x[0-9a-fA-F]+", x["to"])}
        # Resolve typed direct calls to the exact _calc_apply_op entry.
        ap = (byname.get("_calc_apply_op") or [None])[0]
        hit = False
        if ap:
            hit = any(int(t, 16) == int(ap["entry_va"], 16) for t in tos)
        spot["engine_equals_calls_apply_op"] = hit
        spot["engine_equals_call_targets_sampled"] = len(tos)
    dt = (byname.get("_calc_dispatch_table") or [None])[0]
    if dt:
        spot["dispatch_table_blocks"] = dt["block_count"]
        spot["dispatch_table_insns"] = dt["instruction_count"]
    results["xref_spots"] = spot

    # LLVM adjudication: noinline subset, arm64 O0 sym app. llvm-objdump omits
    # labels for local symbols, so count LLVM instructions whose address falls
    # inside Ghidra's reported body ranges (same bytes, two decoders).
    llvm = (WS / "llvm-DebugAnalysis-arm64-sym-app.txt").read_text(errors="replace").splitlines()
    adj = {}
    for r in NOINLINE_SUBSET:
        gf = (byname.get("_" + r) or [None])[0]
        if gf:
            adj[r] = instruction_adjudication(llvm, gf)
    results["llvm_adjudication_arm64_O0"] = adj

    # Gate summary
    gates = {}
    tot_t = sum(v["truth_count"] for v in results["cases"].values())
    tot_r = sum(v["recalled"] for v in results["cases"].values())
    tot_c = sum(v["complete"] for v in results["cases"].values())
    tot_sr = sum(v["stripped_recalled"] for v in results["cases"].values())
    if len(results["cases"]) != 8 or tot_t == 0:
        raise ValueError("empty or incomplete evaluation case matrix")
    gates["discovery_recall_sym"] = f"{tot_r}/{tot_t}"
    gates["pseudocode_complete_sym"] = f"{tot_c}/{tot_t}"
    gates["discovery_recall_stripped"] = f"{tot_sr}/{tot_t}"
    gates["pseudocode_complete_stripped"] = f"{sum(v['stripped_complete'] for v in results['cases'].values())}/{tot_t}"
    gates["full_release_gates"] = "PARTIAL: recall/completion only; precision, body correctness, behavior, full branch/xref/determinism/parity UNKNOWN"
    results["gates"] = gates

    out = OUTPUT
    results["freeze_verified"] = True
    results["freeze_sha256"] = digest(WS / "freeze.json")
    llvm_path = WS / "llvm-DebugAnalysis-arm64-sym-app.txt"
    results["llvm_reference"] = {"sha256": digest(llvm_path), "frozen_before_evaluation": llvm_path.resolve() in FREEZE_HASHES}
    results["attention"] = (any(needs_attention(v) for v in results["cases"].values())
                            or not spot.get("engine_equals_calls_apply_op")
                            or any(not v["instruction_boundaries_and_bytes_agree"] for v in adj.values()))
    with out.open("x") as f:
        f.write(json.dumps(results, indent=2) + "\n")
    print(json.dumps(gates, indent=2))
    for tag, rec in results["cases"].items():
        flag = "ATTN" if needs_attention(rec) else "OK "
        print(f"{flag} {tag}: truth={rec['truth_count']} recalled={rec['recalled']} "
              f"complete={rec['complete']} stripped_complete={rec['stripped_complete']} "
              f"eliminated={rec['eliminated']} missing={rec['missing']} "
              f"incomplete={rec['incomplete']} stripped_missing={rec['stripped_missing']} "
              f"stripped_incomplete={rec['stripped_incomplete']} layout_same={rec['layout_sym_eq_stripped']}")
    print("xref spots:", json.dumps(spot))
    print("llvm adjudication:", json.dumps(adj))
    return 1 if results["attention"] else 0


if __name__ == "__main__":
    sys.exit(main())
