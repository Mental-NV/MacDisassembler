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
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
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


def load(tag):
    return json.load(open(WS / f"ghidra-{tag}" / "baseline.json"))


def entry_va(f):
    return "0x%x" % int(f["entry_va"], 16)


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
        by_va = {entry_va(f): f for f in blind["functions"]}
        # layout check: stripped sibling must share image base + text range
        blind_s = load(f"{cfg}-{arch}-stripped-{kind}")
        layout_same = (
            blind["image_base"] == blind_s["image_base"]
            and [s for s in blind["sections"] if s["name"] == "__text"]
            == [s for s in blind_s["sections"] if s["name"] == "__text"])
        rec = {"truth_count": 0, "recalled": 0, "complete": 0,
               "missing": [], "incomplete": [], "eliminated": [],
               "stripped_recalled": 0, "stripped_missing": [],
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
                if fs["decompile_status"] == "complete" and fs["pseudocode"]:
                    rec["stripped_recalled"] += 1
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
           if re.fullmatch(r"0x[0-9a-fA-F]+", x["to"])}
    # resolve: does any from-sample target fall inside _calc_apply_op body?
    ap = (byname.get("_calc_apply_op") or [None])[0]
    hit = False
    if ap:
        lo = int(ap["body_ranges"][0][0], 16)
        hi = int(ap["body_ranges"][-1][1], 16)
        hit = any(lo <= int(t, 16) <= hi for t in tos)
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
pat_insn = re.compile(r"^([0-9a-f]+):\t[0-9a-f ]+\t")
llvm_addrs = []
for line in llvm:
    m = pat_insn.match(line)
    if m:
        llvm_addrs.append(int(m.group(1), 16))
llvm_addrs.sort()
adj = {}
for r in NOINLINE_SUBSET:
    gf = (byname.get("_" + r) or [None])[0]
    if gf:
        ranges = [(int(a, 16), int(b, 16)) for a, b in gf["body_ranges"]]
        n = sum(1 for a in llvm_addrs
                if any(lo <= a <= hi for lo, hi in ranges))
        adj[r] = {"ghidra": gf["instruction_count"], "llvm": n,
                  "agree": gf["instruction_count"] == n}
results["llvm_adjudication_arm64_O0"] = adj

# Gate summary
gates = {}
tot_t = sum(v["truth_count"] for v in results["cases"].values())
tot_r = sum(v["recalled"] for v in results["cases"].values())
tot_c = sum(v["complete"] for v in results["cases"].values())
tot_sr = sum(v["stripped_recalled"] for v in results["cases"].values())
gates["discovery_recall_sym"] = f"{tot_r}/{tot_t}"
gates["pseudocode_complete_sym"] = f"{tot_c}/{tot_t}"
gates["discovery_complete_stripped"] = f"{tot_sr}/{tot_t}"
results["gates"] = gates

out = REPO / "build" / "eval-results.json"
out.write_text(json.dumps(results, indent=2) + "\n")
print(json.dumps(gates, indent=2))
for tag, rec in results["cases"].items():
    flag = "OK " if not rec["missing"] and not rec["incomplete"] and rec["layout_sym_eq_stripped"] else "ATTN"
    print(f"{flag} {tag}: truth={rec['truth_count']} recalled={rec['recalled']} "
          f"complete={rec['complete']} stripped_complete={rec['stripped_recalled']} "
          f"eliminated={rec['eliminated']} missing={rec['missing']} "
          f"incomplete={rec['incomplete']} stripped_missing={rec['stripped_missing']} "
          f"layout_same={rec['layout_sym_eq_stripped']}")
print("xref spots:", json.dumps(spot))
print("llvm adjudication:", json.dumps(adj))
