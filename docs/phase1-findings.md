# Phase 1 findings — direct Ghidra baseline (9 November 2026)

## What ran

- 16 direct headless pipelines (8 analyst binaries × app/tool, all via
  `analyzeHeadless -import` + default auto-analysis + `MacscopeBaseline.java`
  post script, `sandbox-exec` deny-network profile, max-cpu 4,
  analysis timeout 600 s, decompile timeout 30 s/function, max 5000 funcs).
- 16 LLVM disassembly retentions (`xcrun llvm-objdump --macho --arch …`).
- Outputs frozen (`build/workspaces/freeze.json`, sha256 per baseline) BEFORE
  source-aware evaluation (`analysis/evaluate.py` → `build/eval-results.json`).
- Classification: analyst runs were binary-only; evaluation is SOURCE-AWARE
  (same developer). No blind qualitative scores are claimed.

## Results

- All 16 runs: exit 0, 0 failed / 0 timed-out functions. Elapsed 5–33 s
  (app) / 5–13 s (tool), well under the 600 s job budget; cold JVM included.
- Controlled discovery recall: **120/120** routines at expected VAs in sym
  builds (26 core + 4 corpus per variant × 4 variants), **120/120** with
  `complete` pseudocode in stripped builds. Zero eliminated routines (all
  source routines survive even at O2 — external linkage + noinline markers).
- Pseudocode completion: **120/120** controlled routines, all variants.
- ObjC methods recovered by name in sym builds (`pressDigit:`,
  `pressOperator:`, `pressEquals`, `buttonPressed:`, …).
- Xref spot: `_calc_engine_equals` → direct call into `_calc_apply_op`
  confirmed in sampled xrefs (13 code targets).
- LLVM adjudication (noinline subset, arm64 O0): **8/8** instruction-count
  agreement between Ghidra and llvm-objdump over identical body ranges
  (e.g. `calc_add` 20/20, `calc_parse_digits` 130/130).
- Universal parity: direct fat import analyzes exactly ONE slice (observed:
  x86_64, 87 functions) — the loader does not multi-slice. That slice's
  function set (name+VA) is IDENTICAL to the thin x86_64 baseline; plus
  build-level slice parity 8/8 byte-exact (unsigned payload) and 8/8
  `__text` hash parity. Gate passes via explicit slice handling, not via
  fat import.
- Determinism: repeat run of `DebugAnalysis-arm64-sym-tool` produced a
  byte-identical baseline JSON (sha256 match).
- Blind-output hygiene: no source paths, no `src/` references, no dSYM or
  DWARF mentions in any of the 16 frozen baselines.
- Reality check on scale: arm64 app sym enumerates 164 functions vs x86_64
  app sym 87 — same source, different engine recovery by architecture.
  The gate denominators use the evaluator-confirmed whitelist, not raw
  engine counts; broader precision (false positives) is UNKNOWN.

## Gate verdicts (spec §9.1, Phase 1 scope)

| Gate | Verdict | Denominator / note |
|---|---|---|
| Full headless path (import→analyze→disasm→pseudocode) | PASS | 16/16 runs, exact Ghidra 12.2 + JDK 25 pins |
| Import identity (hash/arch/UUID/image mapping) | PASS | 20 artifacts in `build/manifest.json`, no slice substitution |
| Parser safety (malformed inputs) | UNKNOWN | not run in Phase 1 (expanded corpus is Phase 3) |
| Controlled discovery O0 (both archs, sym+stripped) | PASS | 60/60 sym recall; 60/60 stripped complete |
| Optimized discovery O2 (surviving routines) | PASS | 60/60; 0 eliminated (report, not assumption) |
| Instruction fidelity (noinline subset, adjudicated) | PASS | 8/8 vs LLVM over identical ranges |
| Pseudocode completion | PASS | 120/120 controlled routines |
| Core behavior (pseudocode recompiled & run) | UNKNOWN | harness not built in Phase 1; reference outputs recorded evaluator-side |
| Direct calls / xrefs | PASS (spot) | equals→apply_op confirmed; full coverage not enumerated |
| Universal parity | PASS | slice-identical sets; explicit single-slice loader behavior documented |
| Determinism | PASS (spot) | 1 case × 2 runs identical; full 3×20 not run |
| Annotation round trip | N/A | Phase 2 CLI work |
| REA adapter | N/A | optional, out of scope for this milestone |

No fabricated semantic-equivalence claims: pseudocode was spot-read
(`calc_add` shows a genuine `SCARRY8` overflow check; `calc_engine_equals`
89 instructions with repeat-equals branches) but NOT executed. No broad
wrapper work started: controlled-core pseudocode succeeded, so the project
may proceed to the narrow CLI.

## Concrete limitations / blockers for Phase 2

1. Effective analyzer/options list is NOT yet exported (default 12.2 set
   assumed; per-analyzer options not dumped). The CLI `analyze --profile`
   must record these explicitly.
2. No filesystem sandbox: seatbelt `sandbox-exec` gives network denial only.
   Broad untrusted inputs remain out of scope until stronger isolation lands.
3. Fat-binary import analyzes one slice silently — the CLI must split
   slices explicitly (`lipo -thin`) and never present fat import as
   multi-arch coverage.
4. Ghidra user state dir (`~/Library/ghidra/…`) is shared/mutable outside
   the workspace; worker runs should pin or isolate it in Phase 2.
5. x86_64 binaries were never executed (static analysis only) — no Rosetta
   use; behavioral reference outputs come from arm64 runs only.
