# Current status — what exists vs what remains

Last updated 9 November 2026 (end of Phase 1 milestone).

## Implemented (done, verified this session)

- Frozen integer semantics: `docs/semantics.md` v1.0.
- Calculator fixture: real AppKit UI (`CalculatorFixture.app`) backed by a
  pure C core (21 routines) plus corpus target (4 extended routines);
  Xcode project with shared `CalculatorFixture` scheme and `DebugAnalysis`
  (`-O0`) / `ReleaseAnalysis` (`-O2`) configurations, no LTO, no fast math,
  `ENABLE_DEBUG_DYLIB=NO`, 8 noinline markers.
- Build matrix (`fixture/build/build_matrix.sh`): 8 thin variants
  (arm64/x86_64 × O0/O2 × sym/stripped) + 4 universal containers, strip
  verification (`__text` preserved 8/8), slice parity 16/16, full manifest
  (`build/manifest.json`), arm64 reference outputs, app smoke launch.
- Durable tests (in repo): `calc_core_tests` (36,091 checks: directed
  boundaries + seeded random) and `ui_journeys` (20 scripted journeys
  through production `CalcController` press paths) — all passing.
- Direct Ghidra baseline (`analysis/scripts/MacscopeBaseline.java`,
  `analysis/run_baseline.sh`): 16/16 headless runs green under a tested
  deny-network sandbox; frozen outputs; source-aware evaluation
  (`analysis/evaluate.py`): 120/120 discovery, 120/120 pseudocode,
  8/8 LLVM adjudication. See `docs/phase1-findings.md`.
- Environment lock: `docs/lock-manifest.md` (Ghidra 12.2, JDK 25.0.5.0.3,
  Xcode 27.0, hashes of engine artifacts).

## Remaining (spec stages, not started)

- Phase 2: narrow `macscope` CLI (`doctor`, `inspect`, `project`, `import`,
  `analyze`, `functions`, `disasm`, `decompile`, `xrefs`, `cfg`, `export`,
  JSON schemas), Java-bridge contract, job manifests, limits/cancellation,
  atomic storage, end-to-end tests. Explicit analyzer-profile recording
  (limitation 1 in phase1-findings).
- Phase 3: annotations, ObjC/Swift metadata views, search, bundle
  inventories, REA evidence import, Taskovsky calendar report.
- Phase 4: packaging, SBOM/notices, compat matrix, fuzzing, arm64e,
  broader Swift. License choice (owner decision, deliberately not made).
- Unknowns carried forward: malformed-input safety, pseudocode behavioral
  harness, full precision/false-positive analysis, stronger isolation for
  untrusted inputs.
