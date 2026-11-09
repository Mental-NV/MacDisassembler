# Current status and remaining gates

Updated 9 November 2026. The specification is a staged roadmap; its historic
pre-development wording is not a statement that the current repository still
contains documentation only.

## Implemented

- Source-controlled AppKit calculator, pure-C calculation core and corpus,
  build matrix, core/controller tests and direct full-Ghidra baseline.
  Current measurements and any unresolved phase-1 gates are documented in
  [phase-1 findings](phase1-findings.md), not inferred from CLI completion.
- Initial installable `macscope` 0.2.0 wheel, with no third-party Python
  dependencies and no bundled engine. Uses full Ghidra12.2/JDK25 on the
  tested macOS arm64 host.
- Version/doctor, bounded Mach-O/app-main inspection, private project creation,
  explicit thin/universal slice import without autoanalysis, versioned baseline
  analysis and explicitly selected binary-derived parameter inference,
  function list/show, disassembly, cached and fresh selected-function pseudocode, references,
  CFG JSON/DOT, project/job status, cached search, bounded call traversal
  and normalized exports.
- Package-owned Java bridge, effective analyzer-option recording, real saved
  Program databases, immutable digest identities, SQLite committed snapshots,
  writer lock, atomic result/output publication and pagination-bound cursors.
- Owned-process cancellation, wall/per-function deadlines, bounded facets,
  partial/error envelopes, and explicit rejection of unsupported hard-memory,
  independent-startup and parallel-worker budgets.
- Durable malformed-input, storage, selector, schema, dependency, cached-query
  and process-lifecycle tests; controlled thin/fat64 integration and a clean
  local wheel install. See [CLI validation](cli.md#reproduce-validation).

## Phase-2 boundaries still open

Engine operations are **trusted-owned-input-only experimental**, with an
explicit opt-in. Network and other user-home access are restricted, but the
tested seatbelt profile is not a complete hostile-input filesystem sandbox.
Hard process-memory/disk quotas are not available. No automatic unsafe
fallback exists.

Public queries default to completed snapshots. Explicit `decompile --fresh`
uses the saved Program and the read-only/noanalysis worker. Polished terminal
output, full Mach-O load-command and dyld decoding, and broader host support remain
incomplete. Some calculator batches correctly exit6 because their reference
collections exceed documented bounds despite successful pseudocode output.

## Later phases and separate gates

- [x] Reproduce owned stripped x86_64 instruction checks using independent
  function-start metadata. See [profile validation](parameter-inference.md).
- [x] Expose uncached selected-function decompilation from the saved Program.
- [x] Link available Ghidra pseudocode tokens to machine addresses. The
  arm64/x86_64 thin and universal integration checked cached and fresh links.
- [x] Measure 20 rounds of CLI latency on the development Mac. See the
  [benchmark](benchmark.md) for scope and outstanding reference-host measurements.
- [x] Search committed function names, symbols, strings and pseudocode
  with resumable pages and scoped coverage.
- [x] Traverse saved call references with depth/edge bounds and explicit
  unresolved targets.
- [x] Store user labels and function/instruction comments with reversible
  revisions, search and separate opt-in export.
- [ ] Round-trip annotations and accepted type hints between compatible
  workspaces with validated identity and atomic import.
- [x] Apply explicitly accepted scalar return hints in fresh Ghidra queries.
  The owned arm64/x86_64 tests verified separate provenance and unchanged
  unassisted snapshots. Parameter and compound hints remain open.
- [x] Inventory physical bundle images and resources with hashes and
  resumable pages.
- [x] Import explicit embedded images and resolve bounded in-bundle framework
  links. The owned arm64 main and x86_64 helper passed real Ghidra import.
- [x] Query imported headers, segments, sections and file-backed bytes,
  plus saved symbol, string, import and export collections.
- [x] Record entry offsets, dylib dependencies, rpaths and linkedit extents,
  and decode bounded function-start and data-in-code tables. The owned
  16-binary comparison checked 708 function starts and 56 dylib paths.
- [x] Decode ordinary 64-bit chained bind and rebase pointers from immutable
  slices. The 16 owned inputs matched Apple tool output for 3,890 fixups.
- [x] Decode ordinary pointer operations in legacy dyld streams. Four
  separately linked owned binaries matched Apple tooling on 1,086 fixups.
- [x] Query bounded modern and legacy export tries from the immutable
  slice. Apple and LLVM comparisons verified 406 exports on owned images.
- [ ] Expand tested dyld pointer formats.
- [x] Expose Objective-C classes, methods and selector references with
  static provenance. The owned app matrix matched 216 method addresses.
- [x] Expose Swift symbol-table names and optional sandboxed demangling
  with tool provenance. Broader Swift metadata decoding remains open.
- [x] Run source-aware recovered-C calibration for the two scalar comparison
  functions. [Measured scope and results](parameter-inference.md#recovered-scalar-behavior-calibration).
- [x] Measure owned-tool discovery against evaluator-side DWARF and linker
  starts. All 536 entries matched. LLVM confirmed a missed x86_64 O0 switch
  and adjudicated the x86_64 O2 padding discrepancy. See the
  [discovery measurement](parameter-inference.md#evaluator-side-discovery-measurement).
- [ ] Freeze and evaluate a held-out behavior variation before tuning the
  x86_64 O0 switch recovery.
- [ ] Exercise isolation, malformed-input fuzzing, schema migrations and
  additional host versions before a wider release. Release SBOM and notices
  need dependency and packaging decisions.
- [ ] Separately gated: desktop UI acceptance, private real-app and Taskovsky
  evaluation, optional REA integration, licensing and publication.

## Independent decompiler research

An opt-in research harness and [documented regression](decompiler-review.md)
compare instruction evidence and binary-derived prototype inference on the
owned calculator. They do not change production defaults or establish
pseudocode behavioral equivalence. The alternate CLI profile is explicitly
selected with `--profile parameter-inference`; baseline remains unchanged
as the default. See [profile validation](parameter-inference.md).
