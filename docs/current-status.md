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
  independent-startup and parallel-worker budgets. Group cleanup retains
  the launcher's child identity through signaling and checks budgets before
  accepting the result.
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
- [x] Match 13,900 instruction starts and byte records and 2,732 direct
  targets across the full owned tool core in the patched captures. See
  [the instruction audit](phase1-findings.md#controlled-core-instruction-audit).
- [x] Match all 256 outgoing direct call references in the controlled tool
  core and verify that the 16 encoded indirect calls have no reported target.
- [x] Audit the owned app-main core across both architectures and profiles.
  All 2,732 direct targets matched. A stripped arm64 O2 function boundary
  accounts for the 28 missing instruction records across two captures.
- [x] Report that conflicting boundary in cached, fresh and replayed
  queries. The owned live test preserved the archived Program and snapshot.
- [x] Recover all 23 instructions in both profiles on disposable Program
  copies using the saved binary-derived boundary evidence. The
  [control comparison](phase1-findings.md#temporary-split-body-recovery)
  matched all 196 other functions per profile.
- [x] Validate split-body recovery on a [held-out arm64 fixture](heldout-fallthrough.md).
  Both profiles recovered the eligible 11-instruction body and refused a
  second join because of an outside branch into the competing body.
- [x] Expose guarded split-body recovery as an explicit analysis option.
  The 32-capture calculator comparison found the expected two joins and
  preserved the other functions. The held-out integration and live
  cancellation verified saved Programs and exact replay.
- [x] Match all 152 controlled PC-relative data references across the app
  and tool after opt-in recovery, including the two sites inside the
  previously split body. See [the data audit](phase1-findings.md#controlled-data-references).
- [x] Match three normalized exports per case and profile on the owned
  patched app and tool matrix. The [determinism run](parameter-inference.md#three-run-determinism)
  verified 96 distinct headless workers.
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
- [x] Round-trip full annotation history and accepted return-type hints
  between compatible workspaces, with validated identity and atomic import.
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
- [x] Decode arm64e userland chained fixups through data-only file queries.
  Apple tooling matched 18 records across a linked format-12 fixture and
  two derived format-1/9 copies. Universal selection distinguishes arm64e.
  The decoder handled 12,000 seeded fixup-table and pointer mutations.
- [x] Probe authenticated instructions on an owned arm64e fixture in
  disposable full Ghidra. The loader accepted the image, but low p-code
  omitted signing and authentication effects.
- [ ] Validate authenticated call and pointer semantics before enabling
  arm64e engine import and analysis. Shared-cache, kernel and other
  chained formats remain outside the decoder.
- [x] Expose Objective-C classes, methods and selector references with
  static provenance. The owned app matrix matched 216 method addresses.
- [x] Expose Swift symbol-table names and optional sandboxed demangling
  with tool provenance. Broader Swift metadata decoding remains open.
- [x] Run source-aware recovered-C calibration for the two scalar comparison
  functions. [Measured scope and results](parameter-inference.md#recovered-scalar-behavior-calibration).
- [x] Measure 100% branch-direction coverage for the owned reference core
  with directed and seeded stateful tests. See
  [reference coverage](semantics.md#reference-core-coverage).
- [x] Compare all seven held-out switch routines across the frozen patched
  and control captures. The [behavior check](heldout-switch.md#recovered-c-behavior)
  records signed overflow and caller arity failures separately from
  recovered control flow.
- [x] Inventory all 26 public routines across the 16 patched calculator
  captures and test unmodified comparison, history and state routines against
  the reference. See [recovered core behavior](semantics.md#recovered-core-behavior)
  for instruction-byte denominators and the distinct blockers.
- [x] Evaluate aggregate returns, state transitions and formatting with
  strict sanitizers and immutable capture evidence. Run the frozen
  aggregate policy on a separate fixture. See
  [the combined results](semantics.md#combined-core-behavior).
- [x] Test an experimental [fixed-width C printer](fixed-width-printer.md)
  in a separately selected full Ghidra engine. It preserved the paired
  machine evidence and moved 120 calculator instances to full passes.
- [ ] Meet the recovered-C behavior and testability gates across the full
  core. In the fixed-width printer experiment, O2 coverage reached
  76.9% of routine instances and 51.2% of instruction bytes.
  Misaligned stores, unsupported signatures, vector operations and
  linkage remain open.
- [x] Measure owned-tool discovery against evaluator-side DWARF and linker
  starts. All 536 entries matched. LLVM confirmed a missed x86_64 O0 switch
  and adjudicated the x86_64 O2 padding discrepancy. See the
  [discovery measurement](parameter-inference.md#evaluator-side-discovery-measurement).
- [x] Freeze a [held-out switch variation](heldout-switch.md) before tuning.
- [x] Report unresolved computed jumps as partial in cached and fresh CLI
  views. Verified both owned switch fixtures and their resolved controls.
- [x] Recover the missing x86_64 O0 case blocks with a separately selected
  full Ghidra 12.2 tree containing the upstream native patch. Verified all
  calculator and held-out cases. See the
  [patch evaluation](heldout-switch.md#upstream-patch-evaluation).
- [ ] Validate a released patched engine before changing the default pin.
  The installed 12.2 engine continues to report the affected results as partial.
- [x] Exercise data-only parsers with 10,350 seeded Mach-O mutations and
  10,000 bundle plist mutations. Deep binary plist nesting, unexpected
  XML keys and unknown encodings now return typed `bundle_plist` errors.
- [x] List and inspect worker jobs and request cancellation through their
  live owner. A second CLI process cancelled an owned calculator analysis
  while preserving its previously committed snapshot.
- [x] Restart eligible unpublished analysis jobs with their recorded
  input, engine, isolation, profile, and limits. A live cancellation and
  restart reproduced the request and retained the prior snapshot until
  publication. Publication receipts make repeated requests idempotent.
- [x] Restart eligible unpublished import slices from the immutable workspace
  copy. An owned universal import resumed its cancelled x86_64 slice after
  removal of the original input and preserved the committed arm64 Program.
  Journal recovery verifies and publishes a saved Program across interruption
  before or after its directory move.
- [x] Restart fresh decompilation with the original saved Program and
  accepted hint revisions. A live cancelled query resumed after a newer
  analysis, label and hint were committed. A repeat read the durable result
  without launching another worker.
- [x] Fence a disconnected worker until the launch guard or the same-boot
  process-group check confirms it has stopped. A live owned Ghidra query
  outlived its supervisor. The CLI refused replay until the group exited,
  then replayed successfully. Older disconnected jobs and unverified boot
  identities remain ineligible.
- [ ] Expand malformed-input coverage and exercise isolation, schema migrations and
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
