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
  function list/show, disassembly, cached pseudocode, references,
  CFG JSON/DOT, project/job status, cached search and normalized exports.
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

Public queries use completed snapshots. A read-only/noanalysis reopened-engine
query was independently tested, but a public uncached-decompile/refresh
command remains unexposed. Token/address spans, polished terminal output,
all Mach-O load-command/dyld decoding and broad host/version support remain
incomplete. Some calculator batches correctly exit6 because their reference
collections exceed documented bounds despite successful pseudocode output.

## Later phases and separate gates

- [x] Reproduce owned stripped x86_64 instruction checks using independent
  function-start metadata. See [profile validation](parameter-inference.md).
- [ ] Complete the narrow CLI evidence path with uncached selected-function
  decompilation, token/address spans and reproducible timing measurements.
- [x] Search committed function names, symbols, strings and pseudocode
  with resumable pages and scoped coverage.
- [ ] Add bounded call traversal, revisioned annotations and explicitly
  applied type hints.
- [ ] Add Objective-C/Swift views and explicit bundle image/resource selection.
- [ ] Measure blind discovery and false positives on the owned corpus. For
  behavior, freeze a mechanical recovered-C harness before held-out scoring.
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
