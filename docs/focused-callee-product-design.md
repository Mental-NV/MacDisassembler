# Explicit focused callee parameters: provisional product design

**Design only; not implemented or enabled.** This follows the
[owned feasibility assessment](focused-parameter-assessment.md). The
[native negative-control protocol](focused-native-controls.md) and the additional
integration gates below must pass before shipping. No existing recovery option,
receipt policy, doctor capability or default behavior is changed by this document.

## User benefit and bounded selection

The demonstrated benefit is showing ordinary machine inputs at one direct call
whose selected callee is otherwise unprepared. It is not general source-type,
return, hidden-context, indirect-target or whole-program recovery.

A prospective spelling is:

```text
macscope decompile --project PROJECT --from-import --address CALLER \
  --infer-parameters-from CALLEE --trust-input
```

Treat that spelling as a proposal, not a command available today. Require one
explicit caller and one explicit callee in the same ordinary ARM64 slice. Reuse
unchanged exact-focus selection for both, require distinct nonoverlapping extents,
a directly decoded BL edge from caller to callee, a native-verified leaf callee,
and limits of 8192 bytes per extent and 16384 bytes combined. Require exactly one matching BL site in the caller for this first contract.
Reject multiple matches instead of guessing an edge; a future explicit call-site
selector would require a separate reviewed extension. No automatic candidate selection or recursive traversal.

Do not repurpose analyzed-query `--recover-callee-parameters`, silently turn on
whole-image analysis, or remove `engine.run`'s existing prohibition on combining
from-import with saved-analysis signature plans. A new dedicated typed request
path must preserve that prohibition for legacy calls. Reject incompatible hints,
return recovery, switch recovery, arbitrary boundary edits and fresh-analysis
options before launching a worker.

## New versioned request and provenance

Propose these distinct versioned identities, all unavailable in the current CLI:

- Request: `macscope-focused-callee-query-request/1`, stored under a separate
  `focused_callee_request` producer field.
- Receipt: `macscope-focused-callee-query-receipt/1`.
- Outcome/provenance policy: `macscope-focused-callee-parameters/1`.
- Result origin mode: `focused_readonly_import_callee_parameters`.

These are proposed identifiers, not an implemented runtime contract. A dedicated
request/result validator must dispatch them explicitly; do not silently add
inferred output to `focused_readonly_import`, reuse the analyzed-query recovery
identity, or teach the legacy focused-record reader to accept arbitrary schemas.
Keep old default request serialization and receipt interpretation intact. The
new receipt retains bounded request/result hashes and producing-job linkage,
but must fail closed in old readers instead of looking like an ordinary receipt.

The immutable request must bind at least:

- Project, artifact, slice, architecture and pristine import Program identities.
- Caller and callee exact extent proofs, byte digests and selection policy versions.
- Selected direct edge address, bytes and target, plus the edge-selection rule.
- Explicit parameter-only action, limits and recovery/scope policy versions.
- Producer bridge/package/runtime identities and no-analysis/read-only mode.

Bind request/result digests through the existing publication/ownership gate, with
explicit dispatch for the new policy. A caller's function identity is not itself
a sufficient query identity: two queries can concern the same function but have
different preparation/inference provenance. Never reuse an ordinary focused
receipt merely because its caller address or function ID matches.

Report preparation and inference separately. Preparation can change names even
when inference skips. Record the exact selected callee, body/byte proofs, native
scope checks before and after any commit, inferred ordinary register widths,
stored-return preservation and the actual skip/refusal reason. Do not imply that
`return_unchanged` establishes source ABI correctness. Retain caller scope,
instructions, diagnostics and partial coverage; inference must not launder a
partial caller into a complete result.

## Isolation and fail-closed publication

Reuse the production trust, dependency, worker ownership, limits, cancellation,
read-only source/copy checks and full teardown infrastructure. Do not ship the
experimental harness as a bypass to those checks. Use one disposable Program/JVM
per request, no persistent batch worker. The caller and callee prepare in that
copy only, preparing the callee first and the caller second as in the owned
protocol. A skipped inference still uses the distinct prepared-query provenance,
not an ordinary unprepared receipt. No inferred signature is persisted to original imports or snapshots.

Verify native callee scope against immutable selected extents before applying
parameters and after every subsequent verification decompilation. Preserve
existing custom-storage/signature/return refusals. Independently verify final
caller bytes, body, CFG/coverage and native scope. Missing, malformed, wrong-policy
or out-of-scope evidence is operational failure with no successful receipt.
Validate the new receipt, request producer field, origin and outcome policies
as one consistent tuple. Reject mixed old/new identities and duplicate producer
fields even when inference skips.
A legitimate unsupported-input skip is distinct and remains visible.

## Replay, resume and consumer integration

Offline replay must validate the exact new request, producer job, result digest,
all selected proofs, edge bytes, native/recovery provenance and immutable image
identities. It must never start Ghidra or silently reinterpret a legacy receipt.
New-policy data must fail closed in readers that do not support it. Preserve all
old-policy byte contracts and regression fixtures.

Resume must reproduce the same caller, callee, edge, policies, immutable input and
runtime constraints. An interrupted or failed attempt cannot become a success by
borrowing an unrelated receipt. Cancellation and restart-attempt ownership remain
with the existing lifecycle implementation.

Method dossiers, saved-query browsing and address-reference consumers need an
explicit policy review. They must preserve inference provenance and source-type
uncertainty, or reject the new receipt with a useful unsupported-policy error.
Do not automatically let these results establish indirect edges, runtime identity
or parity claims. Preflight may expose static selection evidence, but must still
say that native support, dependencies and inference success are unverified.

## Required gate matrix

Before a public implementation is considered ready:

1. Complete and independently review the owned native controls, identifying which
   failures were injected and which real behaviors were observed.
2. Fix exact request/result/receipt versions and unique-edge selection in tests.
3. Test stale/tampered caller and callee bytes, wrong Program/image, wrong edge,
   overlaps, nonleaf/unsupported callee, custom signatures/storage, return changes,
   missing/truncated/outside native scope, root failure and partial diagnostics.
4. Test failures before/after preparation and inference, timeout/cancellation,
   exact resume, uncertain termination and no publication after failure.
5. Test engine-free new receipt replay and mutation rejection, and unchanged old
   receipts/default CLI, dossiers and evidence consumers.
6. Repeat an owned native integration matrix using the actual product path, not
   only the experimental harness, with independent source/assembly comparison.

The present twelve-capture feasibility assessment establishes a useful narrow
positive and a conservative generic skip. It does not by itself close this matrix
or justify broader leaf/ABI/architecture support.
