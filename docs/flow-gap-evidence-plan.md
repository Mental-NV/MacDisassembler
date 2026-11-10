# Stage B: focused flow-gap evidence

Implementation plan and first-slice contract, 10 November 2026.

The implementation base is merged main
`c1e5f2062440709630bd56206e93ec408268d603`, tree
`a37e29b131d3626186ebadd960422cfb23192094`. All 254 tracked blobs were
verified before applying this stage. The earlier source research used main
`6bc177d2312f31a5448c0a02b9b007f13c9e21fd`; the relevant flow, receipt and
handoff implementations are unchanged between these bases.

This is a partial Stage B delivery, not completion of B1–B5. It does not
implement Stages C or D, Linux worker enablement, installation, a batch
command, or any new trust/isolation policy. All test inputs are project-owned.

## Findings and implementation boundaries

- `flow_evidence.review` preserves computed-jump CFG gaps, printer warnings,
  focused boundary gaps, native-operation scope, and separate BRK proofs.
  Its gap rows currently vary: some have `from`/`to`, some have a block range,
  and warning-only/native-scope rows have no source transfer site.
- `MacscopeBridge.instructions` and `cfg` already capture source addresses,
  variable-length instruction bytes, inclusive block ranges and edge sites.
  No bridge change is needed to attach locations for these existing records.
- A native high-p-code address outside the selected body identifies an observed
  operation, not necessarily the source of the transfer that reached it.
  Do not relabel it as an exact transfer instruction.
- `focused.verify` compares captured instruction bytes with the selected file
  payload before CLI publication. `resume_focused` and `evidence.focused_query`
  repeat source-byte verification during replay. These checks remain in place.
- Both `jobs.publish_query` and `jobs.query_receipt` call
  `focused.validate_result`. This is the production enforcement point for new
  semantic fields. A permissive JSON schema or a matching receipt digest alone
  does not validate site, bytes, identity or classification.
- `evidence.FUNCTION_FIELDS` already retains `control_flow_gaps`, instructions,
  origins, native scope, tail-call recovery and BRK evidence. The existing HTML
  renderer escapes and prints the complete gap objects. No separate export
  projection or HTML rewrite is necessary for this first slice.
- Ordinary analyzed-snapshot queries and focused receipts are different paths.
  This slice enriches newly captured focused v2 results only. Existing cached
  analyzed queries retain their current behavior until a later slice verifies
  their instruction bytes and adds the same contract deliberately.

## Reviewed additive contract: first slice

Existing gap fields are retained verbatim, including `reason`, `source`,
`warning`, `from`, `to`, `flow`, block bounds, policy and native-scope evidence
when present. No warning or pseudocode is suppressed or rewritten. No partial
result becomes complete because a location is now available.

Each gap in a newly captured focused result receives one optional `evidence`
object. The envelope, function identity, gap reason vocabulary, focused import
v1/v2 policies and receipt schema remain unchanged.

The object has exactly these fields:

- `policy`: `macscope-control-flow-gap-evidence/1`.
- `function`: the selected `function_id`, `image_id`, `arch`, `entry_va`,
  `slice_sha256`, `extent_sha256` and imported `program_sha256`.
- `location`: one of the forms below.
- `classification`: initially `{kind: unclassified,
  reason: classification_not_evaluated}`. This states what the first slice has
  actually established; it is not a positive linkage or internal-flow claim.

### Location forms

**Instruction:** `kind=instruction`, `instruction_va`, `instruction_bytes`,
`byte_verification=selected_extent`, `original_flow`, `effective_flow`.

An explicit edge/instruction `from` address must match a unique captured
instruction wholly inside a selected body range. For a computed-jump block
without a source edge, require a unique captured instruction ending at the
inclusive block maximum with a matching flow type. Use the instruction's
actual byte width, including for x86_64; never guess a four-byte terminal
instruction. Preserve original/effective tail-call flow already verified by
PR #3. The raw edge remains alongside this object.

**Block:** `kind=block_range`, inclusive `block_min` and `block_max`, plus a
reason such as `instruction_evidence_unavailable`,
`instruction_evidence_ambiguous`, or `exact_instruction_not_established`.
Choose the smallest supporting captured CFG block, with deterministic address
ties. Do not replace missing block evidence with the whole linker extent.
The enclosing function retains all captured instruction bytes; the range is
not a claim that one of those bytes is an identified transfer instruction.

**Unavailable:** `kind=unavailable` and an explicit stable reason:

- `warning_has_no_independent_site`: even when the warning contains an address
  equal to a captured instruction. Future correlation requires independent
  evidence; parsing the warning alone will never supply a location.
- `native_scope_does_not_identify_transfer`: native operation addresses remain
  available in the original scope object without becoming invented sources.
- `capture_incomplete`: an incomplete focused CFG/instruction capture has no
  narrower supporting source.
- `source_site_not_captured`, or an instruction-collection reason above: no
  exact instruction or trustworthy smaller block is available.

The instruction/CFG scans reuse the current 2,000-instruction, 500-block, 500-edge and
512-body-range bounds. They add no metadata inventory, file reads, subprocess or Java launch.
Malformed, duplicate, overlapping, out-of-body or wrongly sized instruction
records cannot supply a precise site.

### Publication and replay validation

1. Enrich after engine source-byte verification and after the CLI has assigned
   its pinned function/image identity. Do not enrich an old saved receipt.
2. When any new `evidence` field is present, require it on every gap in that
   function, exact supported fields and policy, matching selected identity,
   consistent location and bytes, and the implemented classification.
3. Revalidate raw gap sources against the existing focused detectors and compare
   the resulting enrichment. A fabricated raw reason, removed source warning,
   extra classification claim, altered byte or stale identity is rejected by
   the production receipt writer and reader as `query_receipt`.
4. Require a partial envelope and a non-complete function when new gap evidence
   is present. Preserve failed/timeout/cancelled function outcomes.
5. Keep old v1/v2 receipts without the optional fields unchanged. No automatic
   backfill, policy upgrade, new classification or rewriting occurs on replay.
   Their existing request/result/producer identity checks and v2 scope safety
   checks continue to apply.
6. Keep this policy's validation interpretation stable. If the future detector
   set, classification or derivation rules change, introduce and dispatch a
   new evidence policy rather than invalidating or silently upgrading saved
   policy-1 receipts. Receipt hashes provide integrity binding, not signatures.

The bundled function schema describes the optional object shape. Python
semantic validation is authoritative for the discriminated location variants,
source relationships and equality to captured evidence. JSON Schema alone is
not an acceptance oracle.

## Remaining implementation slices

### B linkage/internal classification

A separate policy extension must add proof-bearing categories after review:

- `verified_linkage_boundary`: a byte-decoded source transfer plus the relevant
  ordinary stub/relocation proof, or a bounded independently checked wrapper
  instruction sequence and same-slice selector evidence. A direct call's name
  or a function name containing `wrapper` is not a proof.
- `unresolved_internal_transfer`: only when local instruction/edge evidence
  establishes the relevant in-image/internal control-flow relationship. An
  arbitrary indirect jump with unknown destination stays `unclassified`;
  failure to prove linkage does not prove internal dispatch.
- `unclassified`: evidence is absent, unsupported, ambiguous or bounded before
  the necessary proof. Retain the specific reason and raw gap.

Reuse `import_links.stub_slot`, `strong_bind`, exact source-byte checks and
existing `focused_tailcalls` proofs. Do not expand wrapper matching into whole-
image analysis. Bound candidate sites, stub reads, fixup lookups and additional
bytes explicitly. Record unsupported authenticated/weak/flat bindings rather
than weakening their current rejection rules. External system-library
linkage classification need not prove a bundled provider: current
`ImageLinkage.call` intentionally filters such providers from bundle handoffs,
so do not use its absence as proof of no linkage.

Selector evidence proves selector material and its proven use at the selected
site, not a unique runtime receiver/callee. Keep runtime target unresolved.
A static boundary category says nothing about relevance to a business
question. Analyst facts, bounded inferences and unknowns remain separate.

Do not reintroduce a gap for a proven ordinary tail call merely to demonstrate
classification. B1's fixture must contain a genuinely unresolved transfer
which survives the current recovery policy. Use an independently authored
wrapper/handler case with an observable local write or state comparison and a
real residual indirect transfer, not the already-complete ordinary tail stub.

### Durable cached and general query evidence

Extend newly captured analyzed snapshots and fresh analyzed queries only after
verifying same-image source bytes. Fresh queries currently borrow saved CFG
and instruction evidence; bind that origin explicitly rather than presenting
it as a new worker capture. For incoming fallthrough-boundary gaps, the source
may belong to another function. Preserve that separate owner if independently
captured, otherwise report an unavailable site. Never assign a predecessor's
instruction to the selected function.

Apply the same optional-field checks to general query publication/replay and
snapshot validation. Preserve existing cached snapshots and old receipts,
including ones that lack CFG, fallthrough or native-scope fields. Ensure all
CLI projections that carry gaps also carry their evidence without dropping
pins. Keep repeated reads idempotent and offline.

### Live owned focused validation

Extend the project-owned fixture/integration rather than interpreting any
third-party application. Run arm64 and x86_64 independently, never treating a
CPU-header mutation as a native integration. Capture public `--from-import`
JSON, exact instruction bytes and original/effective flow, receipts and
JSON/HTML evidence handoffs. Independently inspect selected source bytes and
linkage with Apple tools when supported.

Use a fresh private project under an existing output parent. No whole-image
analysis. Retain source/input/Program/engine/bridge identities. Prove the
original binary and saved Program remain unchanged. Remove access to the
original app path and make Ghidra unavailable before replaying from the saved
project inputs and receipts. Do not remove the immutable saved slice required
for byte revalidation or misdescribe that as app-independent reconstruction.

Exercise trust denial before launch, a real supervised timeout, cancellation,
resume identities, partial exit code 6, damaged source bytes, and deterministic
exports. Distinguish a worker failure without a receipt from a committed
partial function result. Do not manufacture successful receipts for killed
workers.

## Acceptance and tests

- **B1, remaining:** live owned wrapper-plus-handler evidence for a supported
  local effect plus retained unresolved linkage/dispatch and proof-bearing
  classification. The first slice does not claim this gate.
- **B2, partially implemented:** exact ARM64/x86_64 source locations, block and
  unavailable-site fallbacks, unchanged partial status and explicit unknown
  category have owned unit coverage. Positive internal classification and
  live cases remain.
- **B3, partially implemented:** production focused capture/publication/replay
  and deterministic JSON/HTML handoff tests use owned worker records. They
  verify immutable warning/evidence payloads, rejection of mutated new fields
  even after recomputing receipt and producer digests, and unchanged legacy
  v1/v2 replay. General cached-query coverage and live replay remain.
- **B4, partial negative coverage:** wrapper-like names and selector labels
  never upgrade a classification; unsupported positive classifications and
  fabricated runtime-callee fields are rejected. Positive selector/linkage
  proofs and their adversarial mutations remain.
- **B5, unrun for this slice:** no live Ghidra, Apple build, timeout or
  cancellation integration was performed by this cloud change. Existing
  unit regressions are not substitutes for those gates.

Test additions include:

- ARM64 and variable-width x86 exact terminal instructions, explicit edge sites,
  original/effective flow, duplicate/overlap/width errors and capped evidence.
- Smallest supported block, warning-address spoofing, native-operation/source
  distinction, no invented range, no-gap identity and no source mutation.
- Function/image/slice/extent/Program identity mutations, unsupported policy or
  classification, extra fields, missing per-gap extension, false complete
  status, malformed origin extent, stale raw warnings and legacy replay.
- Engine-free receipt replay, preserved raw warning, unchanged receipt bytes,
  deterministic JSON and escaped deterministic HTML handoff.

Run from repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests python3 -m unittest \
  test_flow_gap_evidence test_trap_flow test_focused_boundaries \
  test_focused_tailcalls test_flow_boundaries test_query_resume -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis python3 -m unittest discover -s analysis/tests -v
```

Before publication: independently review the actual diff, run the affected and
full suites, verify source/package parity, and record exact source identity and
remaining gates. No installed command changes or publication are part of this
first-slice checkpoint.

## First-slice source validation

The final cloud source run passed 548 primary tests, 106 analysis tests, and
75 focused flow/receipt tests. The new module contributes 16 new tests plus
five inherited replay-safety regressions, all passed. The source/package check
built the wheel without installation and compared all 67 runtime members with
their source bytes. The handoff projection also now retains the original
`engine_decompile_status` alongside the reviewed partial status.

Runtime source fingerprint:
`f95250b6c7ed4e55bfb646d0dac20bf6fe6c770e9dbbf2b34f53ab0c322a5b5f`.

This is SHA-256 of compact key-sorted JSON mapping repository-relative `src/`
`.py`, `.java` and `.json` paths to their SHA-256 values, excluding bytecode.
Wheel SHA-256:
`0b6df0e4db0be9a7faaa6be375c3a1e0b7e467cee9aff61a004cf04161c1efc9`.

No live engine/Apple integration, installation or remote publication occurred
for this checkpoint. The acceptance limitations above still apply.
