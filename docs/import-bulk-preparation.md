# Import-to-bulk preparation: bounded implementation contract

Status: design only, 14 November 2026. No new command or speedup shipped.
Extends [bulk export plan](bulk-export-plan.md), not the isolated
[focused batch proposal](bounded-focused-batch-proposal.md).

## Decision

Amortize repeated Ghidra setup, not Python arithmetic or Program copying. Retain
all input/runtime hashes, sandboxing, budgets, cancellation and ownership checks.
Do not change `decompile --from-import` or its independent receipt semantics.
Do not transparently route it through analyzed `batch-export`.

The next bounded feature should be an **explicit shared import chunk**: one
pristine import copy, collective preparation of a finite selection, one native
Decompiler session, and full worker-process teardown before another chunk. No
resident daemon, fresh-Program switching inside a long-lived JVM, or cross-chunk
mutable state. This avoids depending on the unresolved asynchronous disposer
fence required by *isolated* focused JVM reuse; it does not remove the existing
process-ownership/teardown gate.

## First implementation milestone

Start with an opt-in owned-fixture-only experiment of 3–8 exact linker entries,
not a production exporter switch. Prove collective preparation and shared-session
order behavior before expanding toward the following production contract.

## Selection and identity

Proposed later production scope: ARM64, explicit canonical linker-start entries
only, 1–128 per chunk (a safety cap, not a tuned recommendation; the first owned
experiment remains 3–8).  Discovery is a lower
bound, not all application functions. Preserve unresolved metadata-only addresses
outside the selected inventory. Do not overlap Muse grouping/string work.

A new versioned manifest must include source/slice/import Program digests,
runtime/bridge identities, collective-preparation policy, fixed sorted selection,
validated extent/byte proofs, per-chunk membership, output limits and options.
Use distinct shared-import semantics and export identity. Existing analyzed-batch
receipts and focused receipts are incompatible and must never be resumed or
relabeled as this mode. Chunk-size/membership changes require a new export ID.
The exact CLI/schema names need implementation review before freezing.

## Collective preparation, not repeated Focus scripts

1. Supervisor freezes exact linker extents from trusted bytes. Retain the current
   per-extent 8 KiB bound initially. Validate all selected ranges, duplicates,
   overlap, executable mapping and proof sizes before launching. Reject an
   invalid selection without silently shrinking it.
2. Worker verifies input/runtime/Program identities and autoanalysis is disabled.
   Collectively validate all requested spans and existing function/body conflicts
   **before** changing the disposable Program. Never overwrite existing imports,
   active analyses or saved focused evidence.
3. Disassemble each canonical bounded span and explicitly construct its decoded
   instruction body. Do not enable unrestricted follow-flow or whole-image
   autoanalysis. Gaps/invalid instructions must be represented as partial or
   rejected according to a documented policy, not silently accepted as complete.
4. Handle function/body conflicts fail-closed. Initial implementation should
   reject thunks, external entries and ambiguous pre-existing overlapping bodies
   rather than infer ownership. Never solve a conflict by deleting another body.
5. Initial scope does **not** apply focused tail-call overrides or signature/type
   recovery. Record unhandled inter-span transfers and resulting limitations.
   Adding collective recovery later requires separate policy/version/tests.
6. Complete all preparation before opening the Decompiler session. No preparation
   mutation interleaved with decompile calls. Emit per-entry bodies/coverage and
   shared-session provenance. Validate worker records against the frozen plan.

A shared Program can influence inferred names, types, references and output.
This is intentional but must be visible. It is not pristine per-entry focused
analysis. No automatic claim of output equivalence to focused mode is permitted.

## Publication and resource boundary

Prepare and query inside one disposable chunk worker; do not publish this as an
ordinary committed analysis snapshot or alter `active_analysis`. Add an explicit
source-mode path rather than counterfeit analyzed-image metadata. Reuse existing
bounded record validation/publication code only after checking its assumptions.
No executable cache or global analysis state is needed.

The supervisor owns durable per-function files and index publication. Bound total
request/output bytes, selected aggregate bytes, functions, worker time, native
function time, heap, logs and sampled disk usage; derive aggregate byte limits
from the selected proofs. A 128-entry cap alone is insufficient. Keep existing
warnings that heap/disk sampling are not hard OS-wide limits.

On worker failure, cancellation, timeout or malformed output: stop admission,
retain diagnostic evidence, verify owned worker teardown and do not publish a
successful chunk. Resume only against identical frozen inputs/options and verified
records. Prefer all-or-nothing chunk acceptance initially; streaming durable
acceptance is a separate extension. Do not remove intermediate data until exact
exported records are durably verified. Leave original importer/exporter untouched.

## Required gates before any TickTick adoption

- Owned fixtures: mutual calls, adjacent spans, gaps, overlaps, stubs/thunks,
  conflicting pre-existing bodies, malformed bounds and maximum-size input.
- Same unique membership, fresh-copy ascending/descending preparation order:
  require normalized prepared bodies, symbols and decisions to agree. Separately
  run repeated A/B/A
  and B/A/B decompile calls after identical frozen preparation to expose shared
  cache effects. Duplicate selection entries remain invalid. Detect/order-explain
  evidence changes; no hidden dependence on previous chunks. Keep production
  ordering canonical.
- Compare isolated focused and shared output, retain differences rather than
  normalizing away bodies/types/coverage. Equivalence is not an assumed gate;
  honest provenance and conservative limitations are.
- Native timeout/cancel/malformed-record and publication-interruption controls;
  no next chunk until teardown verified. Baseline import bytes/hashes unchanged.
- Resume identity tests, request/record membership checks, caps, corrupted index
  rejection and exporter cleanup interoperability.
- Independent review, full tests, owned native correctness before a bounded real
  sample. Benchmark identical selected sets, include preparation and publication
  wall time and storage; report errors and partials, not only successful latency.

Only then add an explicit opt-in path to the user's exporter. Keep its existing
focused mode default until quality/performance evidence supports a deliberate
migration. No Rust rewrite or arbitrary increase in concurrent JVMs is proposed.
