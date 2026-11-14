# Macscope bulk pseudocode export plan

Status: proposed specification, not an implemented command. No Rust rewrite.
Prepared 12 November 2026. Parent roadmap: [export readability](export-readability-roadmap.md). This plan changes bulk-export execution, not the
meaning of existing isolated focused-query receipts.

## Goal

Export large applications such as TickTick efficiently, grouped by native image
and optionally class, while keeping raw pseudocode, per-function limitations,
resumability and reproducible provenance. Do not execute or modify the target app.
No promise to reconstruct all original source, discover every function, or prove
runtime behavior.

## Current evidence and baseline

Inspected source at `df3cc75`: `src/macscope/engine.py`,
`src/macscope/bridge/MacscopeBridge.java`, and existing batch/benchmark documents.
The Python supervisor launches Ghidra headless Java; Ghidra's decompiler is already
native C++. The existing analyzed-image bridge opens one `DecompInterface` and
iterates functions, but aggregates results with function/output caps. The new
standalone per-address export script instead repeats worker setup to obtain
focused coverage and can take days. It is not the desired bulk architecture.

`docs/focused-import-benchmark.md`: on a small owned fixture, Apple M5/24 GiB,
Ghidra 12.2, 20 rounds, five ARM64 fresh queries took median 22.500 s; the five
native decompiler calls totaled median 0.050 s. Five cached replays took 0.736 s.
Startup, worker and decompiler-open intervals overlap and must not be added.
This is not measured TickTick throughput; no speedup is promised from it.

## Proposed product contract

Introduce an explicit **bulk export session** that owns one disposable Program
and decompiler per native image and finite chunk. Do not silently batch existing
`decompile --from-import` commands. A versioned bulk receipt must say that entries
share an analysis session; it must not claim pristine per-entry isolation.

The existing `bounded-focused-batch-proposal.md` intentionally requires fresh
Program/native state per entry and has unresolved lifecycle gates. Do not claim
that proposal is implemented or reuse its receipt semantics. Review this distinct
contract before coding; preserve existing trust and filesystem protections.

Initial mode: serial images, one active chunk, no resident daemon. A chunk has
finite function/time/output budgets; exact defaults are selected from profiling.
Recycle at chunk boundaries rather than allowing an unbounded JVM lifetime.

### Discovery

- Create a frozen input manifest of image-relative path, binary/slice hashes,
  architecture, source identity, selected functions, discovery sources and gaps.
- Inventory is explicitly a lower bound. Distinguish linker starts, Ghidra
  functions, metadata-only methods, external entries, thunks and unresolved code.
- Never treat pagination as bypassing a discovery cap. Expose all caps/truncation.
- First deliver the mode for existing analyzed images; then add a bulk preparation
  path for imports. Full-main autoanalysis timeout must not block every image.
- Bulk preparation must not just repeat single-function `MacscopeFocus` mutations
  on one Program: design collective preparation and test order dependence.

### Streaming and layout

- One record per address, plus separate image/class indexes. Multiple class owners
  reference the same pseudocode artifact. Unknown ownership remains visible.
- Preserve raw Ghidra text and structured warnings; no AI cleanup of evidence.
- Worker emits bounded, framed candidate records to staging. Supervisor validates
  identity/schema/size and atomically commits each artifact; the worker cannot
  rewrite committed evidence. Avoid a giant whole-image JSON object in memory.
- Image summary separately counts discovered, eligible, attempted, successful,
  partial, failed, timeout, skipped and not-yet-attempted functions.
- A run finishing operationally does not mean complete semantic coverage.

### Resume and compatibility

- Resume only when target/slice, Ghidra/JDK/bridge, options, discovery schema and
  analysis profile identities match. Reject mismatches without overwriting data.
- Verify existing artifact hashes before reuse; replay is labeled cached.
- Keep each completed record durable before advancing its checkpoint. On restart,
  derive progress from verified records, not a possibly stale summary file.
- Preserve the frozen original selection and add new discovery only in a new run.
- Class grouping is an independent indexing stage and can run without decompiling
  again. Later string annotation also needs separate raw-versus-derived output.

### Failure, cancellation and lifecycle

- Bound startup, chunk and per-function time, stdout/stderr, record size, disk use
  and retry count. Include free-space reserve and sampled RSS reporting; do not
  describe JVM heap as a hard process-memory limit.
- On native timeout/crash or uncertain state, close the chunk, retain committed
  records, and mark remaining entries pending. Restart from a fresh chunk only
  under an explicit bounded retry policy; never retry forever or silently skip.
- Healthy semantic partial results may commit with their limitations. Native
  failure is not relabeled partial success.
- Ctrl-C stops new work, requests cancellation, then terminates the entire owned
  process tree under a deadline. No subsequent chunk starts until teardown is
  verified. Ghidra `dispose()` alone is not proof of native process exit.
- Test normal release, cancellation during opening/decompilation/commit, forced
  JVM/native death, disk-full, interrupted supervisor and stale locks. Preserve
  already committed records across all these cases.
- No new privileges, broader home access, network access, application execution,
  target modification, private-API reflection or sandbox weakening. This remains
  explicit trusted-input static analysis, not a hostile-binary sandbox guarantee.

## Phased delivery and engineering effort

1. **TickTick profiling and contract review: 0.5–1.5 days.** Use a fixed small
   Calendar library plus a stratified main-image sample. Record wall time, JVM
   startup, Program open/copy/hash, native calls, publication, RSS and output size.
   Separate cold/warm and replay runs. Pin versions and sampling seed.
2. **Finite per-image prototype: 2–4 days.** Stream an explicit selection through
   one analyzed-image Program/decompiler, serially, with raw receipts and timing.
   Owned fixtures first; then the same TickTick sample. No shipping completeness
   claim. Decide whether imported-image preparation is a separate iteration.
3. **Production hardening: another 4–8 days.** Resume/checkpoint identity, supervisor
   publication boundary, cleanup/cancel/failure tests, documented output schema,
   CLI/help, integration and native regression tests. Shipping gate below.
4. **Optional bounded concurrency: another 2–4 days.** Start with two independent
   images, each with its own Program, if memory and disk measurements support it.
   Never share a mutable Program across concurrent workers.

These are person-day estimates, not calendar promises. A several-fold throughput
gain is an objective to measure, not a commitment. Complex function analysis can
remain expensive. No Rust rewrite is planned; use the existing Python/Ghidra stack.

## Acceptance gates

- No changes to existing single-query/replay outputs or safety behavior.
- Owned fixture batch results compared with fresh singles; changed output must be
  explained. Test A/B/A and reversed ordering, type/symbol preparation interactions,
  shared callees and malformed inputs. Known state leakage is a release blocker.
- Inventory greater than 10,000 entries traverses without silent truncation;
  external/unsupported/undiscovered coverage remains explicit.
- Deterministic indexes and valid address links; Unicode/path collision tests;
  multi-owner class mapping never duplicates or loses raw evidence.
- Inject each failure described above; resumes neither duplicate nor drop records,
  and no worker/process/lock is left alive after verified stop.
- Test memory/disk budgets on the supported Mac. Report median/p95 throughput and
  peak RSS on the same TickTick sample with the same semantic coverage. Reject a
  claimed speedup achieved by omitting evidence, lowering quality or raising caps.
- Independent code/design review, exact-head unit/integration CI and native Mac
  smoke test pass before merge/release. Full TickTick export is a long-run test,
  not the prerequisite for every small code change.

## Proposed order

Profile → review separate bulk-session contract → streaming batch prototype →
failure/resume hardening → class indexes → evaluate concurrency. String discovery/annotation is a requested roadmap workstream; inclusion in an
individual bulk run remains optional. Use evidence-backed annotations, never
regex replacement of unknown addresses in raw pseudocode.

## First implementation checkpoint: analyzed-image finite batches

`macscope batch-export --project PATH --image IMAGE --trust-input --batch-size 32`
uses one read-only disposable analyzed Program and one decompiler interface per
bounded selection chunk (1–128 entries). `--entry 0x...` is repeatable; omitting it
selects the captured RAM functions in the committed analysis, **not every function
in the binary**. Exports live under the project’s `batch-exports/<identity>/`;
`functions/0x….json` retains raw engine pseudocode, status, job and shared-session
provenance. `index.json` binds records to hashes. `--resume` verifies frozen
analysis/runtime/options and hashes before reusing committed chunks. A partially
interrupted chunk is replayed as the same original selection rather than changing
its shared-session semantics.

This is not an isolated `decompile --from-import` replacement. The existing
TickTick per-function focused-import exporter cannot simply switch to this command:
it needs a committed analysis first, and its linker-bounded focused results have
different semantics. Collective import preparation, exhaustive inventory and
bounded within-chunk candidate streaming remain follow-up milestones. The first
checkpoint retains the existing 64 MiB chunk response ceiling and per-job resource
limits. It must not be advertised as a full-image streaming exporter or a measured
TickTick speedup.

`--reserve-mib` defaults to 1024: before each chunk the coordinator checks free
space for the baseline Program copy, the reserve and bounded response allowance.
Successful validated chunks commit records before deleting only their own
throwaway Program copy; the reusable analyzed baseline and receipts remain.
Failed workers retain diagnostics. Native validation and performance measurements
are required before this checkpoint can be called ready.

Resume hardening additionally validates each cached record's embedded export,
function, original chunk and worker-session provenance, not only its index hash.
See [batch resume validation](batch-resume-validation.md) for the bounded contract
and corruption regression tests. This does not authenticate owner-editable files
or change the export identity, engine semantics or cleanup policy.

A bounded [owned native comparison](owned-batch-comparison.md) now verifies
identical records for three selected functions across size-1/size-3 runs and
measures warm setup amortization. It does not establish TickTick throughput,
focused-export acceleration, or the broader acceptance gates above.

Focused-query supervisor diagnostics are described in [focused phase timing](focused-phase-timing.md); they do not change execution or receipt identities.
