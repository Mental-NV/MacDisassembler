# Bounded focused batch proposal

**Review-only specification. No implementation or new available command.**
The [Stage D measurements](focused-import-benchmark.md) determine whether to
pursue this proposal. Review the request, receipt, and lifecycle contracts
before coding. No speedup is promised.

## Purpose and non-goals

Amortize repeated JVM/headless startup across a small explicit selection while
preserving independent single-function evidence. One invocation uses one
project, image, architecture, and verified saved no-analysis import; one
short-lived supervised worker; one CPU; and sequential entries.

No persistent service, cross-invocation engine cache, whole-image analysis,
implicit callees, discovery expansion, type hints, analyzed snapshots,
automatic installation, or changed trust/isolation policy. Existing receipt
replay remains preferable when the captured evidence answers the question.
Replay is not fresh analysis.

## Proposed interface

These names and schemas are proposals, not existing commands:

```text
macscope decompile-batch capture --project PROJECT --image IMAGE --arch ARCH \
  --from-import --addresses-file SELECTION.json --experimental-trusted-input \
  [--timeout 300] [--startup-timeout 60] [--function-timeout 15] \
  [--entry-timeout 30] [--wall-timeout 360] [--heap-mib 1024] --format json
macscope decompile-batch replay --project PROJECT --batch-id ID
macscope decompile-batch resume --project PROJECT --batch-id ID \
  --experimental-trusted-input
```

```json
{"schema":"macscope-focused-batch-selection/1","entries":["0x100001000","0x100002000"]}
```

Require explicit image and architecture. Accept only canonical unslid hex
addresses in ascending numeric order. Reject duplicates, unknown keys,
malformed JSON, symlinks/nonregular files, incompatible flags, or oversized
requests. Validate the entire selection before Java starts; never silently
skip an invalid entry. Fix `--jobs` at one and continue rejecting unsupported
hard process-memory caps.

Initial fixed bounds, subject to review:

- Selection file: 16 KiB; 1–16 entries.
- Preserve 8,192 bytes per linker extent; at most 65,536 cumulative selected
  extent bytes. Charge full extents, not just decoded instructions.
- Preserve per-entry tail-call proof limits of 128 KiB and at most 64
  candidates, plus all tighter bridge, nesting, log, and validation limits.
- Per-entry serialized receipt: 8 MiB; cumulative receipts: 64 MiB.
- Batch index: 1 MiB, referencing receipts rather than duplicating their bodies.

Do not offer options to raise count/byte caps initially. Charge bytes before
publication. An oversized result is a failed item, not a silently truncated
valid receipt. These proposed caps are safety defaults, not tuned results.

## Exact selection and independent state

Each entry must meet the existing focused contract: complete linker start and
next-boundary evidence, unique executable file-backed mapping, valid
architecture/alignment/data-in-code handling, pinned slice/extent bytes, and
verified saved Program identity. Preserve raw-CFG, tail-call, BRK, native-scope,
and unresolved-flow checks. Selecting more entries must not expand any one
function's evidence scope or imply a unique runtime dispatch target. Verify the
immutable import before copying/opening it, and validate each output against
its pinned request and source bytes before publication.

**Initial design: reuse the ephemeral JVM, not mutable per-entry analysis
state.** Derive every entry from the pristine verified import, with an
independent disposable Program and a fresh `DecompInterface`. Dispose/release
both before the next entry. Carry no learned signatures, functions, references,
flow overrides, analysis queues, symbol/type changes, or native caches forward.
Never save entry modifications or change active analysis.

The existing `MacscopeFocus.java` commits preparation changes inside its
disposable Program for the post-script. Looping it against the same mutable
Program is not adequate isolation. A read-only open does not prevent in-memory
mutation, and `flushCache()` alone is not proof of reset. Shared mutable Program
or native decompiler reuse is deferred to a separate reviewed design.

The supported mechanism for independent disposable Programs within one worker
is an implementation prerequisite, not an assumed API. If it cannot be proven,
stop rather than weaken isolation. This conservative design leaves some
Program/decompiler opening cost unamortized.

## Deadlines, cancellation, and resources

Proposed defaults and accepted ranges:

| Budget | Default | Range | Starts/includes |
| --- | ---: | ---: | --- |
| Startup | 60 s | 1–300 s | Worker launch to readiness |
| Worker wall (`--timeout`) | 300 s | 1–3600 s | Launch, including startup |
| Entry wall | 30 s | 1–120 s | Preparation, opening, decompilation, extraction, serialization |
| Native decompilation | 15 s | 1–120 s | One native call |
| Command wall | 360 s | 1–3600 s | Before verification, including publication |

Require startup ≤ worker ≤ command, and native-call ≤ entry. Always enforce
the earliest remaining deadline. Preserve the 1024 MiB heap default and existing
256–4096 MiB range; this is not a hard RSS bound. Preserve existing sampled
storage limits and label them as sampled rather than filesystem quotas.

Entry wall starts when work on that entry begins and is observed by an
independent supervisor even while native work hangs. Supervisor validation and
publication are additionally bounded by command wall, not the entry timer.

The supervisor enforces deadlines independently of Java cooperation using the
existing owned-process-tree termination protocol. Do not begin another entry
after cancellation or expiry. Noninterruptible filesystem operations can delay
return; do not promise an absolute kernel-level deadline.

Record command wall, launch/readiness, Program/database opening, decompiler
`openProgram`, native calls, extraction, and publication separately where
instrumented. Missing intervals are unmeasured, not zero. Nested intervals must
not be summed. Timing remains outside normalized evidence.

## Request and receipt identities

Proposed `macscope-focused-batch-request/1` includes:

- Project/image IDs, architecture, artifact/slice/import-Program hashes, and
  `source_analysis_id: null`.
- Ordered individual focused requests, extent/byte proofs, policy versions,
  exact limits/options, bridge and pinned dependency identities.
- Canonical request digest, computed over the request payload excluding its
  own digest field.

Proposed `macscope-focused-batch-result/1` includes batch/attempt IDs, request
digest, worker terminal status, aggregate coverage, stop reason, status counts,
and ordered items. Each item records its exact entry, focused-request digest,
producer attempt, receipt hash/reference when published, stable error/coverage
reasons, and `capture_kind: fresh | saved_replay`.

Item states: `not_started`, `running`, `complete`, `partial`, `failed`, `timeout`,
or `cancelled`. Valid complete or semantically partial items receive immutable
independently validated function receipts. Failures receive structured records,
not fabricated function receipts. Preserve all current function/envelope fields,
raw warnings, gap evidence, proofs, and partial status.

Use a new versioned batch-entry receipt wrapper and validator. Do not disguise
an entry as an existing standalone query job: current receipt validation binds
evidence to a complete producing job, whereas entries can commit before the
batch terminates. Bind the wrapper to the batch-request digest, original batch
ID, producer-attempt ID, entry ordinal/address, focused-request digest, result
digest, and immutable per-entry completion record. Validate committed entry
completion, not completed parent-batch status. Preserve original fresh-capture
provenance; mark later saved replay only in the invoking index/report, without
rewriting the receipt. Keep existing single-query and v1/v2 contracts intact.

## Atomic publication and failures

For every item, the worker finishes bounded private output; the supervisor
verifies schema, identities, bytes, coverage, and limits; then atomically
publishes the immutable receipt and updates the batch index. Never accept a
partially written worker output. Recover a crash between receipt publication
and index update through validated receipt discovery, without duplicate commits.

Stop on the first operational failure by default:

- Valid semantic partials commit and processing continues.
- Entry failure, timeout, output-limit violation, or unsafe reset stops remaining
  entries. Crash, integrity mismatch, cancellation, or global deadline also stops.
- Prior independently validated receipts remain available; remaining items say
  `not_started` and retain the stop reason. Suspect uncommitted data is not evidence.

Operational completion and evidence completeness remain distinct. A finished
worker can return a partial evidence batch. Preserve existing exit conventions:
zero only for complete evidence, existing partial/failure/timeout categories,
and cancellation 130. Freeze aggregate precedence in interface review. Include
the batch ID whenever a recoverable record exists.

## Trust, replay, and resume

Require explicit trust on **every engine-launching invocation**, including
resume. Never derive trust from a receipt or old attempt. Preserve dependency
verification, private directories, sandbox restrictions, owned-process handling,
and source-integrity checks without adding privileges.

Replay never starts an engine or silently recaptures evidence. It validates
saved identities, request/result hashes, producer records, and captured evidence.
Require saved project/import identity records, the saved slice used to reselect
the extent and check instruction bytes, and request/producer/receipt records.
The original application, actual Program database tree, and Ghidra need not be
available for a valid saved receipt. Fresh continuation has stronger checks.
Replay is not a claim of fresh analysis; corrupt/missing records fail explicitly.

Resume requires confirmation that prior workers stopped using existing leases,
ownership tokens, boot/process identities, and restart fences, plus an exclusive
batch-resume lease. Revalidate the original request and every reused receipt.
Fresh continuation requires exact source/import/architecture/policy/runtime/
limit identity. Changed identities require a new batch, not silently edited
history.

Create a new attempt with original-batch ancestry. Skip only committed valid
receipts, including semantic partials. Restart interrupted/failed work from
pristine state, then continue; never resume native execution state or retry
indefinitely. Preserve old receipts/attempts. Recapturing a committed partial is
a new request. Label replayed versus freshly captured entries separately.

## Compatibility and review gates

Existing single-address commands, schemas, receipts, job behavior, and export
semantics remain unchanged. The batch index is not an analysis snapshot. Do not
implicitly batch existing commands. Export/handoff tooling must explicitly
support the new wrapper or reject it. Installation and Linux enablement remain
outside this proposal.

Before implementation, review interface names, per-entry wrapper, publication
lifecycle, resource defaults, exit precedence, filesystem durability, and the
supported independent-Program mechanism. Before release require:

1. Selection limits and one-over tests, duplicates/interior/missing-next entries,
   mixed images/architectures, malformed mappings, and denied trust.
2. Dual-architecture parity with independent single-address captures.
3. Adversarial order-independence: reversed/permuted entries, adjacent
   caller/callee, tail overrides, conflicting function/type state, partials,
   exceptions, and timeouts.
4. Unchanged saved Program/active-analysis identities; changed digest/runtime/
   policy refusal; unchanged sandbox and no surviving worker.
5. Startup/entry/native/serialization/publication deadlines and cancellation at
   each boundary; actual owned descendant termination.
6. Crash tests around both atomic steps; no torn receipts or false completion.
7. Concurrent resume, stale leases, PID reuse/reboot, tampered receipts, changed
   options/dependencies, and explicit mixed replay/fresh provenance.
8. Offline replay with original app absent and engine unavailable; deterministic
   normalized JSON/HTML and preserved raw gaps/warnings.
9. Compare fresh singles, fresh batch, and replay separately on the D1 workload.
   Record all samples/failures and pins; at least 20 repetitions before p95 or
   gates. Do not select only successful timings.
10. Full relevant unit, receipt, lifecycle, cancellation, isolation, and package
    checks. Mark unrun gates deferred.

Source basis: `focused.py`, `engine.py`, `jobs.py`, `cli.py`,
`bridge/MacscopeFocus.java`, `bridge/MacscopeBridge.java`, and the Stage D plan.
This specification alone does not authorize implementation or persistent state.
