# Bounded focused batch proposal

**Revised review-only contract. No implementation or available batch command.**
This revision replaces the lifecycle/publication assumptions in the original
Stage D proposal. Independent contract review comes first, then a separate
owned-fixture feasibility experiment. Neither step authorizes a product command.
The [Stage D measurements](focused-import-benchmark.md) motivate investigation,
not a speedup claim: the tiny warm fixture and 20 fixed-order rounds do not
predict batch performance, large applications, or the 16 GiB reference host.

## 1. Purpose, compatibility, and gates

Explore amortizing JVM/headless startup across a small explicit selection.
One attempt has one project, image, ordinary arm64 or x86_64 architecture,
verified saved no-analysis import, short-lived worker, and sequential entries.
Reuse the JVM only, never a mutable Program or native decompiler instance.

No persistent service, cross-invocation engine cache, whole-image analysis,
implicit callees, discovery expansion, type hints, analyzed snapshots, automatic
installation, Linux engine enablement, or weaker trust/isolation policy.
Existing single-address commands, receipts, v1/v2 evidence, job behavior, and
exports remain unchanged. Do not implicitly batch existing commands. The batch
index is not an analysis snapshot. Export/handoff must explicitly support the
new wrapper or reject it. Saved replay remains preferable when it answers the
question, but is not fresh analysis.

Three gates are distinct:

1. **Contract review:** resolve lifecycle, ownership, hashes, resource accounting,
   and crash semantics below. Passing review permits only the experiment in §11.
2. **Feasibility:** prove independent Ghidra Programs/native processes and the
   narrowed worker boundary on owned fixtures. Any failed prerequisite stops the
   batch approach; do not compensate by relaxing scope or isolation.
3. **Product design/release:** separately review implementation, public names,
   versioned wire schemas, migrations, help, exit behavior, and all release tests.
   A successful experiment is not this gate and is not a shipping recommendation.

## 2. Deferred interface and bounded selection

The previously sketched `decompile-batch capture/replay/resume` names and flags
remain **unimplemented and unfrozen**. No CLI example here is an available
command. The feasibility harness must live outside `src/`, must not register
commands or alter installed CLI files, and may accept only explicitly supplied
project-owned fixtures. It cannot launch on an arbitrary application.

A future request uses `macscope-focused-batch-selection/1`, with only `schema`
and `entries`. Entries are 1–16 canonical lowercase unslid hex addresses
(`0x0` or `0x` followed by a nonzero hex digit and up to 15 more digits), sorted
numerically with no duplicates. Require explicit image and architecture.
Reject unknown/duplicate JSON keys, non-finite values, invalid UTF-8, excessive
nesting, symlinks/nonregular files, unsupported flags, mixed identities, and
out-of-range addresses. Validate the entire request before launch. Do not skip
invalid entries. Internal order-isolation experiments may deliberately use
repetitions/permutations; they are not accepted production selections.

Fixed initial caps, checked before allocation/copy/publication as applicable:

| Resource | Cap and accounting |
| --- | --- |
| Selection | 16 KiB raw bytes; 1–16 entries |
| Exact linker extents | 8,192 bytes each; 65,536 bytes total; charge full extents |
| Tail-call proof | Existing 128 KiB and 64-candidate per-entry caps; 2 MiB total proof bytes across at most 16 entries |
| Canonical batch request | 4 MiB including all focused requests and proofs |
| Worker candidate | 8 MiB total per entry, including evidence and diagnostic payload |
| Committed entry bundle | 8 MiB total canonical files per entry; 64 MiB cumulative in a batch |
| Derived index | 1 MiB; references receipts, does not duplicate their bodies |
| Control message | 4 KiB; bounded framing, one outstanding entry, no unbounded queue |
| Logs | Existing per-stream limits, also 16 MiB aggregate per attempt including rotated files |
| Attempt history | At most 16 explicit attempts per batch, no automatic retry loop |
| Live workspace storage | Existing 512 MiB sampled check, including Program copies, candidates, staging, logs, and control files |

Preserve every tighter existing bridge, nesting, instructions, proof, or log
limit. A single live disposable Program copy is allowed, not 16 preopened
copies. Include retained prior attempts in the batch storage scan; committed
bytes are additionally charged to the 64 MiB cap. Bound scans by the 16 attempts
and 16 commits, plus the existing project history scan limit. No caller option
raises these caps initially. Exact serialized byte limits are hard application
checks; heap and sampled storage are not hard RSS or filesystem quotas.
One CPU and `jobs=1` remain unchanged. Unsupported process-memory caps fail
explicitly. Oversized output is operational failure, not a valid truncated
receipt. Check budgets before work as well as while it runs.

## 3. Authority and filesystem boundary

**Only the supervisor publishes evidence. Worker output is untrusted staging.**
The existing runtime permits worker writes throughout its current job root.
It cannot safely host authoritative receipts, indexes, leases, or completion
records there while that worker is alive. File mode 0400, a read-only Ghidra
open, or calling a path "immutable" does not establish this boundary.

Proposed logical layout (names are internal, not a migration commitment):

- `jobs/<attempt>/worker/`: the worker's sole writable subtree, including its
  home/tmp, disposable Program, logs, and fixed candidate slot.
- `batches/<batch>/`: supervisor-only request, attempt/ownership records,
  commit staging, committed entry directories, and derived index generations.
- Supervisor leases, launch gate, cancellation fence, and control endpoints
  remain outside the worker write subtree. The worker receives only the bounded
  read/write IPC ends it needs, no supervisor directory FD or writable control FD.

Require a fresh reviewed sandbox profile narrowing the existing job write root
to `worker/`, with no broader reads, executions, privileges, network access, or
writable parent. Pin its digest. Deny worker creation, modification, deletion,
rename, and link-based replacement of committed records and their ancestors.
Copied request inputs in `worker/` are never authoritative; the supervisor uses
its own pinned request. Dependency roots and the pristine import remain outside
worker writes. No worker-supplied path is accepted as an output destination.
The current profile/launch/receipt validators cannot simply be reused unchanged.

The supervisor copies from a fixed candidate slot through checked directory FDs
and regular no-follow files, enforcing size while reading. It creates fresh
supervisor-owned inodes, then validates those copied bytes; it never publishes a
worker inode by rename or hard link. Reject aliases, unexpected files, link
counts, traversal, inconsistent sizes/digests, and concurrent replacement.
Candidate races can fail an entry but cannot rewrite an earlier commit.

"Immutable" means write-once protocol plus denial to the sandboxed worker and
all its descendants. It is not protection against the account owner editing
the project or a hostile kernel. Hashes detect inconsistency; they are not a
signature or proof against a person able to rewrite all trusted records.
This remains experimental explicitly trusted owned-input execution, not a
hostile-input sandbox.

## 4. Independent Ghidra state is a prerequisite

Every entry retains the focused contract: complete linker start/next-boundary
proof, unique executable file-backed mapping, correct architecture/alignment
and data-in-code handling, pinned slice/extent bytes, and pristine saved Program
identity. Preserve raw CFG, tail-call overrides, BRK, native-scope, and unresolved
flow checks. More selected entries must not expand an entry's scope or assert
a unique runtime dispatch target. Never save changes or alter active analysis.

For each entry, make a new verified disposable database copy from a
supervisor-held pristine import, open a distinct Program with its own consumer,
construct a fresh `DecompInterface`/native process, apply only that entry's
preparation, extract bounded evidence, and dispose/release everything. No
functions, signatures, references, flow overrides, symbol/type edits, analysis
queues, Java static state, or native caches may affect the next entry.

The supported Ghidra 12.2 API/lifecycle for this is **not yet proven**. The
experiment must identify actual API calls and ownership/transaction rules,
show that closing releases database handles/locks and native descendants, and
prove that reopening an identical path does not return a cached mutated Program.
It may use fresh per-entry paths; deleting a path alone is not a reset proof.
`MacscopeFocus.java` currently commits preparation changes in its disposable
Program for a later script. Running it repeatedly on the same Program is
invalid. `flushCache()`, rollback alone, read-only open, matching pseudocode
alone, or JVM object inequality alone is insufficient.

A cleanup exception, leaked native child, retained database handle, unknown
mutation, unexpected autoanalysis, or failed reset probe makes the attempt
unhealthy. Stop and discard its uncommitted result. Do not ACK another entry.
The independent-state gate deliberately leaves opening costs unamortized.

## 5. ACK-gated state machine

The supervisor owns the ordered request and the worker's permitted ordinal.
Messages carry protocol version, batch/attempt IDs, a fresh attempt nonce,
ordinal, focused-request digest, and monotonic sequence number. Unexpected,
repeated, out-of-order, oversized, or stale messages fail the attempt. IPC EOF
means stop, never permission to continue. The nonce is local correlation, not
a reusable authentication secret and not part of a portable receipt.

1. **READY:** after pinned startup checks, the worker waits without opening an
   entry. The independent watchdog is already running.
2. **BEGIN(i):** the supervisor checks remaining budgets/cancellation, records the
   permitted ordinal, and starts its entry deadline **before** requesting work.
3. **RUNNING(i):** one Program and one decompiler. No speculative next entry.
4. **CANDIDATE(i):** the worker serializes and closes its fixed output slot,
   disposes/releases the decompiler and Program, waits for their owned native
   descendants to exit, and reports the candidate plus teardown result. It must
   then block. Teardown is inside the entry deadline, not a best-effort postlude.
5. **VALIDATING(i):** the supervisor copies, validates, classifies, hashes, and
   stages a commit. The watchdog remains active; worker waits in this state.
6. **COMMITTED(i):** only after §8's durable commit succeeds may the supervisor
   send **ACK_COMMITTED(i, commit_digest)**. The worker may discard its slot but
   still waits for a separate BEGIN(i+1). Lost ACK cannot authorize more work.
7. **STOP:** after the last entry or any failure/cancellation/deadline. Confirm
   full owned-process-tree exit and finalize attempt status before releasing
   leases. A final entry commit does not by itself mean the attempt succeeded.

The worker never assigns `complete`, accepts its own receipt, advances itself,
or writes an authoritative completion marker. Supervisor crash, cancellation,
missing ACK, watchdog death, or bad IPC must prevent further work. An uncertain
commit/ACK outcome is resolved from committed records, never by assuming failure
and repeating publication. Process-local timers cannot replace the watchdog.

## 6. Operational outcome versus evidence completeness

Store these independently per entry:

- `operation`: `not_started`, `running`, `succeeded`, `failed`, `timeout`, or
  `cancelled` (running is a live diagnostic, never a committed receipt).
- `evidence`: `complete`, `partial`, or `none`.
- Stable machine reason codes, unchanged raw warnings/gaps and native status,
  producer identity, and a receipt reference only when committed.

Only `operation=succeeded` can have a committed evidence receipt. `partial`
evidence requires a reviewed allowlist of semantic limitations, for example
unresolved indirect flow, deliberately bounded proof coverage, or unsupported
semantics with intact extraction. A thunk/external `not_requested` native status
requires explicit focused-contract eligibility and a supported reason; it is
not a blanket success. Preserve every warning and limitation, not just an
aggregate partial flag.

Native timeout, cancellation, failed-to-start/openProgram, null native result,
exception, worker crash, malformed/missing output, output/storage cap, unexpected
truncation, failed validation, identity mismatch, or unsafe teardown is
**operational failure**, even if the existing bridge envelope says `partial` or
Java exits zero. Unknown statuses/reasons fail closed. Derive classification
from native/function/facet statuses and lifecycle checks, not envelope status
alone. The new adapter must enumerate mappings and test each before integration.
Never rewrite failed native work into a "semantic partial" to keep batching.
Diagnostics may be retained separately but are not a function receipt.

Commit valid complete/semantic-partial entries and continue. Stop at the first
operational failure. Earlier independent commits survive; later entries remain
`not_started` with the stopping reason. A failure in final teardown preserves
commits but fails the attempt. Counts separately report committed evidence,
semantic partials, operational failures, and not-started work.

Proposed batch exit precedence, independent of preserved individual reasons:
explicit user cancellation 130; otherwise deadline/resource limit 7; otherwise
lifecycle/ownership/integrity/publication failure 8; otherwise worker/native
failure 5; otherwise any semantic partial 6; otherwise 0. Zero also requires
all requested entries committed and confirmed worker teardown. Preflight usage,
input, or dependency errors retain existing 2/3/4 categories. A later discovered
integrity problem is still reported even when another category wins precedence.
Final numeric mapping is gated with the public interface, not silently imposed
on existing commands. Include batch/attempt IDs whenever recoverable records exist.

## 7. Watchdog, deadlines, and cancellation

Proposed budgets (exact options remain deferred):

| Budget | Default | Allowed range | Interval |
| --- | ---: | ---: | --- |
| Startup | 60 s | 1–300 s | Launch to READY |
| Worker wall | 300 s | 1–3600 s | Launch through confirmed process-tree teardown, including ACK waits |
| Entry wall | 30 s | 1–120 s | BEGIN through validation, durable commit, and ACK, including entry teardown |
| Native call | 15 s | 1–120 s | One native call, additionally bounded by remaining entry budget |
| Command wall | 360 s | 1–3600 s | Before source verification through final publication and teardown |

Require startup ≤ worker ≤ command and native ≤ entry. Use monotonic clocks and
the earliest deadline; no budget resets during resume within an attempt,
validation, copying, waiting for locks, or output serialization. A new explicitly
requested attempt gets new clocks but the identical request budget values.
Heap remains 1024 MiB default, range 256–4096 MiB, not a hard process-memory cap.

A separate watchdog must stay schedulable while the coordinator, validator,
publication fsync, or Java/native call blocks. It observes command, worker,
entry, cancellation, log/storage budgets, and coordinator liveness. Blocking
validation/publication helpers must be included in owned-process bookkeeping.
Do not rely on a synchronous supervisor polling loop that stops during
validation or a watchdog thread blocked by the same runtime lock. Watchdog
failure closes the launch/BEGIN gate and triggers fail-closed termination.

On expiry/cancellation, fence further BEGIN/ACK and publication permissions,
then terminate the owned worker/helper tree using the existing ownership-token,
boot/process-identity, launch-gate, descendant, and PID-reuse-safe protocol.
Keep the watchdog and ownership lease until exit is confirmed, including final
teardown and publication. A stuck/unknown process means `ownership_uncertain`,
blocks resume, and cannot be called safely stopped. Never signal by stale PID
alone. Bounded TERM/KILL cleanup may extend beyond the command work deadline.
Noninterruptible kernel/filesystem operations can delay return; this contract
is not an absolute kernel-level deadline or a hard storage quota.

Immediately before commit linearization, the publisher must recheck the active
attempt fence and all deadlines under the publication lock. Cancellation before
this check forbids publication. If cancellation/crash races an already-started
rename/fsync, the outcome is explicitly uncertain until §8 recovery; never ACK
it or start another entry. A valid commit found during recovery remains an
entry result, with the cancelled/timed-out attempt preserved as such. Do not
claim that a filesystem operation can be revoked after it linearizes.

Measure command, startup/readiness, database copy/open, `openProgram`, native
call, extraction, teardown, validation, commit/fsync, and ACK waits separately.
Absent instruments are null/unmeasured; nested intervals are not summed.
Timings stay outside normalized evidence and cannot justify a speedup alone.

## 8. One authoritative durable commit and recovery

The authoritative unit is one **entry commit directory**, containing the full
canonical receipt wrapper and completion record. A completion record binds all
receipt file hashes/lengths and the producer/request identities in §9. No index,
worker marker, candidate, or attempt terminal status independently commits an
entry. There is no receipt/index two-phase transaction to repair by guesswork.

Durability starts with the prerequisite closure, not the entry rename. Before
releasing the worker launch gate, durably establish the original request, saved
import/image identity records, exact saved slice, and immutable attempt-start
record including the verified launch identity. Flush prerequisite files and
their containing directories, and persist every newly created ancestor entry
up to an already durable project root. Do not infer this from a previous atomic
write or an existing pathname. A recorded dependency is usable only after its
durability barrier succeeds. The live Program database is not a replay
dependency, but its pinned identity record is. Hold launch on any failed or
uncertain barrier; no entry commit may outlive missing mandatory provenance.

While holding the publication lock and valid attempt lease:

1. Copy to a new exclusive directory in supervisor-only staging on the same
   filesystem as commits. Validate the copied bounded bytes and all identities.
   Assemble the immutable wrapper/completion record from supervisor knowledge.
2. Write each canonical file to a fresh no-follow regular inode. Flush every
   file with fsync, then fsync the staging directory. Failure stops publication.
3. Recheck budgets/fence, then atomically rename the whole directory to
   `commits/<ordinal>` with no overwrite semantics. A destination already
   existing is a conflict to validate, never permission to replace it.
4. Fsync the destination parent directory (and changed source parent when
   distinct). Only after these barriers succeed is the commit acknowledged as
   durable. Rename is the visibility/linearization point; directory fsync is
   the durable-success barrier. Use supported local-filesystem primitives and
   test them on the target macOS filesystem. Unsupported barriers fail closed.
5. Generate a supervisor-only immutable index generation from committed
   directories. Atomically replace only the small index pointer/cache. This is
   derived convenience state, not a second commit and not authority for resume.
   Index-update failure cannot undo an entry commit and stops the attempt.

Hold the exclusive publication lock through the durability barrier, so a live
replay cannot observe a rename before its flush completes. If publication dies
or reports uncertain flush success, mark/fence that attempt as unrecovered;
replay must refuse its unacknowledged commit slots until exclusive recovery has
validated and flushed them. Process exit releasing a lock is not a durability
certificate. A durable supervisor acknowledgment record outside the worker
tree may cache that barrier result; if absent after crash, recover rather than
infer success. Such a record is a recovery optimization, not a second commit:
its absence cannot erase a valid entry directory or allow recapture over it.

Do not promise physical power-loss durability beyond filesystem/device flush
guarantees. Document whether macOS full-sync is used and the tested guarantee;
ordinary fsync does not establish that every storage controller honored power
loss. Cross-device rename, network filesystems, or uncertain durability are not
silently downgraded to copy-and-delete or non-durable success.

Recovery, under exclusive mutation/publication leases and verified old-worker
termination, scans only the bounded exact commit slots. It revalidates the
entire directory, canonical file bytes, identities, hashes, and lengths. A
fully valid destination left after crash is adopted once, with recovery flushes
completed before a new ACK/use; missing destination is uncommitted. A malformed,
conflicting, aliased, or incomplete destination is an integrity blocker, not
silently skipped. Staging directories are never evidence and never auto-promoted.
Preserve/quarantine diagnostics outside the evidence namespace within limits.
A missing/stale derived index is rebuilt; a contradictory authoritative commit
is not repaired by trusting the index. No duplicate receipt per ordinal.

Crash injection is required around prerequisite initialization and every newly
created ancestor, then before/after each copy, file fsync, directory fsync,
rename, parent fsync, index publication, ACK, and final attempt record. Test
ENOSPC, I/O errors, unsupported fsync/rename, stale index, and crash after commit
but before ACK. Recoverable committed evidence survives a failed parent attempt.

## 9. Exact identities and replay contract

Use versioned batch request, entry receipt, completion, attempt, and result
schemas separate from existing standalone query receipts. Do not disguise a
batch entry as a completed standalone job. A committed entry does not require
a completed parent attempt, but it must reference a valid immutable producing
attempt-start record and the supervisor-created commit.

Canonical JSON is the existing `storage.canonical` contract: UTF-8 bytes,
ASCII-escaped strings, sorted object keys, separators `,` and `:`, no trailing
newline, no NaN/Infinity, unique keys, and existing depth bounds. Identity objects
use integers/strings/booleans/null only, no floating point or platform paths.
Addresses and SHA-256 digests have canonical lowercase spelling. Re-encode and
require byte equality for committed canonical files. Hash algorithms/field sets
are pinned by schema; no arbitrary deletion of provenance or warning fields.

- **Request digest:** SHA-256 of canonical `macscope-focused-batch-request/1`
  payload without its one `request_sha256` field. Include schema, project/image
  IDs, architecture, artifact and slice digests, immutable import-record digest,
  Program-tree digest, `source_analysis_id:null`, ordered focused requests and
  their complete proofs, bridge/runtime/dependency/policy/schema versions and
  hashes, effective limits/options, and intended sandbox policy identity.
  Include auxiliary JDK/runtime libraries and native decompiler, not just version
  strings. Machine-local executable paths/attempt times are separate diagnostics.
- **Focused-request digest:** SHA-256 of the complete canonical focused-request
  payload in the ordered request, with exactly its own digest field omitted if
  that version defines one. Bind original ordinal and address in the receipt;
  A/B/A experiments do not create valid duplicate production ordinals.
- **Evidence digest:** SHA-256 of canonical evidence payload. Preserve all
  function/envelope fields, raw warnings, gaps, scope proofs, and semantic partial
  status. A versioned explicit normalization allowlist may remove only invocation
  labels, timing, job IDs, and reuse markers for comparison; this normalized
  digest is additional and never replaces exact saved-byte integrity hashes.
- **Receipt digest:** SHA-256 of exact canonical receipt bytes, including schema,
  original batch ID, producer attempt ID, request/focused-request digests,
  ordinal/address, evidence payload/digest, original `capture_kind:fresh`, and
  import/dependency/validator identities. The receipt contains no self-digest or
  completion-record digest, avoiding circular hashes.
- **Completion/commit digest:** SHA-256 of canonical supervisor completion record,
  which binds schema, original batch/attempt/ordinal/address/request digests,
  immutable attempt-start hash, `operation:succeeded`, evidence classification,
  receipt hash and byte length. Its own digest is external, never a self-reference.
  The derived index references this digest plus receipt digest.

Replay is engine-free and never silently recaptures. Required saved data: the
batch request; immutable import/image identity records; the saved exact slice
needed to reselect extents and validate instruction/proof bytes; producing
attempt-start records; complete entry commit directories. Verify all required
hashes, addresses/ordinals, schema/policy support, lengths, scope, and references.
The original application, Program database tree, Ghidra, and JDK need not exist.
Their historical identities remain in the receipt; unavailable executable bytes
are not falsely reverified. Never require the current installed runtime to match
for engine-free replay of a supported historical schema. Missing saved slice or
identity records, unsupported policy, tampering, or invalid commit fails explicitly.

Replay may read a committed snapshot during an active attempt by taking a short
shared publication lock, copying/validating its immutable records, and releasing
the lock. It reports snapshot completeness, not live-batch success. It does not
repair storage, take an engine lease, write receipts, or relabel original fresh
provenance. `capture_kind:saved_replay` belongs only to the current invocation's
index/report; unchanged saved receipts remain fresh-capture records.

## 10. Leases, resume, and concurrent operations

All future batch capture/resume launches must use the existing project engine
writer fence plus a new exclusive batch mutation lease, even though their input
is a no-analysis import. Lock order is project writer, batch mutation, then short
publication lock. Hold the first two through worker/validator teardown and final
attempt publication. Replay takes only the shared publication lock; cancellation
uses the authenticated attempt control channel/fence without waiting on a long
writer lock. No mutation operation reverses this order.

Fail closed on lock conflict; do not steal a lock by deleting/replacing its
pathname. Use no-follow regular persistent lock inodes, nonblocking acquisition,
private directory validation, launch ownership tokens, boot ID, process start
identity, and the existing restart fence. Lease expiry or absent PID alone does
not prove termination. A missing owner after reboot may be resolved only by the
existing verified reboot/process-history logic. Concurrent resume, capture,
import repair, analysis, and cleanup must respect the same project writer fence.
The new batch paths must be reserved against caller-created output aliases.

Resume is an explicitly requested new attempt, with new IDs/nonces/leases and
recorded original-batch ancestry. Acquire locks first; reread all records;
verify every earlier attempt and descendant stopped; recover uncertain commits;
then revalidate every reused receipt. Require explicit trusted-owned-input
consent on **each** engine-launching attempt, never from saved state.

Fresh continuation requires exact current source/slice/import Program-tree,
architecture, runtime/bridge/native and auxiliary dependencies, policy/schema,
proofs, sandbox identity, and effective options/limit equality with the original
request. Changed identities require a new batch. Old runtime paths may relocate
only if all pinned content and sandbox semantics remain identical and the
reviewed identity rules explicitly permit it; do not ignore a changed sandbox.

Skip only valid committed entries, including semantic partials. Retry the first
uncommitted entry from pristine state and continue in original order. Never
resume Java/native state. Reusing a committed partial preserves it; recapturing
it is a new batch/request. No hidden retries. Refuse after 16 attempts or if
history/storage caps are exhausted; do not delete prior evidence to make room.
Keep old failures and receipts unchanged and label mixed fresh/replay provenance
in the new result. An all-committed resume needs no engine and must be reported
as replay/finalization, not a fresh attempt with fabricated work.

## 11. Separate owned-fixture feasibility experiment

After independent contract review, prepare a separate, non-shipping harness and
small checked-in owned fixture sources. No public command, installation,
arbitrary-app capture, Linux engine execution, persistent worker, product schema
change, or modification of the existing evidence/sandbox policy is included.
A new narrower experimental worker profile is allowed only if independently
reviewed and proven no more permissive; otherwise stop the live experiment.
Keep runtime and source pins, all samples/failures, and a reproducible report.

First perform API/source inspection against pinned Ghidra 12.2 to identify the
supported independent-Program lifecycle. Then, on an authorized macOS executor
with the existing pinned dependencies and trust authorization:

1. Capture fresh single-entry baselines for two owned entries A and B. Give B
   deliberate adjacent caller/callee, tail-override, and conflicting symbol/type
   preparations that would reveal reused mutable state. Preserve an unchanged
   pristine import and active-analysis identity before/after every sequence.
2. In one JVM run A/B/A, B/A/B, reversed order, and repeated A. Use a fresh Program
   and decompiler/native child per entry; record identities and verified release.
   Compare the full normalized evidence to independent fresh singles, not only C
   text. Assert preparation changes never appear in the next Program and no
   unexpected analysis queues, database handles, locks, or native children remain.
3. Inject semantic partials and separately operational timeout/exception/open
   failure, candidate corruption, cleanup failure, and missing ACK. Valid semantic
   partials may continue; every operational failure prevents the next BEGIN.
4. Probe worker attempts to overwrite/delete/rename/link the committed receipt,
   index, request, attempt and lease files, and their parents while the worker is
   alive. Confirm denial with unchanged bytes and existing read/exec/network
   restrictions. This is stronger than checking file permissions after exit.
5. Run engine-free protocol/crash/lease tests for §§5–10, including watchdog
   liveness during blocked validation/publication/teardown and stale process IDs.
   Do not confuse mocked tests with live macOS isolation or durability validation.

Report each gate as passed, failed, or unrun. If independent Program creation,
release, ACK fencing, or supervisor-only evidence cannot be demonstrated, stop
batch prototyping and retain single-address captures plus replay. Useful
findings can still be documented without a product implementation.

Only after correctness and isolation pass, compare fresh singles, fresh batch,
and saved replay separately on the D1 owned workload. Use at least 20 full rounds
before p95, retain failures and all pins, and do not discard unsuccessful runs.
Report warm/cold cache conditions, order, database/native-open/commit timings,
RSS/CPU if actually measured, and host limits. No broad speedup/release gate is
inferred from the original 22.894/23.649 s fresh and 0.770/0.781 s replay p95s.

## 12. Product acceptance still deferred

Before product integration, require dual-architecture parity; selection limits
and one-over tests; duplicate/interior/missing-boundary and malformed mapping
refusal; denied trust; exact identity change refusal; all operational/semantic
classifications; owned descendant termination; every deadline/cancellation
boundary; filesystem crash matrix; two concurrent resumes; import-repair/analysis
conflicts; offline replay and raw warning preservation; unchanged original
single-query behavior; deterministic JSON/HTML; package and complete relevant
unit, receipt, lifecycle, cancellation, isolation, and export checks.

This document changes no runtime. Current evidence establishes only that launch
cost warrants a bounded experiment. Ghidra independence, live narrowed sandbox,
durable publication, protocol implementation, performance, public interface,
and release acceptance remain unrun prerequisites until explicitly measured.

Source basis: `focused.py`, `engine.py`, `jobs.py`, `storage.py`, `cli.py`,
`bridge/MacscopeFocus.java`, `bridge/MacscopeBridge.java`, and Stage D benchmark.
