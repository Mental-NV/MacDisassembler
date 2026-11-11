# Stage D: pinned lifecycle API assessment

Read-only source/API inspection of Ghidra 12.2 PUBLIC, build
2026-Oct-23 0157 GMT. This advances only the source-inspection prerequisite in
[the bounded batch proposal](bounded-focused-batch-proposal.md#11-separate-owned-fixture-feasibility-experiment).
No batch harness, product command, live isolation experiment, installation,
application execution or performance measurement was run. Existing single-entry
capture and saved replay remain the available workflow.

## Supported construction and release paths

`DomainFile.getReadOnlyDomainObject(consumer, version, monitor)` documents a new,
disassociated domain object. Read-only prohibits saving back; the object can be
modified in memory. `GhidraFileData` delegates to `ProgramContentHandler`, which
constructs a new DBHandle and ProgramDB and cleans up failed opens. Ordinary
`getDomainObject` may return an already-open object and is not an independence
proof. Use a unique consumer and fresh verified disposable database copy per
entry. Reject link resolution, unexpected upgrade and source identity changes.
Never save or save-as. Do not use `GhidraProject.createProject` on an existing
path: its implementation can delete a previous project at that location.

`DomainObjectAdapter.release` closes only after the last consumer releases.
ProgramDB and DomainObjectAdapterDB close managers and database resources.
Consumer lists, Program `isClosed()` and captured DBHandle `isClosed()` are useful
checks, but the closed flag is set before teardown finishes. Require normal return
from release plus independent closure checks under an external deadline. Object
inequality, rollback or successful deletion of a directory is insufficient.

AutoAnalysisManager has per-Program disposal hooks, but `isAnalyzing()` does not
prove an empty task queue and cancellation may return early for a non-cancellable
worker. Unexpected analysis activity fails the proposed experiment. It must not
be silently drained and then described as no-analysis isolation.

## Native decompiler release is the unresolved gate

DecompileProcessFactory constructs a new DecompileProcess; a fresh
DecompInterface is the right starting point. However:

- `DecompInterface.dispose` normally queues asynchronous disposal.
- `closeProgram` catches cleanup exceptions and requests process disposal.
- DecompileProcess marks itself disposed/not-ready before native cleanup.
- DecompilerDisposer uses a private background queue; its runtime cleanup calls
  `Process.destroy()`, closes streams and swallows exceptions.
- Cleanup performs no `waitFor`, `onExit` or `isAlive` termination verification.
  Its comments acknowledge possible blocking/deadlock.
- Public/protected APIs expose no native PID/process handle or await-termination
  method. A not-ready or disposed state is not proof of OS-process exit.

Therefore these Ghidra APIs alone do not establish that the previous native child
has terminated before the next entry begins. Fresh Program construction is
supported by source; live independent state, native cleanup and absence of leaked
children/locks remain unproved. Do not launch an A/B/A harness by treating dispose
as an acknowledgment, sleeping a fixed interval, or weakening the batch contract.

## Next bounded design question

Investigate a separately reviewed, supported ownership/termination fence outside
Ghidra's private fields. A recorded live ProcessHandle and bounded wait for that
exact process could establish its exit, but an instantaneous descendant snapshot
alone cannot establish complete child ownership or absence of unobserved restarts.
First inspect synchronous startup, retry/restart behavior and available process
identity observability. Any missing/ambiguous identity, unexpected child, cleanup
failure or unresolved ownership must fail closed before another entry begins.
Follow-up source inspection supports a restricted candidate: successful
`openProgram` synchronously initializes and starts the native executable via
`Runtime.exec`; a new interface has no launch retry loop. However,
`verifyProcess` can recreate a not-ready process before a decompile call. The
experiment would have to serialize one open and one call, retain the same live
child identity before and after that call, reject replacement/early death, and
prevent reset/retry/reopen or queued future work. A bounded search of installed
native source found no process-creation calls; that is supporting source evidence,
not proof of exhaustive process history for the installed binary/dependencies.

Independent design review supports investigating an exact-handle fence under
those restrictions: require a clean baseline, one direct child with available
PID/start/parent/executable identity, preserve dependency hashes, await the retained
handle under an external deadline and reject unexpected descendants or ambiguity.
Snapshots can miss transient/reparented children, and executable path alone does
not pin a binary. Most importantly, native process exit does not acknowledge
completion of the asynchronous Java disposer queue, stream cleanup, Program/DB
release or analysis teardown. A separate supported cleanup fence is still
unresolved. This is design-review progress, not approval to launch a batch.

No reflection workaround, native patch or sandbox change is approved by this
assessment. The narrower worker profile and supervisor-only evidence boundary
also need independent review before any live experiment.

If a sound design is demonstrated, the next non-shipping owned-fixture experiment
is fresh singles versus A/B/A and B/A/B, with B deliberately altering symbols,
types and focused preparations to expose contamination. Compare full normalized
evidence, retain pristine hashes, and test failures and cleanup before timing.
Do not infer batch speedups from the earlier single-entry benchmark.

## Evidence pins and source references

Installed source/API inspection, not a new build or runtime test:

| Archive / binary | SHA256 |
| --- | --- |
| Decompiler-src.zip | `06ddf4741bc8bfaf457f99d7dae490b298d1b9ded513a24d2bd4f6c2ad37d913` |
| Decompiler.jar | `489858a046db5ef16be224eee20d290afbf62da690ad115606d4627e749a5412` |
| Project-src.zip | `eda35e5e6c946691ae674a2690896f2ce8c72f5feca37177729982d21e4fa8f4` |
| SoftwareModeling-src.zip | `c73f0e5f7223d46b894a0bec4cb0866b229206423cdeb1393e3cfcc059424ae8` |

Relevant installed source locations: DomainFile lines199–252;
GhidraFileData726–780; ProgramContentHandler116–165;
DomainObjectAdapter112–123; DomainObjectAdapterDB189–191,605–635;
ProgramDB2354–2370; DBHandle733–769; DecompileProcessFactory42–45;
DecompInterface424–444,863–876; DecompileProcess118–127,515 onward;
DecompilerDisposer37–70,98–125. Line references describe this pinned source only.

Status: API construction **supported**; native termination fence **unresolved**;
A/B/A independence, failure injection, ACK fencing, live sandbox, durability and
performance **unrun**. No proprietary application evidence is part of this record.
