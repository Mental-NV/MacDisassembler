# Owned resource-first Calendar investigation

Stage C of the [scoped investigation plan](scoped-investigation-plan.md).
The implementation baseline is merged main
`68b29441e757eb19652ec05abcb120ac53166e69`, tree
`c16d31cdd4381dbe583dc3ef170c5892f5080b21` (PR #5).

This is a reproducible owned-fixture regression using existing public CLI
commands. It does not add an analysis mode, change trust/isolation policy,
replace the installed command, or enable a Linux worker. The earlier
`integration_calendar_workflow.py` rehearsal remains unchanged.

## The owned fixture

`fixture/calendar/ResourceFirstCalendar.m` and
`ResourceFirstCalendarWiring.xib` are independently authored fixture sources.
The compiled nib declares an `advancedRow` outlet, an `advancedToggle` outlet,
and the `changeAdvancedState:` action on `OwnedCalendarResourceController`.
The source's `awakeFromNib` requests `setHidden:YES` on the row. The action
requests the sender's state and writes a volatile configuration ivar only
when the returned state differs. A caller-supplied dispatch pointer remains
unresolved. No application or nib is loaded or executed by this regression.

A new fixture beside the original preserves the original Calendar rehearsal,
resource contract and runtime oracle without conflating them with this test.

## Resource-first sequence

Run from the repository root on macOS with existing Ghidra/JDK dependencies.
Choose an existing output parent and a new nonhidden child directory outside
Git. The harness sets umask 077 and creates a new private project per slice.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
MACSCOPE_GHIDRA="$GHIDRA" MACSCOPE_JAVA_HOME="$JDK" \
python3 tests/integration_resource_first_calendar.py \
  --output-dir "$OUTPUT_PARENT/owned-resource-first" --arch both
```

1. **Consult captures first.** An existing `context.json` triggers replay,
   not fresh compilation or another worker. An incomplete directory is
   preserved and reported; it is never silently rebuilt in place.
2. **Select the resource.** Compile the owned XIB and capture `resources list`,
   `resources nib`, and `resources strings` before importing code. Verify the
   action/outlet identities and directions against explicit ibtool output.
   ibtool represents an action owner-to-control; the nib represents its
   sender-to-receiver direction. The oracle normalizes this deliberately.
   A compiled `NSCustomView` row corresponds to ibtool's `IBNSCustomView`
   with `className=NSView`. Wiring is not a visibility or reachability proof.
3. **Resolve the declared receiver.** Import one separately built architecture
   without automatic analysis. Use explicit image and architecture selectors
   for filtered class discovery, the exact class-list fixup and selected
   `objc methods --class-slot`. Retain selectors and ivars from the same slice.
4. **Verify the entry.** The declared method implementation must equal Apple's
   `nm` and `dyld_info -objc` evidence. Validate its exact linker function-start
   extent before running `decompile --from-import --address ...`.
5. **Capture only the selected code.** Select load, state-change and indirect
   dispatch functions, each with explicit image/architecture. Preserve all
   partial results, raw warnings and residual gap evidence. The harness has
   no whole-image `analyze` path and checks that no active analysis exists.
6. **Corroborate the local effect.** Compare receipt bytes with public `bytes`
   output and the saved slice. Preserve Apple disassembly for each selected
   linker extent. The narrowly scoped test oracle described below connects
   instructions to exact same-slice selector and ivar evidence.
7. **Pin the handoff.** A lead manifest pins artifact, slice, imported Program,
   image and architecture identities. Capture the same exact selected receipts,
   the nib action's class/selector/slot, and the class pointer in `evidence`.
   The combined private JSON/HTML includes resource/source hashes, receipts,
   coverage at every step, facts, bounded inferences and unknowns.

Architecture failures are recorded independently and do not prevent trying
the other architecture. Any failure makes the overall command exit nonzero.
Logs, compiled resources, binaries, engine projects and recovered output are
private test artifacts, not repository deliverables.

## What the byte oracle establishes

`tests/resource_first_oracle.py` deliberately recognizes only the independently
reviewed instruction templates produced by this owned fixture. It is not a
general Objective-C analyzer and is not part of the packaged runtime. Changes
to compiler patterns fail closed rather than being accepted by mnemonic search.

On arm64 the proof follows self to the row load, the true argument in `w2`,
and a branch to the selector stub. The stub must load the verified `setHidden:`
selector reference into `x1` and dispatch through a strong `_objc_msgSend`
binding. The state method preserves self, requests `state` on the sender,
compares the return value with the declared configuration ivar, and has an
exact equality branch over the store.

On x86_64 the proof follows the same relationships through `rdi`, `rsi`,
`rdx`, `rbx` and `rax`; the selector and dispatch pointer are decoded from
RIP-relative instructions. The equality branch must skip the configuration
store exactly. Both proofs check contiguous instruction bytes, declared ivar
size/offset, selector relocation and string bytes, and ordinary strong binding.
No unique runtime implementation of either Objective-C message is asserted.

Negative controls alter the receiver, true argument, configuration offset,
comparison or branch, remove/insert instructions, provide unavailable or
wrong-class ivars, and change selector or binding evidence. They must fail.
A wrapper-like name or plausible pseudocode alone cannot satisfy the oracle.

## Offline replay

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
MACSCOPE_GHIDRA=/nonexistent-engine MACSCOPE_JAVA_HOME=/nonexistent-java \
python3 tests/integration_resource_first_calendar.py \
  --output-dir "$OUTPUT_PARENT/owned-resource-first" --arch both --replay
```

The original application path is temporarily absent during every replay.
Saved raw nib and strings bytes are hashed and reparsed without loading
objects. Saved metadata is regenerated from the imported slice. Query receipts
are resumed with unavailable engine/JDK paths, retaining instruction bytes,
pseudocode, origins and gaps. The byte oracle is rerun against the hash-verified
saved slice. Repeated evidence exports and normalized private JSON/HTML must
be byte-identical; receipt bytes and the job count must remain unchanged.

Immutable imported slices and Programs remain present. Offline replay is not
fresh analysis, and it is not reconstruction without source-byte evidence.
The report does not establish that the row can never appear, that a reachable
UI path exists, persistence, layout geometry, or any third-party app behavior.
There is no runtime oracle in this regression.

## Validation

The [validation record](resource-first-calendar-validation.md) distinguishes
source checks, live architecture results and deferred work. Stage D performance
measurements, Linux workers, installation and a selected-address batch command
remain separate work.
