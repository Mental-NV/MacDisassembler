# Owned Swift conditional value/dispatch assessment

Assessment only. Previous owned Objective-C loop output was useful; private
saved-receipt navigation left value-update and indirect-call meaning unresolved.
Do not invent a decoder improvement or treat conditional static linkage as UI
parity. Freeze the independently authored OwnedValueDispatch.swift source before
capture. Compile an ARM64 optimized dynamic library and independent assembly on
Mac with pinned Swift/compiler versions and command flags; do not execute it.
No source/type hints, whole-image analysis, signature injection or output rewriting.

Select exactly ownedApplyValue, ownedUpdateAndSave and OwnedCountingSink.save by
compiler symbol/entry and linker extent. Preserve compiler-generated enum/tag,
Swift calling convention, existential dispatch and guard code as emitted; do not
simplify optimization after seeing output. Other bodies are not implicitly selected.
Record source/slice hashes, compiler assembly, exact method entries/extents, CLI
and bridge pins, raw output and receipts. Native capture completion, envelope
coverage and semantic agreement are separate results.

Source domains: valid uniquely borrowed record, conforming normally returning
sink and valid object lifetimes. Input may be nil or any Int64. Nil, negative or
unchanged proposals return false without record mutation/save. Accepted proposals
store the value and increment UInt64 revision modulo 2^64, return true and dispatch
one save on normal return. The concrete sink stores value and increments its
counter modulo 2^64. The generic existential caller cannot establish a concrete
runtime sink, purity, durable storage or UI behavior. Unknown sink effects and
trapping/nonreturning or otherwise nonconforming behavior must not become source-equivalence claims.
Include nil, negative/minimum, zero, unchanged, maximum, revision/counter wrap and
the concrete sink body and unresolved existential-call case in source/assembly reasoning.
These are distinct selected bodies, not two caller controls or a proved dispatch link. No runtime test claims.

An independent reader gets only captured code/instructions/metadata, not source or
expected answers. Record correct/incorrect/unknown, then reconcile against source
and emitted assembly, explicitly naming ABI assumptions. Source/compiler agreement
is not executed equivalence. A real gap must receive a bounded independently
reviewed reproducer before product code changes; a correct/inconclusive result is
acceptable. If native access is blocked, report it rather than synthesizing output.
No user app execution, system CLI install, Taskovsky restart or private artifacts.

## Actual static capture and independent reconciliation

Frozen source SHA256:
`d9c5740cc8e15d0028be9f74a1b42cf9668bbec2e5736880a199581ff2bfead1`.
Apple Swift 6.4 (swiftlang-6.4.0.34.1, clang-2100.3.34.1),
`-target arm64-apple-macos14 -O -emit-library -module-name OwnedValueDispatch`.
A separate `-emit-assembly` output and Apple llvm-objdump/linker-start listing
serve as static oracles. The binary was not executed.

The isolated PR57-equivalent native CLI with bridge1.15.0 and Ghidra12.2 imported
without whole-image analysis. Its bridge SHA256 was
`57d37fa1624103fb714f1ded8d4c72272b2b3ceaf0eca69efa91268182985aed`.
All three exact selected extents completed: apply `[0xbec,0xc2c)`, save
`[0xb58,0xbb4)`, dispatch `[0xc2c,0xc98)`. Native completeness is extent coverage,
not Swift ABI recovery, argument completeness or semantic equivalence. Subsequent
PR58/60 presentation changes were not part of that native runtime; installed
current-runtime offline replay is a separate check.

An independent reader saw only the three raw query JSON files (including recorded
instructions), not source or expected answers. It correctly recovered nil/negative rejection
before dereference, equality rejection after reading the record, record update/wrapping increment, the
concrete context stores and conditional indirect-call path. A second independent
reviewer compared source, compiler assembly, native disassembly and pseudocode.
Both identified two reproducible ABI-information omissions:

1. Dispatch's direct call at `0xc48` reaches selected apply. Entry x0/x1/x2 remain
   unchanged through the prologue, but pseudocode prints a no-argument call.
   Separate callee pseudocode consumes three machine-level inputs. This does not
   imply source parameter count, a recovered aggregate type or universal ABI.
2. After the projection-helper call at `0xc60`, its returned x0 moves through x2
   into x20 before BLR at `0xc7c`. Pseudocode makes the helper result appear unused
   and omits that implicit context flow. The helper and indirect destination are
   not selected bodies; no runtime target or concrete sink relationship is proved.

The raw machine-level guards and arithmetic agree within the source domain.
Optional-tag interpretation depends on conforming Swift ABI values; arbitrary
byte values are not additional source enum cases. Inferred signed `long` arithmetic
is not proof of source UInt64 behavior; the emitted unchecked ADD wraps. Paired
stores are not atomicity evidence. Concrete save's runtime access calls may fail
or not return; a prior store does not imply rollback. Symbol names and normal
return do not establish durable storage, live UI behavior or runtime target identity.

Three actual receipts replayed twice identically with engine/JDK paths unavailable
on Mac. Portable and original project hashes remained unchanged during replay.
The owned evidence archive includes source/assembly, raw results and exact receipt
hashes, but no Ghidra databases. Archive SHA256:
`3662479b997c5e5002ee87454f65d7c4d87417add983c0bbed252e3560c24361`.
The current isolated PR60-equivalent wheel also replayed all three receipts twice
in the cloud, exit0, with byte-identical repeated output and all portable file
hashes unchanged. This is saved-native evidence replay, not a fresh PR60 native
capture or native full-suite validation.
No system CLI installation, Taskovsky session, private application publication or
fresh full Mac regression suite is claimed.

## Historical mechanism proposal, superseded by PR62/63

The proposal below was implemented in the separately versioned
[focused register relationships](focused-register-relations.md) view. Its v1
keeps branch barriers; opt-in v2 records conditional bit-test fallthrough. The
linked document records actual checks and limits. Raw Ghidra pseudocode and
prototypes remain unchanged; no runtime target is recovered. Further priorities
follow the [consumer comparison and decision gate](scoped-investigation-followup-plan.md).
The paragraphs below retain the original design rationale, not pending work.

Preserve raw pseudocode. Prefer a separately provenance-bound machine-register
relationship view to automatically injecting signatures. Existing callee-parameter
recovery uses analyzed Programs, not these import-focused receipts; existing
Objective-C send origins deliberately stop at prologues/calls and are not a
Swift call-context solution. Evaluate reuse of existing byte-proven callback
machinery before adding a new decoder. Any view must retain normal-return/path
conditions, distinguish entry registers from call-produced values, stop at unknown
clobbers, and never claim argument count/types or an indirect target. A concrete
proposal requires its own negative controls and independent review before code.


Mechanism review: the callback byte interpreter already records direct/indirect
call register inputs and symbolic post-call clobbers, but accepts a different
import-disassembly receipt shape and stops at this caller's TBZ branch. It must
not be applied by silently relabelling focused receipts, skipping the guard or
inventing a complete path. Prefer a separately versioned relationship view with
shared verified byte semantics, explicit path selection and entry-versus-range
provenance. A post-call x0 is an opaque register value, not an assumed typed or
meaningful return. Existing callback role names and unconditional completeness
claims would misrepresent this new use. These are design prerequisites, not a
shipping implementation or permission to change existing policies in place.
