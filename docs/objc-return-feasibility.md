# Owned selected-method return-channel feasibility

Experiment only, not product functionality. Preserve merged main18868790 runtime.
An isolated copy may explicitly annotate one known owned method's return type,
only within a rollback transaction around decompilation. Never alter imported
objc_msgSend or any other callee prototype. Original source checkout, imported
Program and installed CLI stay unchanged; separately pinned experimental bridge
digest identifies altered assumptions. No app execution or whole-image analysis.

Freeze four owned methods: integer result forwarded from a message send; void
method discarding the same send; method calling then returning zero; floating
result control. Capture baseline all four on arm64/x86_64. Repeat integer and
zero methods with explicit int64_t return assumption. Deliberately apply that
same incorrect assumption to the void method in a distinct negative experiment.
Do not annotate floating result control; it is outside the candidate integer scope.
No parameter assumptions, global signature changes or source-code injection.

Record exact metadata/binary/assembly/receipt/experimental bridge hashes and code,
return inference and native-scope differences. Verify original/experimental base
Programs unchanged after captures and selected type restored after rollback.
If void/int methods have indistinguishable transfer bodies, byte structure cannot
justify automatic return semantics: that is a stopping condition for automatic
inference even if an explicit assumption makes prettier pseudocode. Preserve
unresolved dispatch and partial status. Output from wrong assumptions is evidence
of risk, not support for the annotation. Decide whether any justified product
change exists only after reviewing controls; an inconclusive experiment is valid.

## Initial measured outcome (not a product implementation)

The eight baseline captures completed. Integer-forward, void-discard and floating
forward methods retained unresolved-message-send warnings and apparent void
pseudocode on both architectures. The call-then-zero control correctly returned
zero (ARM64 complete; x86 partial because of undecoded trailing padding).

Forward-integer and void-discard have identical transfer instruction semantics
on both architectures, apart from PC-relative encoding differences. ARM64 moves
x2 to x0 and branches to the same selector stub; x86 moves RDX to RDI, loads the
same selector, restores the frame and jumps through the same message-send slot.
Different source return contracts are therefore not recoverable from this
transfer shape alone. This is the specified stopping condition for automatic
return inference, not evidence that metadata may be automatically trusted.

All six explicitly assumed experimental captures failed closed with exit10 and
query_result_mismatch. Native decompilation ran, but the rollback guard suppressed
all function outputs. No usable improved pseudocode was accepted. A separate
single diagnostic capture retained that guard and found return `undefined→long`,
signature/source `DEFAULT→USER_DEFINED`, and storage `UNASSIGNED→x0:8` still visible
after ending the nested transaction; a second function lookup saw the same state.
That second lookup is not an independent database read.

Official installed Ghidra12.2 DomainObject documentation explains that nested
transactions do not fully end until all outstanding transactions end. Thus this
shows an experiment checking too early for deferred rollback, not a demonstrated
production rollback failure. Original engine file hashes and the baseline bridge
hash remained unchanged. Unchanged disk hashes alone do not prove in-memory
restoration and are not grounds to relax the guard.

At the initial-failure checkpoint, a read-only investigation was checking whether a supported sequential-script
boundary can provide same-Program verification after the full transaction ends.
No further annotation result will be accepted without that verified boundary and
independent review. Any staged result remains untrusted; missing/failed verifier
must reject it. Original Programs and installed tools remain untouched.

## Two-stage alternative (reviewed before execution)

Official installed headless sources confirm that sequential default-mode post-
scripts finish their own transactions before the next script runs, sharing the
same Program through GhidraState. A new experiment-only generator stages output
instead of publishing it. It retains explicit annotation/rollback but does not
pretend nested abort is immediate. A second post-script must observe exactly its
own active transaction (different ID), the same Program reference and binary,
and exact restored function signature, return, parameters/storage and flags.
Only then may it accept the digest-bound staged bytes at a fresh output path.
Nonce/context is one-shot; absent, stale, failed or interrupted verification
leaves no normal output. Script hashes are bound by the bridge digest and a
separate generated-file manifest. No save is allowed while assumptions are active.

Run one owned positive ARM64 method first. Verify a missing-verifier negative
leaves the staged result unaccepted. Only after that gate may integer/zero/wrong-
void comparisons proceed. Preserve the original immediate-check experiment and
its failure records; this is a new verification boundary, not a bypass or product
feature. Continue checking original Programs and production source hashes.

Independent review approved only the bounded first ARM64 capture and missing-
verifier negative. The reviewer found no design blocker but explicitly required
runtime verification of public APIs/transaction shape, unchanged original hashes,
and absent accepted output on verifier failure. At that review checkpoint, native results were still pending;
this approval does not establish product readiness or safe automatic inference.

## First two-stage native gate

On the owned ARM64 integer-forward method at `0x6f8`, the verifier accepted the
same-Program restoration from transaction 4 to transaction 5. The selected query
remained **partial (exit 6)**, with unresolved dispatch and out-of-body native
operations. Original Program file hashes remained unchanged. The separate
missing-verifier run failed **exit 10**, leaving only the unverified staged bridge
payload and no normal bridge/query result. That negative does not prove every
possible verifier failure, but verifies the missing-stage path fails closed.

The explicit return annotation is not an unconditional readability improvement.
Baseline pseudocode exposed the third input and selector in the message send:

```c
(*(code *)PTR__objc_msgSend_00004010)(param_3,PTR_s_ownedInteger_00008098);
return;
```

The experimental output instead contains a return value but hides those inputs:

```c
/* WARNING: Unknown calling convention -- yet parameter storage is locked */
long __OwnedReturnChannels_forwardInteger__(void) {
    long lVar1;
    lVar1 = (*(code *)PTR__objc_msgSend_00004010)();
    return lVar1;
}
```

The return is an **explicit assumption**, not newly discovered evidence. Receiver
and selector visibility regressed, calling convention remains unknown, and the
unresolved-jump warnings remain. Do not promote this experiment to a default or
claim the output recovers the source signature. At the first-gate checkpoint, two additional ARM64 controls
were pending: the deliberately wrong integer assumption on the void-discard
method, and the correct assumption on the call-then-zero method. No two-stage x86 repeat
or floating-return annotation is needed to justify the current no-promotion
position.

First-gate evidence archive SHA-256:
`8fb4e929fba64de470c1c3a6ca9080f67991bd9bddba9a52335fd46451864197`.
Positive job `8f7c66d340364c9089c2ce9e961df392`; missing-verifier job
`846f1524dec944269f2a42bcece1256e`. Generator SHA-256:
`e2bee209d7187e4e23d1a4fcf4663de92283fd0f43b79111bc0dca313aec8fb3`.

## Completed controls and decision

The two additional ARM64 controls passed the same post-transaction restoration
guard (transaction 4 to 5), and original Program file hashes remained unchanged:

| Owned control | Explicit assumption | Observed result | Meaning |
| --- | --- | --- | --- |
| `discardInteger:` at `0x700` | Deliberately wrong `int64_t` | Partial; prints an integer-return function returning the message-call result | A plausible return expression can be fabricated by a wrong assumption. |
| `zeroAfterInteger:` at `0x708` | Source-correct `int64_t` | Complete; still returns zero, but call becomes `func_0x00000760()` without the visible receiver input | Even a correct return assumption degrades argument visibility. |

Both add the unknown-calling-convention/locked-parameter warning. The wrong-void
control still has unresolved dispatch and native operations outside the body;
its partial status must not be construed as validating the assumed return type.
The zero control's complete status describes the bounded flow capture, not proof
that the displayed signature or absent arguments match the source ABI.

An independent reader compared the baseline and first experimental outputs and
recommended **no promotion**. It found that both share identical instruction
bytes, while the experimental return expression adds no independent evidence.
The receiver and selector relationship disappears from pseudocode; dispatch
remains unresolved. Its single address span covers the calling-convention
warning rather than the returned expression, so it is not evidence of newly
established return flow. The bridge hash identifies the altered experiment,
but raw output alone does not explicitly label the assumption. Do not distribute
experimental pseudocode without this report and its generated-file manifest.

**Decision:** stop this return-only annotation approach here. Do not add a
production option, automatically inject Objective-C return metadata, replace raw
pseudocode, or change global dispatch prototypes. The native rollback mechanism
worked for this bounded experiment, but that does not rescue the substantive
usability and correctness problems. Keep the raw output and existing separate
Objective-C metadata/context as evidence with distinct provenance. Any future
user-directed signature experiment would need explicit assumption provenance,
validated parameter/calling-convention handling, and counterexample tests before
it could be reconsidered; those are not implemented by this assessment.

Controls archive SHA-256:
`29b284bad955b54ce48648e9d10ffcfdbf41f8b74cd85be2dd99fc9f45c8fdfa`.
Wrong-void job `a1035adde8154bb0b3f5e2848c20fc98`; correct-zero job
`f9209e805633487799baf160a7607224`. No fixture/app execution, floating-return
annotation, two-stage x86 experimental repeat, production runtime edit, installation or
Taskovsky restart was performed. These are static decompilation experiments,
not execution-equivalence tests.

Independent final review checked the native artifacts, restoration markers,
negative-path rejection, misleading return and parameter-loss controls, and
confirmed that all changes are assessment-only. It approved publication of this
negative result, not a product feature.
