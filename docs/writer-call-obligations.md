# Bounded writer-role call obligations

Spec-first additive opt-in to composition policy 3:
`--callback-writer-call-obligations` requires existing four-role receipt options,
register provenance and explicit `--callback-abi aapcs64`. Default writer-role
calls remain composition gaps. The historical writer role is only a verified
linked destination with observed stores, not an application-state writer.

Permit at most eight byte-decoded direct BL sites in the destination prefix.
Each is conditional on normal return and the existing AAPCS64 callee-preservation
model. Preserve the numeric target, receipt identity, prior path/call sites and
unknown arbitrary memory effects. Never assign effects from callee names or
assume retain/release purity. Call targets within any selected role or the whole
verified destination function extent are cycle/reentry gaps. Do not traverse
callees, expand hop depth, restore caller-clobbered values or bypass unsupported
instruction/control-flow boundaries. An indirect invocation in the destination
remains a composition gap even when a preceding store is retained as a raw fact.
Existing projection budgets remain.

Classify at most 64 observed post-call store lanes for this opt-in, retaining
all raw stores when a budget causes a composition gap. An admissible operand is
an explicitly matched destination input-register relation, a byte-defined
address/integer constant, or an explicitly modeled stack/frame origin. Other
post-call operands (call-clobbered, generic unknown, unresolved loads/arithmetic)
remain raw observations but prevent this conditional candidate. Source-transfer
bindings remain scoped and may themselves be unresolved; matching a machine
register never establishes a receiver, alias, object type or live callback.

For each qualifying store, retain exact location/value evidence, relation to
source inputs where established, ABI hypothesis and call-condition sites. This
proves only a static conditional register-to-store relation after an assumed
return. Callee memory writes, receiver/context lifetime, exceptions/non-return,
actual invocation, final application state and persistence remain unknown.
Stack-only or unknown-base destinations cannot become application writers;
F5a destination-effect classifications and unknown attribution stay unchanged.

Acceptance: owned callee-saved positive; caller-clobbered base/value negatives;
unknown-load/arithmetic operand negatives; stack/constant observations explicitly
separate; call count/store budgets; self/back/reentry calls; unsupported prefixes;
missing ABI/opt-in. Preserve immutable deterministic engine-free receipt replay.
Validate any claimed native four-role positive using contiguous independently
verified owned compiler slices, exact identities and saved receipts. If a native
capture or transfer is unavailable, report that blocker and keep synthetic versus
native-fragment coverage distinct. No runtime or application persistence claim.

## Owned native receipt validation

Four actual bounded import-disassembly receipts were captured from the owned
optimized `OwnedCallbacks` binary using installed CLI 0.2.0-83b6bdf, Ghidra 12.2
and JDK 25.0.5.0.3, with read-only/no-analysis worker operations. The source is
the owned callback fixture (the captured source preserves its original formatting).
Binary SHA-256: `5cd6f86bce7b918a44ce97f0990c8a8c11ec69e5ffb6cdfe92a13e69d5e1423f`.

| Selected role | Contiguous range | Bytes | Receipt SHA-256 |
| --- | --- | --- | --- |
| Assignment | 0xb00..0xb0c | 12 | 05f846b857908c240756bdcd1c05f6bf6dd4061429c6658e05d978cb347dbd57 |
| Invocation | 0xc80..0xca0 | 32 | 0c15225154c2ebe398d7eb6cdd83857d3536fd7bfb5ee5f42e14573068bb53ea |
| Thunk | 0xb34..0xb38 | 4 | 5711408ccfd41139673a00179b059a60651a6d50ac4d426469c15a8ee25e6396 |
| Destination | 0x8f0..0x92c | 60 | 094b1818564711cb84d85d1a694972bca0be5bd41a271730fa85f0397f845f19 |

The portable project retains the original image/import/project bindings and
receipt files. It contains no engine database; offline replay succeeds with
nonexistent engine/JDK paths. The installed-wheel validation script
`tests/integration_native_writer_receipts.py` checks receipt digests, replays the
explicit opt-in twice, compares complete output and job files, and verifies the
default without the writer opt-in remains a gap. No replacement synthetic
receipts or omitted instructions were used for this native check.

The conditional result contains the store at 0x918, whose base and value relate
to destination inputs under callee preservation after BL 0xd94 at 0x914. The
invocation still requires its nonzero predicate and the normal-return/ABI
hypotheses for its BL at 0xc94. Four stack/frame stores and one unresolved-base
store remain distinct; there is **no attributed application writer**. Source
inputs are scoped selected-range values, not identified live objects or proven
function parameters. Assignment/invocation slot identity, context lifetime,
callee memory effects, execution order, actual execution and persistence remain
unresolved. This is a native four-role **conditional static candidate**, not a
runtime callback recovery or whole-application behavior proof.

The capture imported and disassembled an existing owned compiler artifact; it
did not execute the binary, perform full analysis, or install a new system CLI.

## Validation checkpoint

807 primary and 115 analysis tests passed. Independent review passed 69 focused
tests and independently replayed the actual owned native four-role receipts.
The installed package passed the same 69 focused tests plus actual-native and
synthetic multi-receipt replay outside the checkout. All replays were engine-free
and preserved receipt/job bytes and identities. Negatives cover clobbered and
unresolved operands, reentry, call/store budgets and writer indirect boundaries;
raw prefix observations survive rejected composition.

The remaining practical gate is consumer usefulness on a separately authorized
scoped investigation. Passing this owned fixture does not establish arbitrary
Swift coverage, unknown-callee purity, runtime identity or general performance.
