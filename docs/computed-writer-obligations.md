# Scoped checked-add writer operands

Spec first. Explicit writer-call obligations can currently relate input registers,
constants and stack values, but the owned alternative writer stores a supported
checked-add result after a call. Treat that supported computation separately from
unknown arithmetic without claiming a runtime value or an application field.

Allow `--callback-writer-call-obligations --callback-abi aapcs64` on an explicitly
pinned two-hop route, as an alternative to the existing four-role mode. Require
all existing receipt restrictions and keep link status separate from the writer
proof. No automatic opt-in, recursive calls, transitive register substitution or
outer-function extent inference. Existing call limit 8 and post-call store limit
64, cycle/reentry checks, indirect-call barriers and unknown callee effects remain.

Writer policy 2 adds value-only basis `scoped_checked_add_computation`. Never
accept it as a store base/pointer proof. Require exactly one earlier checked-add
site whose result exactly equals the stored scoped value, including source
envelope, selection start and origin instruction. Require a validated 64-bit
ADDS-immediate definition, with the recorded immediate/width/overflow flag and
result bound to its byte-decoded site. For this symbolic basis the left operand must be a selected input
register of this receipt/selection. Concrete arithmetic retains the existing
byte-defined constant basis, not a synthetic symbolic definition. Loads, clobbered values,
nested/generic arithmetic and foreign identities remain unresolved.

Require the exact adjacent overflow guard in both instruction sites and path
obligations, bound to this definition/operand/immediate; the stored value must
retain that guard and all preceding call/branch conditions of the definition and
guard. The defining instruction precedes guard, which precedes store. Unsupported
or absent paths cannot be supplied by a matching register name. The existing
byte decoder provides def-use provenance; this view does not invent a new alias.

Return bounded defining arithmetic and guard evidence alongside a separately
labeled symbolic input and `runtime_value: unknown`. Per-store status remains
conditional, not concrete recovery. Runtime execution, application attribution,
persistence and receiver lifetime remain unknown. Add no algebraic folding or
materialized expressions and traverse no further definitions.

The two-hop view exposes `writer_call_evidence` only on opt-in. Its proof may be
gap even when both independent links verify; a prefix barrier must remain a proof
gap. Text shows the writer-proof status separately. Default two-hop output retains
its original behavior. Existing four-role unknown-arithmetic negatives remain.

Acceptance: exact owned native checked-add store and matched base under explicit
ABI assumptions; wrong source/selection/origin/result, missing or mismatched guard,
lost condition sites, forward definitions, loads/clobbers/nested arithmetic and
computed bases remain gaps. Retain budget/reentry negatives, immutable offline
replay and all earlier native gates. This does not establish four-role completion.

## Validation checkpoint

856 primary tests and 115 analysis tests passed. Independent review reran 31
focused tests and the actual owned native two-hop gate. Installed-wheel replay
outside the checkout tested four configurations (guard off/on, writer proof
off/on), each twice in text and JSON: 16 CLI invocations, no engine dependencies
and no changes to jobs or receipts. Existing native composition and standalone
checked-add replay gates also passed.

Using the exact owned receipts documented in `pinned-twohop-thunks.md`, the opt-in
proof identifies destination input x20 as a matched base relation and the value
stored at 0xabc as `scoped_checked_add_computation`, defined at 0xaa0 from selected
input x0. Its no-overflow guard at 0xaa4 and call hypothesis at 0xab8 remain
explicit. The definition, guard and symbolic input keep the destination receipt
identity. Without guard projection, writer proof remains gap even though both
independent entry links verify. No runtime value or application meaning is inferred.

Independent review added matched site/path tampering negatives for branch target,
fallthrough and predicate state; the helper checks those against encoded bytes
and the limited supported overflow knowledge. No whole-image analysis, inspected
application execution, system installation or consumer session occurred.
