# F5e: split-load invocation and conditional fallthrough obligations

Spec-first, callback policy 6 / composition policy 2. Default paired invocation
matching and existing barriers are unchanged. New composition-only flags:

- `--callback-context-register x20` pins the **analyst-selected machine register**
  to inspect at BLR. Supported pins are x0..x7 and x19..x29, the existing recorded
  invocation-input set. This does not identify Swift context ABI. The pinned
  register must hold a byte-observed memory-read identity; identify that exact
  load by instruction/lane. Target and context loads must be distinct and share
  exactly the same evidenced base within this selection, with matching relative
  layout to the assignment pair. Merely similar offsets or different symbolic
  bases cannot establish that relation. Intervening stores remain a gap.
- `--callback-invocation-fallthrough` permits a single contiguous **fallthrough
  path** in the invocation receipt only. Decode CBZ/CBNZ W/X from bytes; record
  the branch destination, tested register/value, width, and required fallthrough
  predicate. Do not visit taken branches, merge paths, skip instructions or
  assume the predicate true. Other conditional forms remain barriers. Reject
  backward/self edges and statically impossible fallthrough. Stop after 16
  conditional branches; existing 1024 instructions/4096 bytes applies. Track
  prior zero/nonzero predicates on identical scoped value versions; reject
  contradictions, including X==0 with W!=0. W==0 with X!=0 remains possible
  unless independent zero-extension evidence exists. Fresh loads never alias
  earlier loads solely because their locations match. Generic unknown register
  writes receive an instruction/receipt-scoped value identity; copies preserve
  it and later writes replace it. Register labels alone are never value identity.

The second flag also permits invocation direct calls only when the user explicitly
selects `--callback-abi aapcs64`. Existing normal-return and callee-preservation
assumptions remain required. Caller-saved inputs are invalidated. Callee-saved
registers may retain loaded pointer identities **conditionally**, not memory
contents or object lifetime. Preserve unknown call effects, slot memory changes,
context lifetime, runtime target, execution order and taken-path behavior as
unresolved obligations. A call without the ABI hypothesis remains a barrier.
Direct calls back into the selected invocation range are cycle/reentry gaps;
no recursive proof is attempted. Calls in assignment/thunk/writer roles remain
composition gaps in this slice.

The output keeps byte facts, path predicates, ABI assumptions and unknowns
separate. Every later observation includes prior branch-condition sites; the
full scoped predicates remain in `path_obligations`. Composition exposes these
under role identity and repeats branch/call requirements on conditional register
bindings. It never applies those bindings to writer facts. `conditional_candidate`
is still inconclusive, not a runtime invocation or attributed/persisted write.
All alternate branch paths are explicitly not analyzed. Missing receipts and
identity validation keep existing fail-closed behavior. No native jobs are added.

Acceptance: owned split and paired positives; exact same-base and layout checks;
clobbered context/target, store overwrite, unknown memory effects, absent ABI,
divergent/unsupported branches, cycles, impossible predicates and budgets.
Replay must preserve all unknowns and produce identical output without engine
jobs or receipt mutation. Native positive invocation-path coverage must use one
contiguous independently verified compiler slice and preserve every intervening
instruction. If the whole four-role native chain cannot compose, report that
separately from synthetic positive coverage. No whole-chain claim by omission.

## Owned native oracle and remaining whole-chain limit

Reverified Apple Swift 6.4 (`swiftlang-6.4.0.34.1`, arm64 macOS, optimized)
`OwnedCallbacks.swift` from the existing owned compiler artifact. The selected
0xc80..0xca0 file-mapped bytes are exactly:
`950e40f9550100b4941240f9e00315aae10314aa49ffff97e00313aaa0023fd6`.
They contain eight contiguous instructions, none omitted:

1. LDR x21,[x20,#24]
2. CBZ x21,0xcac
3. LDR x20,[x20,#32]
4. MOV x0,x21
5. MOV x1,x20
6. BL 0x9b8
7. MOV x0,x19
8. BLR x21

The selected fallthrough requires the loaded x21 to be nonzero. Initial x20 is
the shared load-base input; after the second load it is a different, loaded
context value. Preservation of x21 and loaded x20 through BL is an explicit
AAPCS64/normal-return hypothesis, not recovered callee behavior. The taken target
0xcac lies outside the selection and is not analyzed. Only the numeric direct
call destination is reported; disassembler labels do not establish its effect.

Exact-byte unit projection now reaches BLR conditionally and retains both load
identities, branch predicate, call site, memory/lifetime unknowns and receipt
scope. This is native **invocation-slice** evidence, not a full native composed
chain. The existing native writer at 0x8f0..0x92c contains BL 0xd94 before its
store at 0x918; writer-role calls remain a composition gap. No instructions are
removed to evade that limit. Full positive four-role coverage still uses owned
synthetic receipts. Native inspection reused existing artifacts read-only;
there was no fresh compiler build, Ghidra capture, installation or execution.

## Validation checkpoint

788 primary and 115 analysis tests passed on the cloud checkout. Independent
review passed 67 focused tests after fixes for contradictory predicates and
unknown-value version identity. Installed-wheel replay outside the checkout
uses unavailable Ghidra/JDK paths and reproduces conditional path/call obligations
identically, preserving unknowns and all job/receipt files. This replay uses owned
synthetic receipts, distinct from the native exact-byte slice validation above.
