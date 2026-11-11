# Bounded callback composition (F4b)

Composition policy 2 adds [explicit split-load and invocation-path opt-ins](split-invocation-obligations.md).
The paired-only contract below remains the default; the native whole-chain limit
remains until all its roles satisfy their obligations.

Specification first. The composition view joins independently verified saved
receipts, not execution states. It never forwards a stored value into a load,
assumes aliases, identifies a live receiver, or claims persistence.

`disasm --from-import --range START:END --receipt THUNK
--callback-evidence --callback-provenance --callback-target-receipt WRITER
--callback-assignment-receipt ASSIGNMENT --callback-invocation-receipt INVOCATION`
requests a bounded four-role view. Both new options must occur together with
saved thunk/writer receipts and provenance (or the explicit AAPCS64 hypothesis).
The existing one-hop linker-verified thunk-to-writer link is reused. No recursive
search, extra native jobs, or receipt mutation occurs. Each selection is at most
4096 bytes / 1024 instructions. At most one target store, one associated context
store, one invocation and its target/context loads are accepted; ambiguity is a
gap rather than ranking by names. Roles may reuse a receipt, but a direct writer
link back to its source selection is a cycle and cannot compose.

A target store is an address-valued store naming the selected thunk entry.
A context store is the other lane of that same pair instruction. This is only
an observed pair, not a recovered closure layout. Invocation must be a BLR with
a byte-proven memory-load operand and a paired load of a context register. These
are independent facts, even if offsets agree. Later stores in the assignment
prefix, intervening calls, unsupported barriers, missing receipts or uncertain
operand origins prevent the candidate composition. Unsupported destinations
cannot contribute a writer fact. All existing gaps remain visible.

The output separates `facts`, `assumptions`, `unknowns`, and `gaps` and always
remains inconclusive. A `conditional_candidate` means the four independent
observations exist, not that the chain ran. Unknown obligations always include
assignment-slot to invocation-slot identity, unchanged intervening memory,
invoked code identity, context identity/ABI, execution order and application
writer attribution/persistence. Matching offsets do not discharge any of these.
ABI conditions are accumulated with their receipt identities and sites.

Acceptance: owned paired assignment/load/invocation and linker writer chain;
overwritten callbacks, mismatched context offsets, clobbered target register,
uncertain loads, cycles, missing receipts, unsupported boundaries and immutable
deterministic offline replay. Keep raw independent evidence and failures rather
than silently interpreting absent composition as absent callbacks.

Invocation input-register observations are retained in provenance modes. For a
structural candidate only, `conditional_register_bindings` maps each captured
machine register to the same register at the selected thunk entry, conditioned
on the unverified runtime target and execution order. These bindings are not
substituted into writer facts or memory reads. Each source value keeps its
invocation receipt scope; no field/object alias is introduced. Register names
alone do not prove a Swift calling convention or context role.

## Validation and scope

Independent review includes concrete-address (ADR and MOVZ), overwritten store,
clobbered target/context, unresolved load, self-link and writer-backedge negatives.
A candidate retains all runtime identity obligations even when the numeric slots
match. Any writer back edge into the traversed thunk/writer ranges blocks
composition; no deeper graph is explored. Existing role-local gaps remain
visible even when they merely mark the expected invocation/transfer boundary.

Hand-constructed owned Mach-O fixtures exercise the full four-role positive
composition and deterministic immutable replay. They are not compiler output.
The installed-wheel smoke runs outside the checkout with unavailable Ghidra/JDK,
replays all roles twice, and verifies no new job files or receipt changes.

At this checkpoint, 730 primary tests and 115 analysis tests passed. Independent
review passed 45 focused callback/composition tests, including fixes for writer
back-edge cycles and concrete slot mismatches across address/constant forms.
The CLI and projection changes are additive; receipt storage and native workers
are unchanged. This is a bounded static candidate view, not general callback
recovery or an application-behavior result.

### Native compiler oracle: supported fragments, unresolved whole chain

Reinspection of the owned `OwnedCallbacks.swift` artifact compiled with Apple
Swift 6.4 (`swiftlang-6.4.0.34.1`, arm64, `-O`) confirms assignment at
0xb00..0xb0c: `0800009008d12c9188d201a9` materializes thunk 0xb34 and stores
x8/x20 as a pair at x20+24/+32. The thunk's `6fffff17` branches to writer 0x8f0;
independent function-start metadata bounds the thunk at 0xb34..0xb38 and writer
at 0x8f0..0x92c. These are separate static facts.

The compiler's actual invocation is **not supported by this composition slice**:
at 0xc80 it loads x21 from x20+24, branches conditionally at 0xc84, loads context
separately from x20+32, calls another function at 0xc94, then BLR x21 at 0xc9c.
There is no contiguous paired-load-to-BLR path. The 0xc98 suffix has only MOV
and BLR and cannot recover the earlier loads/context. Debug output similarly
uses separate stack loads with unknown contents. Tests preserve the conditional
branch barrier and the suffix's unknown invocation operand. Do not omit these
intervening instructions to manufacture a composed result.

This was revalidation of existing native artifacts using disassembly and Mach-O
metadata, not a fresh build or Ghidra capture. Nothing was executed or installed.
Thus the full positive chain is covered by owned synthetic receipts, while the
native Swift chain remains explicitly unresolved. Supporting the real split
load/conditional-call path needs a separate specification and validation step;
it is not silently enabled here.
