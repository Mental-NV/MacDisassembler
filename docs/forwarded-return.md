# Forwarded integer returns

Use `decompile --fresh --recover-forwarded-return` on a selected
arm64 or x86_64 function in an owned-input analysis. The query requires
`--experimental-trusted-input` and uses its own disposable Program
copy. Run it separately from accepted type hints and the other call
recovery options.

The `macscope-forwarded-return/1` policy proves a direct call to a
linker entry followed by a single, register-preserving epilogue.
The selected wrapper must have no branch that bypasses the call
and enters the epilogue. A separate direct caller must store the
full returned word to a writable Mach-O segment. On x86_64 this
is an immediate RIP-relative store from `RAX`. On arm64 a bounded
straight-line sequence can copy `X0` and store it through a
verified page-relative address. Discarded values and byte stores
provide insufficient evidence.

The bridge checks the saved call paths and bytes. It requires
Ghidra to infer an eight-byte integer in the expected return
register of the immediate callee. It uses the existing bounded
callee parameter recovery before applying the same return ABI to
the wrapper. It preserves the input parameter types and storage
and respects protected signatures. The final decompile must
retain the proved return. The query records the call and store
sites, the return register or skip reason, and the request digest
in `origin.forwarded_return_recovery`. Receipt replay verifies
the saved analysis and original bytes.

## Installed CLI validation

The installed wheel imported the original
[callee-parameter fixture](../analysis/heldout_callee_parameters.c)
and the second [forwarded-return fixture](../analysis/heldout_forwarded_return.c).
Both used owned O0 arm64 and x86_64 slices, both symbol states, and
both analyzer profiles. The second fixture was frozen at `7597a02`
after LLVM confirmed separate full-width, discarded, and byte-only
observations. Workers could read their imported copies and had no
access to source, evaluator artifacts, or prior project folders.

All 16 wrapper queries applied the proved return. The original
fixture's behavior check used a separate fresh query for the helper's
definition. The evaluator matched frozen outputs to source and
DWARF, compiled the captured C with the existing compatibility
policy, and checked the return and both state fields. Each of the
16 cases passed 256 directed and 10,000 seeded comparisons with
zero mismatches.

The eight indirect-call controls from the original fixture declined
recovery. The second fixture's eight ignored-result and eight
byte-only controls declined for lack of a full-width observation.
Each control matched ordinary fresh output. All 48 query receipts
replayed, including the helper queries. The original Programs and
cached exports retained their hashes.

Installed-wheel regression queries reproduced the earlier direct,
dispatch, scalar, and callee-parameter outputs. A second wheel
containing the workspace manifest fix also replayed an earlier
baseline receipt after parameter inference became active and
reproduced the active profile's fresh forwarded return.

| Local evidence | SHA-256 |
| --- | --- |
| Installed wheel | `9430162e19c55554f37d06ddd78edce4188d83de8ffa096602d25c9fcc906f7e` |
| Original fixture plan | `90c8274ab338ef153c5abed814d0d0af4b724e324a8a725629ded225bb790394` |
| Second fixture plan | `c979449e43c844a31f97dddea056c6bcd8ae9e9fa43c7f73db1f2760e7cabea3` |
| Frozen queries | `2d23bb016ead04d57826238d53ee62246d6a29a235bb1df1f924206fefbb4019` |
| Behavior report | `7f4e78fa63669a028e266d5847002b4d7ded1543cf561595b4675f19b3a1e2ca` |

The reports are in
`/private/tmp/macscope-forwarded-return.gwE9OS/official`.
