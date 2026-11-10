# Held-out function-boundary validation

This owned arm64 assembly fixture varies the guarded call, the constants
and the calling pattern from the calculator. Freeze the source and this
contract before capturing it in full Ghidra. Treat the Mach-O as data
throughout the experiment.

## Cases and expected outcomes

| Case | Expected recovery decision |
| --- | --- |
| Guarded call with a frame setup after two branches | A false split at the frame setup is eligible for a join. The real linker entry owns all 11 instructions. |
| A similar body with an outside branch into the second frame instruction | A split can be reported as ambiguous. The outside reference prevents automatic joining. |
| A wrapper that branches to a separately linked callee | Preserve both linker-confirmed entries. |

Build one native arm64 Mach-O with Apple Clang and retain a linker map,
the linked evaluator binary and an independent LLVM disassembly. Stage
symbol-bearing and stripped analyst copies. Require identical executable
bytes and UUIDs and confirm that stripping removes the evaluator names.
Use separate private projects for the two variants and exercise both
baseline and parameter inference.

First freeze ordinary full-headless exports. Record which cases split
naturally, along with all complete controls. If a candidate is already
correct, exercise the exact guard against a deliberately split copy of
its saved Program. Keep forced splits separate from natural discovery
counts. The fault injection may use evaluator addresses. The candidate
planner and recovery decision may use only the saved Ghidra Program,
normalized evidence and the Mach-O linker starts.

A recovered positive must match LLVM's instruction starts and bytes
through the complete body and preserve the computed call. For each
control compare entry ownership, instruction records and pseudocode.
An outside reference into the proposed competing body must prevent a
join even when it targets an interior instruction instead of the
competing entry itself. Never replace a successful frozen export or
publish a modified Program during the experiment.

## Frozen measurement

The fixture and interior-reference control were frozen at `5e6ef85`.
Apple's default `strip` removed the evaluator names and preserved the
UUID, function-start table and executable bytes. Four full Ghidra 12.2
exports were frozen before opening the evaluator address map.

Both stripped captures split both guarded bodies. The symbol-bearing
captures had six functions each and contained both complete bodies.
The guarded repair restored all 11 LLVM instructions and preserved the
computed call in both stripped profiles. The second candidate stayed
split in both profiles. An independent decode showed that its outside
branch lands four bytes past the competing entry, so checking references
only to the entry would miss it. The wrapper, linker-confirmed callee
and main retained their body ranges, instruction bytes, CFGs and
pseudocode. The archived and disposable Programs retained their digests.
No forced splits were needed.

The capture, recovery plan and recovery report SHA-256 values are
`1a9f9d702b13fca1d307a07fd400e80354cf92754a4ad6768e54bcb348c4cee5`,
`436e6e84e5c3d50ddc6e2578698f5fb488d6145a51ca01bca342b47d9c29a9aa`
and `f4334cd286f00978df74e1e3ed9ff758c0f41a3be852d299ee0cb1b545595de0`.

## Production validation

`analyze --repair-split-boundaries` applies the guarded join to the new
analysis Program after autoanalysis. It records the immutable linker
request and the decision for each candidate. Both held-out profiles
joined the safe body, retained the second split with
`outside_reference`, and kept the confirmed callee. A fresh query
reopened the repaired body. A repeated analysis produced the same
normalized export, and a live cancelled analysis resumed with the
same policy, engine, isolation profile and limits.

In the patched calculator matrix, the opt-in joined the stripped arm64
O2 app body in both profiles and left the other 30 captures unchanged.
The comparison covered entry inventory, body ranges, instruction bytes,
CFG, signatures and pseudocode for the other functions. Each pristine
import Program retained its digest. The recovery matrix report SHA-256 is
`e1cfda3fa055991bf8619ba9dbd25f8066cca04fd015bdd44e860d0753e6421a`.
