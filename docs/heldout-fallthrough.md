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
