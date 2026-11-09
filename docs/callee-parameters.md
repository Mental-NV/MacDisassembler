# Query-scoped callee parameters

Use `decompile --fresh --recover-callee-parameters` for a selected
arm64 or x86_64 function from a saved owned-input analysis. The option
runs in a private Program copy and requires
`--experimental-trusted-input`. It uses its own query, separate from
return recovery and accepted type hints.

The `macscope-callee-parameters/1` policy follows up to two direct
call hops and at most 16 internal targets. A site's encoded arm64
`BL` or x86_64 `E8 rel32` destination must match a saved call
reference and a linker entry. The planner checks the saved instructions
against the imported slice and declines cycles in the traversed graph.
The bridge rechecks each path in the saved Program before applying
changes.

Ghidra infers each eligible callee's parameters from its own body,
processing callees before their callers within the verified graph.
The bridge accepts a contiguous prefix of ordinary integer argument
registers with supported widths and leaves existing signatures in
place. It checks committed types and storage against the native
inference and verifies that the stored return type and storage are
unchanged. The selected function is then decompiled in the copy.
`origin.callee_parameter_recovery` records the verified paths, argument
storage, and per-callee skips. Receipt replay verifies the original
analysis and proof.

An initial disposable experiment isolated the effect of committing only
parameters. That recovered all ten outstanding symbol-bearing O0
baseline routines on the candidate engine. Committing the native
return types as well made the x86_64 operator-entry case untestable
again. The installed option commits only parameters.

## Installed CLI validation

The installed wheel reimported the owned O0 calculator on both
architectures in both symbol states and analyzed it under baseline.
The new saved captures matched the archived body ranges, instructions,
CFGs, cross-references, signatures, and pseudocode. The evaluator
selected the known regression addresses. Workers received only the
imported copies and could not read source, evaluator files, or prior
project folders.

The evaluator compiled the frozen fresh definitions with compatibility
policy `macscope-ghidra-aggregate-compat/10`. Where needed, a closure
used a separately queried definition of `calc_apply_op` or
`calc_history_get` with the other saved definitions. The formatter used
the separate [scalar signature option](scalar-call-signatures.md).
The 24 completed comparisons had zero mismatches. Twenty covered the
ten parameter-related failures in both symbol states. Two covered
the formatter, and two repeated the previously passing x86_64
`calc_apply_op` domain. Each completed domain used at least 100 directed
and 10,000 seeded cases.

| O0 baseline scope | Saved routines | Saved instruction bytes | Routines with fresh recovery | Instruction bytes with fresh recovery |
| --- | ---: | ---: | ---: | ---: |
| Stripped | 41/52 | 5,360/8,644 | 52/52 | 8,644/8,644 |
| Symbol-bearing | 41/52 | 5,360/8,644 | 52/52 | 8,644/8,644 |

Each row includes 26/26 arm64 routines and 4,792/4,792 arm64 bytes,
plus 26/26 x86_64 routines and 3,852/3,852 x86_64 bytes. The combined
O0 report incorporates the separately verified parameter-inference
result from the scalar checkpoint. Both results use the separately
selected experimental full Ghidra tree.

The [independent call chain](../analysis/heldout_callee_parameters.c)
was frozen at `aef19e6`. Its baseline queries recovered the parameters
on both hops. All eight indirect-call controls declined recovery.
Eight queries with existing parameter-inference signatures skipped
the already analyzed callees. Both groups of skips matched ordinary
fresh output. All 50 calculator and held-out receipts replayed. The
original Programs and cached exports retained their hashes.

The independent observer is still untestable in all four baseline
captures. Ghidra prints it as `void` in both cached and fresh C,
although its caller observes the forwarded result. The arm64
epilogue restores the frame and leaves `X0` intact. The x86_64
epilogue leaves `RAX` intact. A separate return hint on the immediate
callee alone also left the outer wrapper `void`. The independent
observations are separate from the calculator score.

A second read-only diagnostic set the same native eight-byte return
on the immediate callee and the selected wrapper after recovering
their parameters. The outer caller copies `X0` to `X8` and stores
`X8` on arm64, and stores `RAX` directly on x86_64. The assisted
wrapper output passed 256 directed and 10,000 seeded cases in each
of the four captures with zero return or state mismatches. The
diagnostic is separate from the CLI score. Its report SHA-256 is
`1ce7547b0480ba564fcb2a91935cd87256228d148c92e46245977ee14ea7795c`.

The previous direct, dispatch, and scalar options reproduced their
archived C and recovery decisions in installed-wheel regression
checks.

| Local evidence | SHA-256 |
| --- | --- |
| Installed wheel | `b8e0149414b119bc3f10fd60f0a98b8cfa8dcfaf75a86f038359b73299a2aed9` |
| Independent fixture plan | `90c8274ab338ef153c5abed814d0d0af4b724e324a8a725629ded225bb790394` |
| Frozen queries | `6b7cb53e9326246858a719f6ff6b36a6ca4b07990133a4aa8ba3821b3d3b9eb1` |
| Behavior report | `d73a87feb0cb10ba62f8b685a50e2f29314930376d78f6b052dfdfc580d13317` |
| Combined O0 score | `9ff418f31aa5dbe6b32d661584da460d835c39ca382399d2e458288a56deb1ae` |

The reports are in
`/private/tmp/macscope-baseline-callees.89xYWz/official`.
