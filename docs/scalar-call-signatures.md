# Scalar call signatures

Use `decompile --fresh --recover-scalar-call-signatures` to apply
binary-derived scalar ABI evidence in a disposable copy of a saved
Program. The option accepts a single function selector and requires
`--experimental-trusted-input`. It uses its own query, separate from
aggregate return recovery and accepted type hints.

The `macscope-scalar-call-signatures/1` policy handles two cases.

- On x86_64, the exact direct call targets a linker entry and is followed
  by a test or comparison of the full `EAX` register. The complete leaf
  must have a single return and define `EAX` with `movzx eax, al` in its
  return sequence. A branch that can bypass the definition declines
  recovery. The selected function can be the caller or the callee.
  The bridge checks the saved flow and native one-byte return storage
  before applying a four-byte integer return. It preserves the input
  parameters and skips protected signatures.
- On arm64, the exact `BL` must reach a file-backed Mach-O import stub.
  The stub's `ADRP`, `LDR`, and `BR` must resolve to the strong, zero-addend
  `___stack_chk_fail` binding in libSystem. The bridge checks that the
  saved thunk resolves to the matching external function with zero
  parameters and a non-returning signature. It applies the explicit
  `void (void)` ABI to the import in the query copy.

The query returns `origin.scalar_signature_recovery` with its policy,
request digest, applied sites or skip reasons, and the proved ABI.
Receipt replay revalidates the request against the original saved
analysis and imported bytes.

## Installed CLI validation

The installed wheel reimported the owned O0 calculator and the
[independent scalar-call fixture](../analysis/heldout_scalar_signatures.c)
for arm64 and x86_64 in both profiles and both symbol states. The
fixture was frozen at `b118771` after checking its emitted call and
return instructions with LLVM. The x86_64 control uses a byte result
at its call site. The arm64 control calls `abort` through a different
import stub. The workers could read the imported copies and had
no access to source, evaluator artifacts, or prior project folders.

The calculator's saved instructions, body ranges, CFG, cross-references,
signatures, and C matched the archived captures. All 24 eligible
queries applied recovery, including separate x86_64 caller and helper
queries. All eight independent controls declined and matched ordinary
fresh C. All 32 receipts replayed. The original Programs and cached
exports retained their hashes.

The evaluator matched the frozen outputs to source and DWARF and
compiled the captured C with the existing compatibility policy.
The x86_64 state-transition closure used the separately queried fresh
helper definition and the remaining saved definitions. The independent
evaluator used the frozen source's architecture-specific reference
branch. The first evaluator run had selected the host's reference
branch for the x86_64 case and rejected the arm64 byte return. The
scored run corrected those harness checks and reused the same frozen
CLI outputs.

| Behavior case | Passing scopes | Directed per scope | Seeded per scope |
| --- | ---: | ---: | ---: |
| Calculator arm64 `calc_format_int64` | 4 | 1,005 | 10,000 |
| Calculator x86_64 `calc_engine_input_op` with parameter inference | 2 | 6,252 | 10,000 |
| Independent observers | 8 | 256 | 10,000 |

All 14 completed domains had zero mismatches. The two baseline x86_64
operator cases applied the verified return width but failed to compile.
A different callee still has an incompatible pointer and integer
parameter type. The arm64 behavior domains test normal returns with a
stable stack guard.

The scores below apply separately to stripped and symbol-bearing
calculator captures. Each fresh score combines the passing opt-in
outputs with the other passing saved routines.

| O0 profile | Cached routines | Cached instruction bytes | Routines with fresh recovery | Instruction bytes with fresh recovery |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 41/52 | 5,360/8,644 | 42/52 | 5,900/8,644 |
| Parameter inference | 50/52 | 7,869/8,644 | 52/52 | 8,644/8,644 |

The installed wheel also reproduced the prior x86_64 O2 direct and
dispatch results in a regression check using the saved parameter-inference
calculator Program. Both fresh C outputs and recovery decisions matched
the archived results.

| Local evidence | SHA-256 |
| --- | --- |
| Installed wheel | `59dad5c9f397a81761f8e12c4209204212f92892ec17a235a3abac63007a1e05` |
| Independent fixture plan | `175050c7f9bf2e96f2734729f0ffece26bb9bc07db745a43a960bca48e2b0e20` |
| Frozen queries | `ccd33bffec84e591588c861b22258aaeb1a1ba546232951857a689ed88315db0` |
| Behavior report | `ab0e13a21a0ee02bd9ce4326bd46726d0f079d5a6fa4799dbf96f3a4f638cb0f` |
| Combined O0 score | `c05da22e093a91994d38fd5cdba68f349b6f8a619b1bb83f5db30c56b0bb74d6` |

The reports are in
`/private/tmp/macscope-scalar-signatures.9nKUhH/official`.
