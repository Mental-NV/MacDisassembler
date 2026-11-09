# Direct-call signature recovery

Use `decompile --fresh --recover-direct-signatures` on an owned x86_64
input analyzed with the selected full Ghidra distribution. The
`macscope-direct-call-signatures/1` policy follows at most two direct
call hops in the selected function's saved analysis. It checks the
linker starts, complete call references, and the encoded `E8 rel32`
destinations against the imported slice. A separate caller must
observe both result registers, and each eligible call must forward
both through a verified return epilogue.

The Java bridge repeats the site and observer checks in a private
copy of the saved Program. It requires each eligible leaf's native
inference to agree on two arguments in `RDI` and `RSI`, a 16-byte
result in `RDX:RAX`, and a common calling convention. It preserves
explicit signatures and checks committed storage and the re-decompiled
parent before returning the selected function. The option is separate
from indirect dispatch recovery and accepted type hints. The result
records its policy, request digest, and applied sites or skip reason.
Receipt replay revalidates the query binding.

## Installed CLI validation

The installed wheel reimported the owned x86_64 O2 calculator and an
independent [two-register observer and control](../analysis/heldout_direct_signatures.c)
under both profiles in both symbol states. The independent fixture was
frozen at `0633fd4` before capturing Ghidra output. An initial compiler
check showed that constant status fields let Clang overwrite `EDX`
after each leaf call. The frozen version uses runtime-dependent
status fields and forwards both registers.

Query selection used binary evidence. Worker access to evaluator
files, source, and earlier projects was denied. The evaluator matched
the frozen captures to source and DWARF after the queries. It compiled
the returned C with the existing versioned compatibility shim. For
each state routine, its closure used the fresh `calc_apply_op`
definition from a separate query and the remaining saved definitions.
The previously archived calculator exports matched the new exports
in instructions, blocks, body ranges, cross-references, signatures,
and cached C.

| Fresh result | Cases per profile and symbol state | Directed per case | Seeded per case |
| --- | ---: | ---: | ---: |
| Calculator `calc_apply_op` | 1 | 4,800 | 10,000 |
| Calculator `calc_engine_input_op` | 1 | 6,252 | 10,000 |
| Calculator `calc_engine_equals` | 1 | 521 | 10,000 |
| Calculator `calc_dispatch_table` with dispatch recovery | 1 | 4,800 | 10,000 |
| Independent two-register observer | 1 | 256 | 10,000 |

All 20 behavior cases passed with zero mismatches. All four
single-register controls returned `missing_two_register_observer`
and matched ordinary fresh output. All 24 receipts replayed. The
original Programs and cached exports retained their hashes.

The following calculator counts apply independently to the stripped
and symbol-bearing inputs. The O2 fresh column combines separate
opt-in queries with the prior passing captures from the same engine.
The O0 rows use the existing captures.

| Optimization | Profile | Cached routines | Cached instruction bytes | Routines with fresh recovery | Instruction bytes with fresh recovery |
| --- | --- | ---: | ---: | ---: | ---: |
| O0 | Baseline | 41/52 | 5,360/8,644 | 41/52 | 5,360/8,644 |
| O0 | Parameter inference | 46/52 | 6,944/8,644 | 46/52 | 6,944/8,644 |
| O2 | Baseline | 48/52 | 3,772/4,269 | 52/52 | 4,269/4,269 |
| O2 | Parameter inference | 51/52 | 4,206/4,269 | 52/52 | 4,269/4,269 |

The O2 x86_64 portion reaches 26/26 routines and 2,053/2,053 bytes
in each profile and symbol state. The O0 all-routine gate remains open.

| Local evidence | SHA-256 |
| --- | --- |
| Installed wheel | `a6f584aff80a638983d32be92c22669e18ea66105f2a5e4805457449a16792d0` |
| Full Ghidra tree | `c390df8cf50fe697a24d548cd23a29d531e72cf065ae3250589cea8157f4c98e` |
| Native decompiler | `0630a5df99cffa2f570db15b891d95f4912cd1c414364b6ffd6f8ecb3f07533d` |
| Independent fixture plan | `e95ea0b6ef466c89b52cc8ad41a112367122bd097ae8d219276b2836ba0c9744` |
| Frozen queries | `bc2469cf4ba81edfec6b91f4735fc715b39f91c78225f6da4b92cc7fffaa2e14` |
| Behavior report | `0de37bfd59b2f69ca25be63bd6bb8cceff4c34ee8fe34a9605e0c80610693989` |
| Combined scope report | `922100b2eb965d76e287b4157eac2c512d143a48d81d1ec95d0d3e0940d2a982` |

The reports are in
`/private/tmp/macscope-direct-signatures.u8pBHz/official`.
