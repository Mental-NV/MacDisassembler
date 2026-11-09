# Indirect dispatch evaluation

The owned calculator uses an indirect call through a selector table.
The experimental evaluator verifies the instruction bytes with LLVM
and follows the on-disk Mach-O chained rebases. It accepts a bounded
linear scan of 16-byte records and a bounded, masked index into an
eight-byte pointer table. The optimized form requires a verified
rebase from the selected slot to a row and another from the row to an
exact linker function start. The guard determines which slots can
be read. The evaluator checks file-backed bounds, read-only-after-fixups
segment flags, and overlapping fixups. Changes to a selector byte, a
callee address, or the failure branch were rejected in separate
mutated copies of the independent fixture.

After export freeze, policy `macscope-ghidra-aggregate-compat/8`
links the printed indirect expression to the captured functions at
those addresses. It checks the decoded call against the captured
computed-call instruction. The emitted lookup keeps the printed index
and arguments and stops on an unverified slot. Policy /8 also preserves
the byte-definedness mask on aggregate field copies and lowers explicit
byte-aligned zero-extension shifts, including a comma assignment inside
a guard. The ordinary CLI continues to report these computed calls
without resolved cross references. The analyzed fixtures are never
executed. The isolated harness executes compiled recovered C and the
reference functions.

## Calculator results

The committed evaluator `5d879dc` was run against the same 16 calculator
exports used for the [vector checkpoint](vector-widths.md). Each dispatch
instance had four verified table slots. Twelve instances passed 4,800
directed and 10,000 seeded cases each, covering both profiles and both
symbol states for arm64 O0, arm64 O2, and x86_64 O0. The four x86_64 O2
instances remain untestable because the capture has a scalar return.

The width-preserving lowering also moved `calc_apply_op` and
`calc_sign_toggle` to full passes on x86_64 baseline O0 in each symbol
state. All previous aggregate passes retained their results. The
aggregate report SHA-256 is
`81606f1fcc17dcc6a362c1b45312bee135f30fc66ad75bdd7797906b57b94e9a`.

The rows below apply independently to symbol-bearing and stripped
exports. Each scored instance completed its declared domain with zero
mismatches. The score combines disjoint calculator cohorts after
checking their export hashes, analysis IDs, and routine identities.

| Optimization | Profile | Routines passed | Instruction bytes passed |
| --- | --- | ---: | ---: |
| O0 | Baseline | 41/52 | 5,360/8,644 |
| O0 | Parameter inference | 46/52 | 6,944/8,644 |
| O2 | Baseline | 47/52 | 3,689/4,269 |
| O2 | Parameter inference | 51/52 | 4,206/4,269 |

Arm64 O2 passed 26/26 routines and 2,216/2,216 instruction bytes in
each profile and symbol state. The x86_64 O2 parameter-inference score
remained 25/26 routines and 1,990/2,053 bytes. The x86_64 O2 baseline
score remained 21/26 routines and 1,473/2,053 bytes. The baseline still
falls below the 90% instruction-byte threshold in each symbol state.

## Independent fixture

The source was frozen in `805b77f`. A preliminary capture informed the
instruction matcher. The evaluator was then committed before the final
capture. LLVM and the rebase parser verified four entries in all 16
captures. The four selector bytes and their table order differ from
the calculator. All recovered-C comparisons hit the blockers below.

| Build | Recovered C outcome |
| --- | --- |
| arm64 O0 | All four captures were ineligible because the evaluator could not establish definedness of a stack value |
| arm64 O2 | Two symbol-bearing captures hit a signed left shift under the undefined-behavior sanitizer. Two stripped captures had partial pseudocode |
| x86_64 O0 | All four captures were ineligible because the evaluator has no binding for the printed `_memset` call |
| x86_64 O2 | All four captures exposed a scalar return |

The frozen capture manifest SHA-256 is
`1e59bc59f4c93a16ef945f31b28055e3bad578052f082d29ff3d22f29f58c0d0`.
The report SHA-256 is
`c17bbb7ea1b92341c04f6298890290654c8ed96c4b0e9c9070c5566eb0eab503`.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis python3 analysis/compare_heldout_aggregates.py \
  --fixture dispatch --ghidra /path/to/experimental-full-ghidra \
  --java-home /path/to/pinned-jdk --output-dir /private/tmp/new-dispatch-evaluation \
  --experimental-trusted-input
```

## x86_64 O2 return diagnostic

The caller reads both `RAX` and `EDX` after calling the dispatcher at
`0x1000006d0`. On the success path the dispatcher returns both registers
from its computed call at `0x100000702`. Its invalid-selector path sets
`EAX` to zero and `EDX` to three. Ghidra independently recovered the
same two-register return storage for all four table targets.

In a disposable copy of the stripped parameter-inference Program,
applying the common callee type at the computed call let Ghidra recover
the full value at that call. The enclosing function still returned
only `RAX`. Supplying the same return type at the enclosing function
made Ghidra print both result fields on both paths. That assisted
output passed 4,800 directed and 10,000 seeded cases separately from the
calculator score. Its report SHA-256 is
`ad43d4f47be741df31886ced1049563d9c1166637797293c6b24e7e68fec1915`.
Automatic return recovery remains open.
