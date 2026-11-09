# Wide signed division and unsigned range guards

The x86_64 O2 baseline prints the signed path of `calc_div` as an
infix division with a byte-array operand. LLVM decodes `idivq` at
`0x1000005b2`. Ghidra's high p-code retains `INT_SDIV` with two
16-byte operands and a 16-byte result. The same routine contains a
separate unsigned division. [Dispatch return evidence](dispatch-tables.md#automatic-recovery-on-saved-programs)

The C printer emits `SDIV16` only when a 16-byte signed division
has a byte-array operand. It retains both expressions and their order.
Compatibility policy `macscope-ghidra-aggregate-compat/9` accepts the
explicit operation and checks aggregate byte definedness before signed
division. The earlier ambiguous infix form remains outside the shim's
division rules.

The independent fixture and evaluator were frozen in `750c1ad`.
The fixture uses a dividend whose high word is independent of the
low word's sign bit. Its directed cases include the extremes of both
signed operands. Its second routine checks ordinary unsigned division.

The division-only engine made all four independent x86_64 O2 signed
cases compile. The harness then caught a separate overflow in their
range guard. The saved high p-code adds a signed 64-bit value to an
unsigned 64-bit constant and compares the sum as unsigned. The C
printer emitted `param_2 + 1U < 3`, which C evaluates with a signed
64-bit addition. The second patch renders both operands with an
unsigned 64-bit type when a small unsigned literal would otherwise
lose its width. The signed division and guard patches were committed
separately in `80bb2fc` and `73a8af1`.

## Build a separate full engine

Start with the full engine and native source from the
[vector checkpoint](vector-widths.md#calculator-scores-by-evidence-condition).
The two original printer files must match the recorded hashes. Apply
the patches in order and install the rebuilt native decompiler into a
copy of the full engine.

```sh
set -e
trial=$(mktemp -d /private/tmp/macscope-wide-division.XXXXXX)
control=/private/tmp/completed-vector-checkpoint
native=Ghidra/Features/Decompiler/os/mac_arm_64/decompile
cp -pR "$control/cpp" "$trial/cpp"
printf '%s  %s\n' \
  24140458307947a3e7f3919c9438a5f0e278b9705f1f0f8d0d96d04603ca4fb4 "$trial/cpp/printc.cc" \
  2349287e9dad1323a5227e5b8d106e0049d1a7b0cb1182ff83a18ca9b29fcf52 "$trial/cpp/printc.hh" \
  | shasum -a 256 -c -
patch --batch -F0 -p1 -d "$trial/cpp" < analysis/patches/ghidra-12.2-wide-signed-division.patch
printf '%s  %s\n' fbc36402853af5f7c40d2633054f8aff50cd2cbbdf4e822719466684ec88f4d3 \
  "$trial/cpp/printc.cc" | shasum -a 256 -c -
patch --batch -F0 -p1 -d "$trial/cpp" < analysis/patches/ghidra-12.2-wide-unsigned-literal.patch
if [ -d "$trial/cpp/ghi_opt" ]; then
  mv "$trial/cpp/ghi_opt" "$trial/control-objects"
fi
(
  cd "$trial/cpp"
  MACOSX_DEPLOYMENT_TARGET=14.0 make -j8 ghidra_opt \
    ARCH_TYPE='-arch arm64' ADDITIONAL_FLAGS='-w' CXX='/usr/bin/clang++ -std=c++14'
)
cp -pR "$control/engine-final" "$trial/engine-candidate"
install -m 755 "$trial/cpp/ghidra_opt" "$trial/engine-candidate/$native"
codesign --verify "$trial/engine-candidate/$native"
```

Select `--fixture division` in
`analysis/compare_heldout_aggregates.py`. Capture the control first and
pass its output with `--reuse-fixture` for the candidate. Both runs
require the explicit owned-input flag. The candidate worker cannot
read either evaluator root.

## Paired evidence

The control and final candidate trees matched across 5,442 file and
symlink paths except for the native decompiler. The candidate native
SHA-256 is
`0630a5df99cffa2f570db15b891d95f4912cd1c414364b6ffd6f8ecb3f07533d`.
The full candidate engine SHA-256 is
`c390df8cf50fe697a24d548cd23a29d531e72cf065ae3250589cea8157f4c98e`.

Both engines passed all 79 calculator tool CLI checks. Sixteen paired
exports preserved all 664 function records, signatures, instructions,
CFGs, references and analysis options. The final candidate changed the
printed C in eight O0 formatter instances and two x86_64 O2 baseline
division instances.

All four independent x86_64 O2 signed cases passed 256 directed and
10,000 seeded comparisons each with zero mismatches. The eight unsigned
instances that passed before the changes still passed. Twenty other
independent instances remained outside the compatibility contract.
One export in the first control run reported a different full-engine
digest. The final pair reran both sides on dedicated read-only engine
copies. The independent and calculator captures then matched the exact
full-engine identities on each side.
The independent candidate report SHA-256 is
`fd9bdef0aa3f67a7b41077cb984f3171a098c8da5800b7a7d608b9556aee88b3`.
The combined paired report SHA-256 is
`9dd842eb494beb2fe50f4f2c447a40ab879806fc761eddc4bb31808128895e69`.

Both x86_64 O2 baseline `calc_div` instances passed 400 directed and
10,000 seeded cases. The paired calculator report records only those
two verdict changes. Every previously passing routine retained its
verdict. The calculator report SHA-256 is
`6bc88e99f71b92ff090a766a9ca4cf421a03253059cf11df70f025fc9e03e86b`.

The actual CLI then recovered the dispatch return against the candidate
engine for both profiles in both symbol states. Each fresh query passed
4,800 directed and 10,000 seeded cases. The saved Programs and snapshots
retained their original hashes. The query behavior report SHA-256 is
`5aa1a6aff6dae1a427cc9cb28edef687beb0cf8090e978a4b7744fd95a0808de`.

The table applies separately to stripped and symbol-bearing inputs.
All scored domains had zero mismatches.

| Optimization | Profile | Cached routines | Cached instruction bytes | Routines with fresh dispatch | Instruction bytes with fresh dispatch |
| --- | --- | ---: | ---: | ---: | ---: |
| O0 | Baseline | 41/52 | 5,360/8,644 | 41/52 | 5,360/8,644 |
| O0 | Parameter inference | 46/52 | 6,944/8,644 | 46/52 | 6,944/8,644 |
| O2 | Baseline | 48/52 | 3,772/4,269 | 49/52 | 3,835/4,269 |
| O2 | Parameter inference | 51/52 | 4,206/4,269 | 52/52 | 4,269/4,269 |

The baseline O2 score with fresh dispatch remains eight instruction
bytes short of 90%. The combined scope report SHA-256 is
`94e50100fce3e09b7de85133f3c50e1d441316312d3a508e27056fb27fd977ec`.

## Direct-call diagnostic

In a disposable copy of the x86_64 O2 baseline Program, Ghidra inferred
two arguments and the same two-register result for the two direct
callees of `calc_apply_op`. Committing those existing inferred
signatures made Ghidra print both result fields in the caller, without a
separate return hint on the caller. LLVM shows the caller's result is
consumed from both `RAX` and `EDX`. The assisted C passed 4,800 directed
and 10,000 seeded cases with zero mismatches. It remains separate from
the scored outputs. The diagnostic report SHA-256 is
`3d25b9f6206a4b7ddcaed8e55a0119f140a01d7ed5437d480bf37c1fc06b5b8d`.

Using that same diagnostic definition in the recovered closures also
made `calc_engine_input_op` pass 6,252 directed and 10,000 seeded cases
and `calc_engine_equals` pass 521 directed and 10,000 seeded cases. Both
completed with zero mismatches. These assisted results share the same
open signature requirement. Their report SHA-256 is
`d05ae6ea88f30a06eddd40851230456a4ffd037575c1baf558a61d3d5bb53f77`.
