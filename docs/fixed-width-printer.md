# Experimental fixed-width C printer

The recovered-C audit found that ordinary signed arithmetic in printed
expressions can overflow before the printed overflow checks execute.
Ghidra's p-code for integer add, subtract, multiply and two's-complement
negation computes a value at the recorded operation width. The
experimental printer renders an eligible signed 32-bit or 64-bit
expression using unsigned arithmetic at that width, then converts back
to its selected signed type. This final conversion uses the tested Apple
Clang two's-complement behavior. Each operand is emitted once.

The patch uses the p-code opcode, operand and result widths, and C
expression types. It excludes pointers, enums, narrower and wider
expressions, and non-C output. It also suppresses the compound-assignment
shortcut when that shortcut would skip the explicit conversions. It
preserves expression grouping, prototypes, checked-arithmetic intrinsics and
the compatibility evaluator unchanged. There is no process-wide
signed-wrap compiler option.

## Build and evaluate

Start with the source and full-engine control prepared for the
[upstream switch patch evaluation](heldout-switch.md#upstream-patch-evaluation).
The two original printer source files must match the recorded 12.2
digests. Build in a separate scratch tree and replace only the native
decompiler in a copy of the full control engine.

```sh
trial=$(mktemp -d /private/tmp/macscope-fixed-width.XXXXXX)
control=/private/tmp/completed-switch-experiment
native=Ghidra/Features/Decompiler/os/mac_arm_64/decompile
cp -pR "$control/cpp" "$trial/cpp"
printf '%s  %s\n' \
  65264c9a35daa2168a6318ffc361c1a92ce755f4a8608ebcd40eee2f0012418f "$trial/cpp/printc.cc" \
  b10782066c5a941204a7c71304872084a7e229e4e10a23afdf90bfeb8ddbc95d "$trial/cpp/printc.hh" \
  | shasum -a 256 -c -
patch --batch -F0 -p1 -d "$trial/cpp" <analysis/patches/ghidra-12.2-fixed-width-c.patch
(
  cd "$trial/cpp"
  MACOSX_DEPLOYMENT_TARGET=14.0 make -j8 ghidra_opt \
    ARCH_TYPE='-arch arm64' ADDITIONAL_FLAGS='-w' CXX='/usr/bin/clang++ -std=c++14'
)
cp -pR "$control/engine-patched" "$trial/engine-modulo"
install -m 755 "$trial/cpp/ghidra_opt" "$trial/engine-modulo/$native"
codesign --verify "$trial/engine-modulo/$native"
```

Run the calculator tool profile matrix under each engine with the same
bridge and JDK. Run the three strict [core evaluators](semantics.md#recovered-core-behavior)
on each matrix. Pair the matrices and the three reports with
`analysis/compare_printer_behavior.py`. It verifies capture and engine
identities, unchanged machine evidence and signatures, matching
evaluator contracts and stable instruction-byte denominators.

For the independent check, select `--fixture arithmetic` with
`analysis/compare_heldout_aggregates.py`. The source, compatibility
rules and harness were frozen in `71a2c70` before the native experiment.
The second run accepts `--reuse-fixture` with the first run's scratch
directory so both engines analyze identical binaries. The source
varies the earlier aggregate fixture with wrapping arithmetic and
checked 32-bit and 64-bit operations.

## Build and capture evidence

A clean rebuild from the installed 12.2 source reproduced the
experimental executable byte for byte. Comparing 5,442 file digests
and symlink targets across the two engine trees found one difference,
the native decompiler.

| Engine | Native SHA-256 | Full tree SHA-256 |
| --- | --- | --- |
| Upstream switch-patch control | `ca2b9cca5de09246dd545627cceeda80d2314101c0ad1212e40323cb8ce72bae` | `f185534bf8b3cef92df7f369370f1487b44d321e69516c49ce0d4c592fd28cae` |
| Fixed-width printer | `2cd9d1237597accfc25d01bc445450fafd23e3f017ddf3587a962cfd01bb2ff0` | `271ebac500e1ed001c7f879cc4c89f5ca06ac8aedecfc405671e04321c84df1f` |

Both calculator tool matrices passed 79 CLI checks, including saved
and fresh pseudocode queries. Across 16 matched captures, all 664
function records retained their signatures, cross references,
instructions and CFGs. Pseudocode changed in 330 records. One earlier
attempt shared a writable candidate tree between two jobs. A transient
tree digest difference caused a typed fresh-query refusal. The completed
matrices used independent copies. The source of the transient tree
change is unresolved.

## Held-out result

Both engines analyzed the same eight input files across both profiles.
All 16 paired exports preserved the full inventory of 56 function
instances, signatures, cross references, instructions and CFGs.
Thirty-two pseudocode records changed.
All 24 candidate worker policies denied both evaluator roots. A direct
worker-policy check could read the staged Mach-O and was denied access
to both evaluator source copies.

The 16 packet cases all failed the control run with signed multiplication
overflow. All 16 passed with the experimental printer, completing
164,096 directed and seeded comparisons with zero mismatches. The
checked routine stayed outside the frozen compatibility rules in all 16
cases because its `SCARRY4` intrinsic has no binding in that policy.

The paired report SHA-256 is
`c7e1fee5092207f232e541e13d9e64cf35f0822869a10119a03362883e58f703`.
The control and candidate behavior report digests are
`53561be3371ab19172c7ab4cc23654a8a403ca91a946ddcc31e46209d26bd1cb`
and `18c7c75c12f55d39b40a48e477020e41366b216276276ed95de2ff70a71c8b38`.

## Calculator behavior

The first state calibration exposed a missing `ulong` typedef in its C
harness. Its scanner already accepted that type and the aggregate,
scalar and history harnesses already declared it. Both engines were
rescored with the same typedef. The recovered code, directed cases,
seeded inputs and sanitizer settings were preserved.

| Cohort | Engine | Primary domains complete | Full pass | Primary domain bytes | Full-pass bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| All 416 instances | Control | 218 | 202 | 19,352 / 51,652 | 17,756 / 51,652 |
| All 416 instances | Fixed-width printer | 322 | 322 | 31,454 / 51,652 | 31,454 / 51,652 |
| O2, 208 instances | Control | 126 | 118 | 6,452 / 17,076 | 5,996 / 17,076 |
| O2, 208 instances | Fixed-width printer | 160 | 160 | 8,748 / 17,076 | 8,748 / 17,076 |

The printer moved 104 primary sanitizer failures and 16 wide-counter
failures to full passes. That includes all 88 prior aggregate overflow
failures. No verdict regressed and no completed domain had a mismatch.
The 20 remaining sanitizer failures are misaligned stores in the
recovered state routines. Another 18 cases fail compilation and 56
remain outside the compatibility policy. O2 integer formatting accounts
for 3,108 of the 8,328 unpassed instruction bytes. The other gaps
include state aggregate subfields, indirect dispatch linkage, and
ambiguous aggregate division. The 90% O2 gate remains open for both
routine instances and instruction bytes.

The paired calculator report SHA-256 is
`4f1bbd512a9d60bc222267322e587c97a95b0825b059eb990b28a66b9a36ee3b`.
