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
