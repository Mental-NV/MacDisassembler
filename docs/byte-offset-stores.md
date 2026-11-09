# Experimental byte-offset store printer

The fixed-width printer left 20 state cases that failed the alignment
sanitizer. LLVM independently decoded eight-byte stores at byte offsets
`0x24` and `0x2c` in the owned O2 calculator. Examples include
`stur d0, [x0, #0x2c]` at `0x100000a30` on arm64 and
`movq %rax, 0x2c(%rdi)` at `0x100000a90` on x86_64. The
printed C uses an eight-byte typed pointer at those offsets.

The experimental rule recognizes scalar p-code stores with a
same-width pointer cast over an explicit byte displacement that does
not preserve the stored type's alignment. It emits the original
address and value once through `STORE_LE16`, `STORE_LE32`, or
`STORE_LE64`. Policy `macscope-ghidra-aggregate-compat/2` binds
those operations to exact-width little-endian byte copies. The
ordinary C compiler and address and undefined-behavior sanitizers
remain enabled. The rule is limited to little-endian byte-addressed
default memory. It excludes special bit-field printing, non-scalar
pointer targets, explicit volatile varnodes, and other memory operations.

## Reproduce

Start from the source and the full engine of the separate
[fixed-width printer](fixed-width-printer.md). Copy both into a new
scratch directory. Apply the store patch to the copied source.

```sh
printf '%s  %s\n' \
  f71bf7b6c653f648c763b076bf60e9701f1f62528eaf4205d417e5a33af4049d "$trial/cpp/printc.cc" \
  | shasum -a 256 -c -
patch --batch -F0 -p1 -d "$trial/cpp" <analysis/patches/ghidra-12.2-byte-offset-stores.patch
```

Use the fixed-width build procedure to rebuild and replace only the
native executable in the copied engine. Run the calculator tool
matrix with the same bridge and JDK under both engines. Score both
with the three strict calculator evaluators at the same revision.

The independent owned store fixture and its evaluator were frozen in
`4b9c5db`. It covers two routines that mutate caller-owned memory,
return a 64-bit value and 32-bit flags, and exercise null pointers.
Each completed case compares 256 directed and 10,000 seeded inputs
and every byte of the caller's buffer. Select `--fixture stores` in
`analysis/compare_heldout_aggregates.py` and use `--reuse-fixture`
for the second engine. Pass the two resulting directories via
`--heldout-pair` to `analysis/compare_printer_behavior.py` to check
the paired binary, evaluator, sandbox and machine evidence.
