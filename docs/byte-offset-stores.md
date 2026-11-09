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

## Store-printer results

The store-only native executable reproduced byte for byte from a clean
build. Its SHA-256 is
`5677d32b4776574964069945a71975406cfa49085ea004dc7f87a889d155031e`.
The paired calculator matrix preserved all 664 function records,
signatures, instructions, CFGs and cross references. Both engines
passed all 79 CLI checks.

The store-only candidate moved all 20 alignment failures to full
passes. It passed 342 of 416 calculator routine instances. O2 passed
180 of 208 routine instances (86.5%) and 11,514 of 17,076 instruction
bytes (67.4%). The paired report SHA-256 is
`fb99dc626af44c9f5250aabd32d82361b577378e2791c0d87026121fd01c53b1`.

The independent store fixture exposed a second error. Eight eligible
cases progressed from an alignment failure to completed domains with
9,897 mismatches per case. Twenty-four remained outside the frozen
policy. The mismatch was the returned flag word. The recovered code
reloaded bytes from the original address after writing eight bytes at
offset three. The machine code retained the earlier value. On x86_64
O2, `0x10000034c` loads the value into `rdx`, `0x100000352`
stores at offset three, and `0x100000356` consumes `edx` without
reloading. On arm64 O0, the code saves the initial load to the stack
and reads that saved value after the write.

## Byte-range overlap

Ghidra's `ActionMarkImplied` can inline a load across an intervening
store when it sees different start addresses. Its original check does
not compare the widths of the memory operations. The separate
byte-range patch permits inlining across a same-space store only when
it proves disjointness. It recognizes bounded chains of same-width
copies, casts, and constant offsets. When the load and store share a
base, it compares both circular distances at the address width with
the corresponding access widths. Unknown bases or unsupported address
units preserve the earlier load as a separate value.

The distinct `--fixture store-alias` variation was frozen in
`7362b3d` before changing that analysis. It includes an overlapping
write beginning before the load and an adjacent write beginning just
after the load. The original fixture serves as a reproducer.

Apply `analysis/patches/ghidra-12.2-byte-range-alias.patch` after the
store patch. The original `coreaction.cc` and `coreaction.hh`
SHA-256 digests are
`c41b8f4563591820a8a9904f4b745a631e6470d6484b9967dbe465dc28863876`
and `4d2b5aacd9d6aed0e98036009042a3f7b37f46888c060933105d3c56f6fbf8f2`.
