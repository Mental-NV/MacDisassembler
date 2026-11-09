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

## Paired overlap results

A clean build reproduced the byte-range executable with SHA-256
`deec187a2f54c8441b1ad7b26ea284adf9f45d8c6ce423f49dfacceecddff861`.
The original eight cases that mismatched after the store-only change
all passed with the byte-range rule. Twenty-four remained outside the
frozen policy. The reproducer report SHA-256 is
`642a5b728ea2f0bcb6eb159b05bcb3787a03a9141d30973269668e81c1c9f0e9`.

In the separate held-out fixture, the store-only control mismatched
in eight overlap cases and passed eight adjacent cases. The byte-range
candidate passed all 16, with zero mismatches in 164,096 comparisons.
Sixteen cases retained their unsupported verdicts. Each paired fixture
preserved all 56 function records, signatures, instructions, CFGs and
cross references. Each candidate denied the original evaluator root in
all 24 worker policies. The independent report SHA-256 is
`3be953fdd46be32b31bd502b840dc752c7c8a07162c062407f62e566eceacbec`.

The byte-range build also passed all 79 calculator CLI checks. All
664 recovered function records matched the store-printer control,
including byte-identical pseudocode across the 16 paired captures.
The strict behavior rerun passed the same 342 of 416 cases. The
combined report ties the independent held-out capture to the exact
native and full-tree identities used in the calculator matrix. Its
SHA-256 is
`12ba056a64626d07c74b5fa87490ffba49705cb0e5640d373fb3f3bc22646021`.

## Remaining C coverage evidence

Eight O2 state cases still use a 12-byte temporary for a direct
dispatcher call. Four have a captured dispatcher with a 16-byte
return form. The other four print a scalar dispatcher return, so
their aggregate calling convention still needs binary evidence.

The O2 x86_64 formatter prints both a read and a write to
`_DAT_100001700`. The Mach-O places those 16 bytes in the read-only
`__TEXT,__const` section. LLVM identifies the direct reference at
`0x1000008e4` as a `movdqa` load. Supporting the printed
`pshufb` expression alone would leave the apparent store unresolved.
