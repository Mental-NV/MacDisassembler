# Aggregate widths and vectorized formatting

## Declared widths

Four read-only queries on disposable copies of the saved O2 Programs
captured high p-code for both architectures and both profiles. The
original Program digests matched before and after each query. The
12-byte caller result splits into an eight-byte value at offset zero and
a four-byte status at offset eight. For example, the arm64 baseline
`calc_engine_equals` call at `0x100000bc0` writes a 12-byte value,
and the following `SUBPIECE` operations select those two fields.
The query manifest SHA-256 is
`1c895b03cf576c845efd00e8078b1ee391fcc17fbf7d665b8d0b10760b734306`.

Compatibility policy `macscope-ghidra-aggregate-compat/3` supports
explicit 12-byte and 16-byte declarations, enforces their byte bounds,
and tracks definedness when a wider aggregate is assigned to a
12-byte local. The evaluator still uses each captured callee's
declaration. A printed scalar call cannot satisfy an aggregate
assignment. This distinction added four O2 state passes and preserved
the compiler failures when the callee lacked an aggregate result.

The independent `--fixture return-width` source and evaluator were
frozen in `0abf0a4`. It passed 28 of 32 routine instances, including
all four that use a 12-byte temporary. Four roots had incompatible
arity. Its report SHA-256 is
`ea7d6429cce87d790fe26a421c0b7b8970ed939248e909d94fb43d7b859e0058`.

## Vector operations

Policy /4 adds the 16-byte, one-byte-lane forms of Arm `REV64` and
`EXT` and preserves the definedness of each selected byte. It compiles
the complete recovered formatter, including the vector path. The
64-bit decimal input domain exercises the scalar path because the
digit count stays below the vector path's threshold. The separate Arm
fixture places both vector operations on its live path. [Arm Neon
Intrinsics Reference](https://arm-software.github.io/acle/neon_intrinsics/advsimd.html)

Policy /5 adds explicit pointer-to-16-byte-array parameters and the
128-bit form of `PSHUFB`. The low nibble selects an input byte, and
the high bit selects a defined zero. Known-width vector copies use
byte transfers. The separate `--fixture vector-mix` source and
evaluator were frozen in `eb58198`. All eight x86_64 O2 cases executed
the printed shuffle and passed. The 24 other cases were outside that
version's intrinsic or external linkage rules. Its report SHA-256 is
`625cfb0e31b5e43bd37fc0a81c0d069a5be0c494718636936a5397af2f2692ff`.
[Intel instruction set reference](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf)

## Read-only spans and return addresses

The x86_64 formatter's shuffle mask is in `__TEXT,__const`. Its only
direct machine reference is a load. High p-code shows an apparent
global write introduced by merge and indirect markers. A diagnostic
build found the read-only property cached for one byte of the
16-byte location. The candidate resolves the missing byte properties
before using Ghidra's existing extended-constant representation.
It requires the whole span to be read-only and nonvolatile and
preserves the existing treatment of written varnodes.

Policy /6 binds the printed synthetic x86_64 return address only
when it matches the end of a decoded direct `CALL`, the call's
stub is a RIP-relative indirect jump, and that slot binds to the
verified libSystem stack-check failure import. The recovered stack
assignment and failure call both remain in the compiled expression.
The stack-check stub fixture evidence gives call `0x100000964`,
return PC `0x100000969`, stub `0x1000016ec` and bind slot
`0x100002078` in both symbol states. Policy /6 also binds
`ZEXT412` as the printed four-to-twelve-byte zero extension.

## Reproduce

Start with the source and engine used for
[byte-range alias handling](byte-offset-stores.md#byte-range-overlap).
The original `funcdata_varnode.cc` SHA-256 is
`79ca4fcb6d5a8675779162d9e8b9fb7fc106c6ba27f937f8ae26c13ed1bda090`.
Apply `analysis/patches/ghidra-12.2-readonly-vector-spans.patch`
in a separate scratch tree and rebuild the native engine. The
independent `--fixture readonly-shuffle` source and /6 evaluator
were frozen in `db6785f`. Use the first run's frozen input directory
with `--reuse-fixture` for the candidate, then pass both runs
through the paired verifier alongside the calculator reports.
