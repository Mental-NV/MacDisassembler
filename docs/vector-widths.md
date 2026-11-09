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

The frozen /6 mask run exposed a C lowering error. A vector assignment
pattern also matched the tail of a scalar cast such as
`*(long *)*param_1 = value`. Policy /7 requires the whole vector
lvalue at the beginning of the statement and preserves the scalar
store. The /7 replay of the original Arm fixture passed eight live
Arm vector cases. The /7 replay of the frozen mask captures passed
all eight immutable x86_64 O2 cases on the candidate, compared with
zero on the control. Four live Arm cases passed on each engine.
These replays are regression checks on already observed outputs.

The native mask pairing preserved the recovered code of all eight
x86_64 writable controls. Its paired SHA-256 report is
`8e4c34b291bc63d62ee8a438b2ef33934e102ba6ca19c04428b2344c9b425186`.
The /7 mask candidate replay report SHA-256 is
`eb6860d243ffc020e802511ef69490560f279a3832b7c857cdd39ce691a221be`.

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
Use the corresponding committed evaluator revision when reproducing a
historical comparison. The corrected vector-store rules and the new
`--fixture vector-slices` source were frozen in `63a726f`.
The new fixture passed all eight arm64 O2 cases with zero mismatches
over 82,048 comparisons. Each passed output executes both `REV64`
and `EXT`, using two distinct input vectors and checking the whole
caller buffer. The 24 other cases remained outside the policy because
of external linkage or unsupported emitted forms, including
`pblendw` and `CONCAT44` on x86_64. The frozen report SHA-256 is
`9adb238d38876eeeb43c0c6b864b0ec6a3a97e28a87626739dcbdc508fbc4284`.

## Calculator scores by evidence condition

The clean rebuild reproduced native SHA-256
`15a0f6359c078a84f552411bc19cacd08b6357a62653fee1c6b50b805de9d4f6`.
The full candidate tree SHA-256 is
`5ad3fc87fca82a0b53a7da264cb83907b635e7bb8c0d7d4e42250e2c5462c143`.
Comparing 5,442 files and symlink targets found only the native
executable changed. The candidate passed 79 calculator tool CLI
checks. All 16 paired captures preserved the 664 function records,
signatures, machine instructions, CFGs and references. The four
x86_64 O2 captures changed the formatter and the entry function's
printed C. Each of the four formatters passed 1,005 directed and
10,000 seeded tests.

| Blind input condition | Profile | O2 routines passed | O2 instruction bytes passed | O0 routines passed |
| --- | --- | ---: | ---: | ---: |
| Binary only | Baseline | 46 / 52 (88.5%) | 3,597 / 4,269 (84.3%) | 37 / 52 |
| Binary only | Parameter inference | 50 / 52 (96.2%) | 4,114 / 4,269 (96.4%) | 44 / 52 |
| Embedded symbols | Baseline | 46 / 52 (88.5%) | 3,597 / 4,269 (84.3%) | 37 / 52 |
| Embedded symbols | Parameter inference | 50 / 52 (96.2%) | 4,114 / 4,269 (96.4%) | 44 / 52 |

The parameter-inference O2 score also meets both 90% thresholds on
each architecture within each symbol state. Arm64 passed 25 of 26
routines and 2,124 of 2,216 bytes. x86_64 passed 25 of 26 routines
and 1,990 of 2,053 bytes. All completed domains had zero mismatches.
The only O2 routine outside this profile's testable domain on either
architecture was the indirect dispatcher. The baseline and the
complete O0 behavior requirement remain below their gates.

The paired calculator report SHA-256 is
`c14f316bedc6c1f1ec07bd012ec22faf75360261bfa04576893dabbc17330dbf`.
