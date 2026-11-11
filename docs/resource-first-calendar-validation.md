# Stage C validation record

Validated 11 November 2026 (UTC). All inputs are the independently authored
owned Calendar fixture. The binaries and compiled nibs were read statically;
no application was executed and no nib was instantiated. No third-party app
analysis, installation, Linux worker, or whole-image autoanalysis was performed.

The [workflow](resource-first-calendar-workflow.md) describes the exact scope.
The base is merged main `68b29441e757eb19652ec05abcb120ac53166e69`, tree
`c16d31cdd4381dbe583dc3ef170c5892f5080b21`.

## Source identity and checks

The runtime is unchanged from the reviewed Stage B source:
`0e3a72e7722fd21a0283a951522b32f3ebe129010539d9d865774c757e5ccf42`.
This is SHA-256 of compact, key-sorted JSON mapping repository-relative `src/`
Python/Java/JSON paths to their SHA-256 values, excluding bytecode.

Exact live harness SHA-256:
`4bbf6416a3803cc119f380fa22345057885b59389acb0751c4a461a5e0b0d459`.
Exact live byte-oracle SHA-256:
`abd4ec8508219185550a8204d33055b4fc4f7396f06b850f92dcf16a1c9cf30f`.
Fixture Objective-C SHA-256:
`ddd9980e6d627d08b70c43c597554940e219a1ca1ed04685fd504c8703a9e43b`.
Fixture XIB SHA-256:
`f1b560caa5059264fb67e8a403d368f6e2c748e689e9047a602cd28789f630c6`.

The final six-file fixture/harness/oracle/unit-test fingerprint is
`e524b8c8773537aeebc65b9964e4e0284ebb6c6590dab31921e731db05036645`,
using the same compact path-to-SHA-256 mapping format. Unit tests canonicalize
their temporary directories so macOS `/var` symlink aliases do not conflict
with the existing product path restrictions. No product restriction changed.

Final cloud source checks passed:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python3 -m unittest discover -s tests -q
# 619 tests
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis \
  python3 -m unittest discover -s analysis/tests -q
# 106 tests
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests python3 -m unittest \
  test_resource_first_workflow test_resource_first_oracle -q
# 17 tests, a subset of the primary suite
```

The 17 tests also passed on the Mac with canonical temporary paths. They cover
wrong receiver/value/ivar/selector/bind evidence, altered branch/store patterns,
missing/inserted instructions, incomplete and inconsistent nib wiring,
whole-image-command rejection, existing-capture reuse, preserved incomplete
captures, independent architecture failures, and deterministic escaped HTML.

The dependency-free wheel builder produced the unchanged
`macscope-0.2.0-py3-none-any.whl`, SHA-256
`bc942a233e4b743b6720fefb03bee86d84a4a1c8c35ddae52d565946941b43ff`.
All 69 packaged runtime members matched source bytes. No wheel was installed.
`git diff --check` passed.

Independent review identified three weaknesses in the first harness: labels
without exact nib endpoint agreement, mnemonic checks without dataflow proof,
and losing the other architecture's outcome after an early failure. The final
candidate fixes all three. Independent rereview found no actionable issues.
Live compilation additionally established the actual NSCustomView/ibtool class
representation and reversed ibtool action direction; the oracle checks those
exact representations rather than weakening the assertion.

## Live dual-architecture result

The existing host/toolchain was macOS 27.0.1 arm64, Apple clang 21.0.0,
Python 3.14.6, Ghidra 12.2, JDK 25.0.5.0.3 and bridge 1.15.0. Ghidra tree digest:
`72b7d1c417bf822927ba839647d1cc85268a165e9680e06781fa5f54ba1e9dbc`.
Bridge source digest:
`547c3b210c669312c4f7ca2de94280bb98d875d0e40daea7d6ddcd3a31c6c776`.
No dependency was installed or updated.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
MACSCOPE_GHIDRA="$GHIDRA" MACSCOPE_JAVA_HOME="$JDK" \
python3 tests/integration_resource_first_calendar.py \
  --output-dir "$ARTIFACTS/reviewed-validation" --arch both
```

The exact reviewed harness and byte oracle passed without further patches.
Each architecture was compiled and imported independently. Each project has
one import and three focused query jobs, no active analysis and no whole-image
analysis. Public `status --verify-programs` subsequently verified the actual
saved import Program with Ghidra/JDK paths unavailable; analysis remained
`not_analyzed` on each architecture.

| Selected function | arm64 | x86_64 |
| --- | --- | --- |
| Load/hide request | Partial | Partial |
| Conditional state change | Complete | Partial |
| Caller-supplied dispatch | Partial | Partial |

Partial outcomes are expected evidence, not suppressed failures. On x86_64 the
state method's selected instructions and pseudocode are present; undecoded
linker padding keeps coverage partial. The dispatch gaps retain raw warnings
and unclassified computed transfers. The load request remains partial despite
the independently verified local selector/argument effect.

The independently reviewed owned instructions establish:

- **arm64 load:** load row at self offset 8 into x0, set w2 to 1, branch to
  the setHidden: selector stub. Its actual selector slot and objc_msgSend
  binding are verified from the saved slice.
- **arm64 change:** preserve self in x19, request state on the sender,
  load configuration at offset 24, compare x0 with that value, branch on
  equality over `str x0,[x19,#24]`.
- **x86_64 load:** load row at self offset 8 into rdi, load the setHidden:
  selector into rsi, set edx to 1, and dispatch through the verified GOT slot.
- **x86_64 change:** preserve self in rbx, request state on sender, compare
  rax with the eight-byte value at self offset 24, and use `je +4` to skip
  `mov rax,24(rbx)` on equality.

These are bounded request/local-write conclusions, not resolved runtime
message implementations, UI reachability, permanent invisibility, persistence,
geometry, or whole-function semantic equivalence.

## Pinned artifacts and replay

Final immutable input SHA-256 values:

- arm64: `0e1daed9a074727705531779f34c8fc6a9cefa66815d54ae88c6b25d272d92ab`.
- x86_64: `df691dd76d8cac4618c801729bdc95769dd80344247387859391112db2c50f0c`.

Final imported Program digests:

- arm64: `ccf4fd35bdeadd6cded55d0fe5a561dd74a983ca19b45d6dc4ce2243e0096ba1`.
- x86_64: `c63b06b40ff31e862985bf4839aacd27631ec0010feab6fb39373057821fe411`.

A separate repeat of the command with `--replay` and nonexistent engine/JDK
paths passed on both architectures. The original app path was absent. Saved
nib and strings bytes were reparsed, metadata regenerated, and focused receipts
and the byte oracle revalidated against immutable saved slices. No extra job
was created, receipts remained unchanged, and owner-only JSON/HTML reproduced
byte for byte. The immutable saved inputs and Programs were retained.

Final normalized report hashes:

| Architecture | JSON SHA-256 | HTML SHA-256 |
| --- | --- | --- |
| arm64 | `c8e188e8f0eec275898df57bd56fa857d0d7834eede0e132440a5f87adef50fa` | `79bb7ba4ddba04257802bb1b66cc7d110ae50910addd4b762cff7bf80e17e691` |
| x86_64 | `ec048b89cd156712d64cbe72ebb46be72cf1f2d9d765660bfb4cac4f8c641ad3` | `124f239465c5a9aaa0abb3d5a55f6c165a63119b1f43ccd7e2bf402214eefb24` |

Generated binaries, raw Apple output, receipts, reports, context and summary
remain in the private owned validation directory outside Git. No recovered
output is committed with this record.

## Acceptance and deferred work

- **C1 passed on both:** compiled nib connections agree with the owned XIB and
  ibtool class/type/endpoint evidence, with no visibility claim from wiring.
- **C2 passed on both:** exact selected functions, independent Apple instruction
  review, bounded byte/selector/ivar proofs, no whole-image analysis, and
  retained partial/unresolved transfer evidence.
- **C3 passed on both:** handoffs separate facts, bounded inferences and unknowns.
  No runtime oracle or third-party conclusion is asserted.
- **C4 passed on both:** original app path absent and engine/JDK unavailable;
  saved resources and focused receipts reproduce pinned private JSON/HTML.

Stage D measurements and any subsequent batch specification remain unrun.
Linux worker enablement and installed CLI execution parity remain deliberately
deferred. This test-only stage makes no broader optimizer or UI claim.
