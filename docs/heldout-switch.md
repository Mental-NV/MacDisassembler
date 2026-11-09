# Held-out switch validation contract

This owned command-line fixture is separate from the calculator and is
frozen before changing computed-jump reporting. The six operation values
select distinct unsigned 32-bit calculations. The gaps within the selector
range share a constant-return default. The compiler may emit a table,
comparison tree, or tail calls.

## Freeze and capture

1. Build from the committed `analysis/heldout_switch.c` with Apple Clang,
   `-std=c11 -g -O0` and `-std=c11 -g -O2`, separately for `arm64` and
   `x86_64`. Retain the object from the separate `clang -c` step so
   `dsymutil` can read it after linking. Keep the linked binaries, linker
   maps and matching dSYMs in the evaluator store. Record the commit, source
   hash, compiler/SDK versions, binary UUIDs and slice hashes.
2. Give each analyzer job only its own symbol-bearing or `strip -S -x`
   copy. Verify that stripping preserves `__text` and leaves no
   `_heldout_dispatch` symbol in the stripped copy. Disable DWARF and
   source analyzers. Never send a source-derived address to a discovery
   run. Keep the stripped and symbol-bearing captures separate.
3. Enumerate functions and save the exports before using source, symbols
   from the evaluator copy, or dSYM addresses for evaluation. Use the
   evaluator UUID and independent linker start, LLVM disassembly, and
   table bytes where applicable to identify the dispatcher and its
   reachable case targets. Store addresses and case block evidence with
   each verdict.

## Scoring

For each dispatcher report whether the engine discovered its entry, which
of the six explicit operations and default it covered, and whether a
computed branch has absent or uncertain destinations. A binary-only
report can claim complete pseudocode only if it contains no known missing
reachable path and communicates any unresolved computed jump. A complete
report is not by itself behavioral evidence.

A path whose recovered C depends on an omitted block, a missing switch
target, or manually restored semantics counts as untestable. Never
rewrite pseudocode or supply corrected function types from this fixture
to improve the score. For this control-flow checkpoint the input
executables are data-only and no runtime equivalence claim is made.

Compare against the original owned calculator matrix separately, including
the x86_64 O0 dispatcher and the x86_64 O2 padding case. Preserve the
existing analyzer options and compare raw Program evidence as well as the
CLI coverage status.

## Measured results

The evaluator source was frozen in `c7b16ad` with SHA-256
`9542120fecb68c6cef1d76b7aa8df5c2dc89bf28c4c6c17337cc372b21d52347`.
Apple Clang built the four variants. Each dSYM UUID matched its linked
binary. Stripping removed the dispatcher symbol and preserved the text
bytes. Sixteen headless exports were frozen before evaluator-side address
mapping. The capture sandbox additionally denied reads of the evaluator
source directory and staged alternate binaries. The evaluator dSYMs and
link maps lived under the existing denied home-directory scope.

| Held-out build | Dispatcher entry | Observed reachable paths per capture | CLI pseudocode |
| --- | --- | ---: | --- |
| arm64 O0 | `0x100000424` | 7/7 | Complete |
| arm64 O2 | `0x100000368` | 7/7 | Complete |
| x86_64 O0 | `0x100000410` | 1/7 | Partial |
| x86_64 O2 | `0x1000003a0` | 7/7 | Complete |

Each row covers both profiles and both symbol states. LLVM and the raw
eight-entry signed table showed that the x86_64 O0 jump at `0x100000444`
can reach six case blocks in `0x100000446..0x1000004a6`. The Ghidra CFG
recorded zero destinations for that jump and omitted all six blocks.
The directly reachable default remained present. At x86_64 O2 the
recorded destination set matched all seven distinct table targets.
LLVM comparison branches independently confirmed the seven paths in
each arm64 build.

The original calculator matrix was checked separately. Its x86_64 O0
dispatcher has the same missing-flow pattern at `0x1000007ea`, with four
omitted case blocks. The x86_64 O2 padding difference produced no review
gap. Across 32 archived calculator and held-out captures the CLI kept
the original pseudocode and machine evidence. Cached queries returned
partial for all eight affected captures. Seven fresh checks, including
all four affected held-out captures and one resolved control, matched
the saved code and preserved the source Program and snapshot.
The live calculator matrix passed 152 CLI checks across eight tool and
eight AppKit main images. Both x86_64 O0 AppKit symbol states also
reported the unresolved `calc_apply_op` jump in both profiles. LLVM and
the AppKit table bytes confirmed the corresponding four omitted blocks.
The paired raw machine facets remained equal and the sole analyzer
option difference was the selected parameter-inference setting.

The detector reports unresolved control flow and leaves reconstruction
of those cases open. Ghidra upstream closed a matching regression with
a patch associated with the 12.2.1 milestone. The local result used the
pinned 12.2 engine throughout. [Ghidra regression](https://github.com/NationalSecurityAgency/ghidra/issues/9996) · [Upstream patch](https://github.com/NationalSecurityAgency/ghidra/commit/c93917a622211349998f641de54cfdbe0e0e5bee)

The private capture manifest and evaluation report SHA-256 digests are
`625c9a98c64bfa965319aae1567f27a0dbef0b305e8db231083404e0725412ce`
and `f408a3651b45ea8a72429a2655a55be52b85bc9177e8300da1d250d93428cff4`.
