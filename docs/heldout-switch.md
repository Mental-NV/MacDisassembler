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

The later installed-wheel check at `9aadc9f` reimported the owned
stripped x86_64 O0 calculator under the exact default Ghidra 12.2
tree. Both cached and fresh `calc_apply_op` queries returned exit 6
and identical computed-jump gaps. The `calc_add` control completed.
The fresh report SHA-256 is
`549adf0697691c9c0cd375fcf7549e22d93e99091f50bea5f1dc8b1c202da28e`.

## Upstream patch evaluation

The published Ghidra releases still showed 12.2 as the latest release
on 9 November 2026. We rebuilt the installed 12.2 native decompiler
twice with Apple Clang 21 on arm64, with the same C++14, O2 and macOS
14.0 deployment settings. The patched build replaced only the upstream
`RuleRangeMeld` source hunk. Each native binary went into a separate
complete copy of the installed distribution. We compared all other file
digests and symlink targets against the installed tree. Both copies
passed the headless bridge contract under their own engine digests.
[Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases) · [Upstream patch](https://github.com/NationalSecurityAgency/ghidra/commit/c93917a622211349998f641de54cfdbe0e0e5bee)

| Engine component | SHA-256 |
| --- | --- |
| Installed 12.2 native decompiler | `bbbe0c16cb5446ab6c338faa28f777a3d923e30cfd5546fab661ccf51c95f6cb` |
| Rebuilt unpatched native decompiler | `7431d1c2bcbee96ebc87438fe341d365aaafe86039bc58116cae743a6af13433` |
| Rebuilt patched native decompiler | `ca2b9cca5de09246dd545627cceeda80d2314101c0ad1212e40323cb8ce72bae` |
| Rebuilt unpatched full tree | `cb6bede0c713fe5f0efff9451d0d46ac0d858f08f0883d3f90d84d3d07171442` |
| Rebuilt patched full tree | `f185534bf8b3cef92df7f369370f1487b44d321e69516c49ce0d4c592fd28cae` |

- The rebuilt unpatched control reproduced all six missing x86_64 O0
  case paths in four held-out captures. All 16 patched held-out
  captures retained the six cases and default. Both x86_64 builds
  matched the full independently decoded jump-table destination set.
- The patched calculator matrix passed 151 CLI checks across 16 owned
  tool and AppKit images. Both profiles and symbol states recovered
  four omitted case blocks per x86_64 O0 image, with all five distinct
  table targets in the CFG. The other 24 profile captures served as
  controls. The DWARF tool comparison matched 536 entries and 532
  exact byte extents. The four remaining differences were the same
  eight bytes of x86_64 O2 alignment padding.
- Eight fresh calculator dispatcher queries matched their cached
  pseudocode and preserved the saved Programs and snapshots. A fresh
  query from the unpatched tree against a patched snapshot received
  the typed `query_engine_mismatch` error.
- Comparing the installed and patched calculator runs preserved the
  complete entry inventory and effective options. All body range,
  instruction, and CFG differences were in the eight recovered
  dispatcher records. The patch also changed eight signatures and
  22 pseudocode records outside those dispatchers. This experiment
  measures reachability and printed output. Behavioral equivalence
  remains a separate gate.

Private report digests, in the order held-out A/B, calculator matrix,
paired calculator comparison, and calculator discovery, are
`45c597ac9911814f662a0f993d662f22409fcca2668f16736fad3a1ed34f396e`,
`600da3d34a4f547ea0609683f7cb5398ed88d93d54ff5eec89b4bfd332207779`,
`0a4ecfc82d77d14d8b85432f6a6dccd3330a9dbbefb11df624c9f32e72fec6c4`,
and `00a1302d3cbd486d9f9d094f0158629274e5663c752806578da72ef04a3189a7`.

### Reproduce the private build

Use a new directory under canonical `/private/tmp`. The recipe keeps the
upstream source and rebuilt binaries in scratch space. The expected
download SHA-256 is checked before copying it into the build.

```sh
experiment=$(mktemp -d /private/tmp/macscope-switch-patch.XXXXXX)
(
  set -eu
  installed=/opt/homebrew/opt/ghidra/libexec
  source_dir=Ghidra/Features/Decompiler/src/decompile/cpp
  native=Ghidra/Features/Decompiler/os/mac_arm_64/decompile
  upstream=c93917a622211349998f641de54cfdbe0e0e5bee
  curl --fail --silent --show-error --location \
    "https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/$upstream/$source_dir/ruleaction.cc" \
    -o "$experiment/ruleaction.upstream.cc"
  printf '%s  %s\n' \
    ad428d347b0f955366392d4e3c361b7ec3caab0cc9d9cc991913865644cb3efe "$experiment/ruleaction.upstream.cc" \
    e9ea936f305309f888fbbe72649e3a6f45cfbe76a06187484a3fba6efa899dac "$installed/$source_dir/ruleaction.cc" \
    | shasum -a 256 -c -
  cp -pR "$installed/$source_dir" "$experiment/cpp"
  cd "$experiment/cpp"
  for variant in original patched; do
    if [ "$variant" = patched ]; then cp "$experiment/ruleaction.upstream.cc" ruleaction.cc; fi
    MACOSX_DEPLOYMENT_TARGET=14.0 make -j4 ghidra_opt \
      ARCH_TYPE='-arch arm64' ADDITIONAL_FLAGS='-w' CXX='/usr/bin/clang++ -std=c++14'
    cp -cpR "$installed" "$experiment/engine-$variant"
    install -m 755 ghidra_opt "$experiment/engine-$variant/$native"
    codesign --verify "$experiment/engine-$variant/$native"
  done
)
```

Run `doctor --full-digest --ghidra "$experiment/engine-patched"`. Select
that same full tree with `--ghidra` for import, analyze and fresh queries
in a new private workspace. Cached queries use the committed snapshot.
The default engine and existing projects keep their original identity.

## Recovered C behavior

The evaluator matched all seven source routines to the frozen captures by
dSYM UUID and linker-confirmed entry address. It compiled the emitted bodies
and declarations as printed, with generic integer typedefs. The dispatcher
linked against the six recovered helpers from the same capture. The harness
used the printed parameter types and compared the 32-bit return bits against
the frozen unsigned reference. It treated sanitizer failures as failed
comparisons.

Every completed helper test covered 121 directed and 10,000 seeded input
pairs. Dispatcher tests were configured for 1,452 directed cases across all
operations and defaults, plus 10,000 seeded cases.

| Routine | Outcomes across 20 captures |
| --- | --- |
| `combine_xor`, `combine_mul`, `combine_max`, `combine_rot` | All 80 outputs passed 809,680 comparisons in total, with zero mismatches. |
| `combine_add`, `combine_sub` | All 40 outputs triggered signed-overflow diagnostics on valid unsigned inputs. |
| `heldout_dispatch` | Four unpatched x86_64 O0 outputs had incomplete control flow. Two patched arm64 O0 baseline outputs failed compilation. Fourteen compiled outputs triggered signed overflow in a recovered helper. |

The two arm64 O0 baseline dispatchers emitted three arguments for helpers
whose recovered declarations accepted two. The parameter-inference profile
allowed those dispatchers to compile. The restored jump targets therefore
establish reachability, while the full recovered dispatcher behavior gate
remains open. These runs executed the generated comparison harness as
native arm64 C.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 analysis/compare_heldout_switch.py \
  --comparison /private/tmp/completed-patch-comparison \
  --evaluator /path/to/owned/heldout-evaluator \
  --inputs /private/tmp/frozen-heldout-inputs \
  --output-dir /private/tmp/new-heldout-behavior \
  --experimental-trusted-input
```

The comparison directory contains the 20 frozen exports and their A/B
report. The evaluator directory contains the linked files and matching
dSYMs. The input directory contains the captured symbol-bearing and stripped
slices. The runner verifies their text and identity before any comparison.
The measured behavior report SHA-256 is
`a743ffead583bc0e6018fb7a21817dbbf7b746516ee525886b9adb40f2f476f8`.
