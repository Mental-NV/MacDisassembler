# Experimental binary-derived parameter inference

This is an explicit alternate analysis profile, not a change to baseline's
analyzer configuration or a semantic-correctness guarantee. It is implemented
on an isolated local branch, with no automatic profile selection or fallback.

## Use and provenance

```sh
PYTHONPATH=src python3 -m macscope analyze --project /path/to/private-project \
  --profile parameter-inference --experimental-trusted-input --json
```

The production implementation is generic: it enables Ghidra 12.2's
`Decompiler Parameter ID` analyzer and contains no calculator-name-specific
parameter logic or call-text rewrites. Source, DWARF/PDB, external-library and
demangler analyzers remain disabled. Embedded names in symbol-bearing
binaries are still available. No source prototype is supplied.

The versioned identity is `parameter-inference/1` and Program marker is
`macscope-binary-only-parameters/1`. Requested configuration, applied marker,
effective options and bridge/dependency hashes are recorded. Profile mismatch,
missing option evidence, or an enabled source analyzer rejects publication.
The alternate profile changes inferred signatures, parameter/return types and
calling-convention labels throughout the Program; these may be wrong.

Every fresh analysis clones the no-analysis import. Returning to baseline
cannot inherit parameter commits from the inferred Program. Baseline is still
the default. New metadata and canonical xref ordering change serialized
exports; this does not promise byte-for-byte compatibility across builds.

## Measured checkpoint, 9 November 2026

All **16 fixture pairs / 149 public CLI command checks passed** on the pinned
macOS arm64, Ghidra 12.2 and JDK 25.0.5.0.3 environment. Inputs are schema-2
manifest-verified v1.1 fixtures: arm64/x86_64 × O0/O2 × symbol-bearing/stripped
× AppKit app main/command-line tool. The source manifest records an earlier
revision plus its dirty-state and exact source-file hashes; it must not be
mistaken for a clean tagged build.

There were 1,581 compared function records per profile across the matrix,
including externals/thunks, and 933 complete pseudocode records per profile.
All paired entry sets, names, body ranges, instructions, CFGs and decompile
statuses were unchanged. This is an explicit set of measured fields, not
a statement that every export field or every possible function is unchanged.
The only effective analyzer-option delta was `Decompiler Parameter ID`,
from `false` to `true`.

| Fixture case | Function records | Complete pseudocode | Changed signatures | Changed pseudocode |
| --- | ---: | ---: | ---: | ---: |
| DebugAnalysis-arm64-sym-app | 171 | 112 | 111 | 91 |
| DebugAnalysis-arm64-sym-tool | 44 | 36 | 36 | 15 |
| DebugAnalysis-arm64-stripped-app | 171 | 112 | 111 | 91 |
| DebugAnalysis-arm64-stripped-tool | 44 | 36 | 36 | 15 |
| DebugAnalysis-x86_64-sym-app | 115 | 56 | 55 | 32 |
| DebugAnalysis-x86_64-sym-tool | 44 | 36 | 36 | 13 |
| DebugAnalysis-x86_64-stripped-app | 115 | 56 | 55 | 32 |
| DebugAnalysis-x86_64-stripped-tool | 44 | 36 | 36 | 13 |
| ReleaseAnalysis-arm64-sym-app | 197 | 110 | 109 | 85 |
| ReleaseAnalysis-arm64-sym-tool | 39 | 31 | 31 | 6 |
| ReleaseAnalysis-arm64-stripped-app | 198 | 111 | 110 | 85 |
| ReleaseAnalysis-arm64-stripped-tool | 39 | 31 | 31 | 6 |
| ReleaseAnalysis-x86_64-sym-app | 141 | 54 | 53 | 30 |
| ReleaseAnalysis-x86_64-sym-tool | 39 | 31 | 31 | 9 |
| ReleaseAnalysis-x86_64-stripped-app | 141 | 54 | 53 | 30 |
| ReleaseAnalysis-x86_64-stripped-tool | 39 | 31 | 31 | 9 |

Each case passed cached-pseudocode parity, exact baseline snapshot restoration,
and unchanged input/import-Program digests. The two O0 symbol-bearing tools
also passed exact repeated-inference snapshot comparison and actual reopened
engine queries with saved-profile inheritance, `-readOnly -noanalysis`, and
unchanged source Program digests. Repeat-inference equality was **not** tested
on all 16 cases. A separate offline inventory check found complete function
enumeration, no global analysis timeout/output budget hit and no bridge errors
in all 50 captured exports. Thirty-eight analyze/export results per command
type are still `partial` because an outgoing-xref collection reaches its
documented cap. No measured pseudocode, instruction or CFG facet was partial;
the test does not claim complete cross-reference coverage.

The known arm64 O0 three-argument call to the two-argument error-latching
callee was reproduced in both symbol-bearing app/tool baselines. The alternate
profile produced the expected two-argument call and invalid-digit guard.
This is a source-aware exact regression sentinel, not a general proof that
all argument counts, stripped functions or recovered behavior are correct.
Many other bodies and inferred signatures changed; x86_64 output includes
calling-convention labels such as `__stdcall` that remain unvalidated.

Additional checks:
- 146 engine-free CLI/storage/process/profile tests passed.
- 53 engine-free research tests passed.
- Existing 69-command baseline CLI integration passed, including thin/fat64
  slice parity for both architectures and the production read-only query.
- Four-run arm64 O0 research smoke passed: default, whole-program inference,
  callee-only inference and repeat. An independent offline re-summary exactly
  matched its recorded summary. This is a new smoke check, not a rerun of the
  historical ten-run experiment.

### Repeatability defect found during validation

The first profile-matrix attempt stopped correctly when snapshot publication
detected different output for an identical baseline identity. Two incoming
references differed only in iteration order. Normalization now canonically
sorts both unordered xref arrays and retains duplicates. A regression test
covers reversed order, equality and non-mutation of the input arrays.
The failed private trial remains intact; the complete matrix used a fresh
output directory. No analyzer change was needed for this fix.

## Independent validation follow-up

The original matrix comparison accepted identical truncated function subsets
because it received the function rows and options without the bridge's
inventory metadata. A truncated copy of a saved export reproduced the false
pass. The profile matrix and prototype comparison now require complete
function enumeration with consistent counts, no global analysis timeout or
output cap, and no bridge errors. Unrelated partial facets such as capped
references remain allowed.

An offline replay passed for all 50 saved CLI exports and reproduced the
comparisons for all 16 profile pairs. The saved ten-run prototype experiment
and four-run smoke test also reproduced their summaries. This replay used
existing Ghidra outputs.

A fresh LLVM comparison checked the eight v1.1 command-line tool baselines.
Whole-section LLVM disassembly crossed zero padding into two stripped
x86_64 functions, misaligning their first instructions. The addresses
`0x100001a90` (O0, also the Mach-O entry point) and `0x100000e20` (O2)
both appear in the Mach-O function-start table. Re-decoding the affected
ranges with LLVM's `--start-address` and `--stop-address` resolved both
discrepancies. Across the eight exports, 268 Ghidra-selected function records,
12,336 instructions and 2,582 direct targets agreed. The default
live validator now reproduces the two bounded re-decodes automatically.
The eight-input check passed through its CLI, with exactly those two retries
and zero unmeasured direct targets.

## Recovered scalar behavior calibration

The fixed harness covers `calc_compare_s64` and `calc_compare_u64`. It used
16 unmodified recovered functions from the owned symbol-bearing tool exports,
covering both profiles, arm64/x86_64 and O0/O2. Each was compiled as native
arm64 C on macOS with Apple Clang 21 and undefined-behavior checks. The
compiler and test executable ran in bounded, network-denied workspaces.

All 16 candidates compiled and ran. Each matched the manifest-verified
reference on 121 directed pairs and 10,000 seeded pairs, with zero mismatches
across 161,936 comparisons. Comparison uses the 32-bit return representation
and covers less-than, equality and greater-than. A fixed shim supplies the
printer's scalar typedefs. The harness preserves the candidate text and
requires the declared argument signedness and width.

This is a source-aware calibration of two functions. It does not score
aggregate returns, pointer operations, state transitions, stripped inputs,
or execution under the x86_64 ABI. The broader behavior and blind gates
remain open.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 analysis/recovered_compare.py \
  --fixture-build-root /path/to/owned/build/review-v2 \
  --profile-matrix /private/tmp/completed-profile-matrix \
  --output-dir /private/tmp/new-recovered-scalar-check \
  --experimental-trusted-input
```

The private report records all candidates and compiler and input provenance.
The measured report SHA-256 is
`e02a8b1de70ffada60dddae9293d4998d746030c0c019b4e45ab37ae49ac7cc3`.

## Evaluator-side discovery measurement

The evaluator matched the build manifest, dSYM UUID, symbol-bearing and
stripped text bytes, and each captured input and analysis identity. It took
concrete, contiguous DWARF subprogram ranges in `__TEXT,__text` with an
independent Mach-O linker function start. It compared those ranges against
the complete captured inventory of nonexternal, nonthunk functions by
address. The two optimized dSYMs each contained 43 abstract or declaration
records without a concrete range. No other records were excluded.

Across 16 tool captures (two profiles, two architectures, O0/O2, with and
without symbols), all 536 expected entries were present. There were no
extra in-body or outside-cohort candidates. Exact, unadjudicated byte
extents matched in 528 cases.

| Architecture and build | Exact extents per capture | Byte-level adjudication |
| --- | ---: | --- |
| arm64 O0 | 36/36 | Complete agreement |
| arm64 O2 | 31/31 | Complete agreement |
| x86_64 O0 | 35/36 | `calc_apply_op` omitted 88 bytes, including four reachable case blocks. LLVM disassembly and the six signed table entries independently confirm the four targets and the repeated default target. |
| x86_64 O2 | 30/31 | `corpus_stats_over_points` omitted a single eight-byte alignment NOP at `0x100000fc8`, immediately after an unconditional jump. |

The strict O0 body gate remains open on x86_64. The O2 discrepancy is
padding. These results cover the owned tool cohort and do not establish
held-out precision or behavior. Both Ghidra profiles reported complete
pseudocode for the x86_64 O0 dispatcher despite the missing case blocks.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 analysis/score_discovery.py \
  --fixture-build-root /path/to/owned/build/review-v2 \
  --profile-matrix /private/tmp/completed-profile-matrix \
  --output /private/tmp/new-discovery-score.json
```

The measured report SHA-256 is
`74b9b59c55f8bc69a53fbc94aa515285dfc579ee47ea53c4a838717a9bd7edfb`.

## Reproduce and inspect

See [CLI instructions](cli.md#experimental-binary-derived-parameter-inference)
for the matrix command and [the earlier research review](decompiler-review.md)
for the callee-only experiment. The new production profile does not expose
manual prototype injection or the targeted callee-only operation.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s analysis/tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/integration_profiles.py \
  --fixture-build-root /path/to/owned/build/review-v2 \
  --output-dir /private/tmp/new-profile-matrix \
  --experimental-trusted-input
```

The compact [measured checkpoint](evidence/parameter-profile-20261109.json)
records input, source, implementation and report hashes. Full logs, saved
Programs and recovered outputs remain private and are not checked into Git.
The historical checkpoint remains unchanged and has its own code revision.

Broader recovered-C comparisons, held-out scoring, broader
ObjC/Swift/third-party coverage, UI acceptance and stronger input isolation
remain open. The engine remains experimental for explicitly trusted, owned
inputs. Its sandbox is not a complete hostile-input boundary.
