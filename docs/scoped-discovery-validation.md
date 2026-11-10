# Scoped class discovery validation

Validated 10 November 2026 against the Stage A implementation based on main
`6bc177d2312f31a5448c0a02b9b007f13c9e21fd`. All 249 baseline tracked file blobs
were compared with that main commit before development in a separate checkout.

This records source validation, not an installed CLI upgrade. See the
[reconciled plan](scoped-investigation-plan.md) for the acceptance contract and
the remaining B, C and D stages.

## Results by acceptance ID

- **A1, passed:** Real Apple-clang-linked chained arm64 and x86_64 dylibs each
  have 12,032 unrelated fixups before their class-list slot and class metadata.
  The class slot is fixup rank 12,032 and the name-pointer site rank 12,035
  (zero-based). Apple `dyld_info` reports 12,046 total fixups in each image.
  Filtered public CLI class queries complete with one matching declaration.
  Two selected method implementation addresses per architecture agree with
  both `nm` and `dyld_info -objc`. The general fixup inventory remains partial
  at its unchanged 10,000-record cap. No header patching or lowered limits are
  used for this integration.
- **A2, passed:** Tests distinguish complete no-match from empty partial,
  exhaustion and a verified match plus an unresolved candidate. Partial
  totals stay unknown, including after filtering and pagination.
- **A3, passed:** Tests reject misaligned/non-file-backed slots, inconsistent
  section mapping, ambiguous file-backed or zero-file mapping overlaps,
  corrupt relevant chained pages, unsupported pointer/legacy encodings and
  external class bindings. Existing cached-page per-slot validation and
  failure-retention regressions still pass. A missing optional superclass
  does not discard an independently verified class name.
  A subsequent safety review extended the proof to every consumed scalar and
  string byte, including NUL terminators, and to raw/legacy exact-slot queries
  with predecoded relocations. Required-field overlaps yield partial/no rows;
  optional-superclass overlaps retain the verified class and partial methods.
  Unrelated, empty and boundary-touching virtual segments remain harmless.
- **A4, passed:** Instrumented tests cover repeated class entries, shared
  slots, same-page cache hits, eviction/re-decoding, failed pages, late classes,
  and exhaustion before/after a verified class. A test reaches the actual
  262,144 attempted-node ceiling with production limits unchanged, asserting
  exactly that many decoder calls and zero published rows from failed pages.
  A separate test reaches the real 2,048-slot ceiling. Pointer, node, page and
  cache counters/limits are exposed through diagnostic strings.
- **A5, passed:** The list/string envelope remains schema-valid. Deterministic
  paging/replay, changed-filter and changed-image cursor rejection,
  image/architecture ambiguity, text/JSON output, and complete/partial legacy
  class-slot behavior are covered. Tests fingerprint saved project files and
  forbid process creation during metadata queries. The Apple integration
  uses a loaded-process audit guard for every public CLI invocation.
- **A6, passed:** True-zero, zero-partial, some-partial and filtered-empty
  partial results provide distinct explanations. Concrete advice uses an
  actual class-list slot, never a class-object address. A merely mapped slot
  is not asserted to identify a matching class. Manual fallback pins the same
  slice hash and architecture. Metadata commands do not invoke Apple tools.
- **A7, source/package checks passed; installed parity deferred:** 527 primary
  tests and 106 analysis tests passed in the cloud checkout. The final Mac
  rerun passed both integrations and 69 focused ObjC/dyld/mapping tests.
  The final cloud focused set passed 69 tests. All 66 runtime/source
  wheel members matched their source bytes. Installed-wheel execution parity
  is deliberately deferred; no installed command was replaced.

Independent review found and then cleared raw/legacy zero-file mapping
ambiguity, unsupported-legacy diagnostic classification, and a filtered-empty
candidate-slot guidance gap. A later PR safety review identified inherited
exact-slot and non-pointer byte-range gaps; the follow-up includes owned
raw, legacy and chained negative cases plus optional-superclass positive cases.
Independent re-review cleared that follow-up, repeated the public CLI repros
and all test suites, and checked 536,250 interval reads against a byte-wise
reference implementation.
No bridge, engine trust or isolation behavior was changed.

## Reproduce

From the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis python3 -m unittest discover -s analysis/tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests python3 -m unittest test_objc test_dyld test_macho_view -v
```

The Apple oracle is explicitly opt-in and requires a new output directory
under canonical `/tmp`:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/integration_owned_discovery.py \
  --output-dir /tmp/macscope-owned-discovery-run
```

The integration compiles project-owned dylibs and never executes them. It
prepares metadata-only test projects through the existing storage APIs; this
is not a Ghidra engine import or a whole-image analysis. Every acceptance
query then runs through `python -m macscope`. Apple tools are invoked by the
test harness separately. Generated binaries, Apple output and CLI captures
remain outside Git. If an architecture fails, the runner exits and any later
architecture is unrun; inspect the saved report and error output rather than
assuming both passed.

The final Apple host ran macOS 27.0.1, Apple clang 21.0.0 and Python 3.14.6.

## Tested source identity

The final Mac and cloud runtime source identity is:

`9d544a67c828a04f1d4dd80b7d89b4ff4eac49841fa540593546393661a41071`

This is SHA-256 of compact, key-sorted JSON mapping each repository-relative
`src/` file with extension `.py`, `.java` or `.json` to its SHA-256, excluding
`__pycache__`. It includes all 66 packaged runtime files. The built wheel
SHA-256 was:

`7f4c374efbcfbbc45df260fa6fa9a2aac3288db1b332fa87523d335a40774223`

## Remaining limits

- Legacy discovery beyond the general fixup inventory cap remains partial.
- Class discovery covers selected class-list declarations, not runtime
  dispatch, inheritance, categories or other images.
- Page-cache occupancy and page-query limits remain explicit additional
  bounds. Pagination cannot make a partial discovery exhaustive.
- Installed CLI parity and installation remain deferred. Linux engine
  enablement, generic flow-gap evidence, the new resource-first focused
  workflow and focused-query benchmarking were not performed by Stage A.
