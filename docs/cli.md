# macscope CLI 0.2.0 (experimental)

The narrow CLI uses **full Ghidra 12.2 headless**, its Mach-O loader and
analyzers, and its native decompiler. It does not use Hopper, REA, PyGhidra,
paid engines, a remote model, or a replacement instruction lifter.

This is an initial phase-2 implementation, **not a release for hostile or
untrusted binaries**. Ghidra operations require an explicit
`--experimental-trusted-input` flag. Validation uses only this repository's
source-known calculator. No analyzed input is executed.

## Install without third-party Python dependencies

Tested: macOS 27.0.1 arm64, Python 3.14.6, full Ghidra 12.2,
Homebrew OpenJDK 25.0.5.0.3. Python metadata requires 3.12+, but other
Python/OS/host combinations have not been verified. Engine/JDK are
independently installed; `doctor` never installs, downloads or changes them.
No license has been selected and no upstream engine files are bundled.

```sh
mkdir -p dist
python3 -c 'import macscope_build; print(macscope_build.build_wheel("dist"))'
python3 -m venv build/macscope-env
build/macscope-env/bin/python -m pip install --no-index --no-deps \
  dist/macscope-0.2.0-py3-none-any.whl
build/macscope-env/bin/macscope doctor --json
```

For source checkout use `PYTHONPATH=src python3 -m macscope ...`.
`MACSCOPE_GHIDRA` / `--ghidra` and `MACSCOPE_JAVA_HOME` / `--java-home`
select exact independent dependency locations. They do not relax version or
native-component checks. Defaults match the pinned development machine:
`/opt/homebrew/opt/ghidra/libexec` and the installed Homebrew JDK 25.0.5.0.3.
The wheel is pure Python plus project-owned Java bridge source and JSON
schemas, with zero third-party Python runtime/build dependencies.

## Verify the local engine

`doctor` checks the selected Ghidra release, launcher and key JAR class
headers, and verifies that the native decompiler and selected Java
components have arm64 Mach-O headers. It checks the exact JDK build by
starting `java -version`. An incompatible component or a conflicting
Java override produces a typed dependency error. `--full-digest` also
hashes the complete selected Ghidra tree.

```sh
macscope doctor --verify-worker --experimental-trusted-input --json
```

The opt-in probe generates a two-instruction Mach-O in a temporary private
workspace. It checks import, analysis, saved disassembly, and the native
pseudocode from a reopened Program. It includes the full engine digest and
removes the temporary workspace on exit. The report distinguishes this
live verification from dependency preflight. For all worker jobs, the
runner verifies the Java home, build and architecture reported by the
bridge before publishing a result. The runtime record lives in the
private job manifest.

The installed wheel passed the live probe on stock Ghidra and the
separately selected experimental full engine. Five dependency faults
returned typed errors, including a wrong-architecture native decompiler
that was rejected before job creation. A host-native replacement passed
the Mach-O preflight and failed the live protocol check during analysis.
The validation report SHA-256 is
`231a06a52d6af526dc51dc2bf259d66f5034389bdab282b74618e3d474e85906`.
Ordinary imports, analyses, and fresh queries on owned arm64 and x86_64
targets recorded the same selected arm64 JVM in all six job manifests.
Both fresh receipts replayed and cached results from the preceding
bridge remained readable. The job report SHA-256 is
`61a552dc5b9fc3ec507f1e04bed84d723f6888b4eb75613276963884d874e234`.

## Implemented commands

All commands have `--help`; unknown flags are errors. Data goes to stdout,
errors also have a short stderr diagnostic. `--format text|json|jsonl`,
`--json`, `--output FILE`, and `--force` are supported as applicable.
Text currently renders escaped, indented JSON, not a polished terminal view.
JSONL collection records each have the complete versioned envelope.
Successful `--output` writes only the file, not a duplicate stdout response.

```sh
macscope --version
macscope version --json
macscope doctor --json --full-digest
macscope inspect path/to/CalculatorFixture.app --json
macscope bundle list path/to/CalculatorFixture.app --kind images --json
macscope project create workspaces/calculator
macscope import path/to/CorpusFixture --project workspaces/calculator \
  --arch arm64 --experimental-trusted-input --json
macscope import path/to/CalculatorFixture.app --project workspaces/calculator \
  --include-images 'Contents/Frameworks/Example.framework/Example' \
  --arch all --experimental-trusted-input --json
macscope analyze --project workspaces/calculator --profile baseline \
  --experimental-trusted-input --timeout 300 --json
macscope functions list --project workspaces/calculator --limit 100 --json
macscope functions show --project workspaces/calculator --name _calc_add --json
macscope disasm --project workspaces/calculator --name _calc_add --json
macscope decompile --project workspaces/calculator --name _calc_add --json
macscope decompile --project workspaces/calculator --name _calc_add --fresh \
  --experimental-trusted-input --json
macscope decompile --project workspaces/calculator --all --limit 1000 --json
macscope xrefs --project workspaces/calculator --name _calc_add --direction both --json
macscope xrefs --project workspaces/calculator --to 0x100000510 --json
macscope cfg --project workspaces/calculator --name _calc_add --format dot
macscope search calc_add --in all --project workspaces/calculator --json
macscope calls --name _calc_add --direction callers --depth 2 --project workspaces/calculator --json
macscope status --project workspaces/calculator --json
macscope jobs list --project workspaces/calculator --json
macscope headers --project workspaces/calculator --json
macscope sections --project workspaces/calculator --name-contains text --json
macscope imports --project workspaces/calculator --json
macscope exports --source dyld --project workspaces/calculator --json
macscope strings --project workspaces/calculator --min-length 8 --json
macscope fixups --project workspaces/calculator --kind bind --json
macscope objc methods --project workspaces/calculator --name-contains press --json
macscope swift symbols --project workspaces/calculator --json
macscope export --project workspaces/calculator --json --output private-results.json
```

A project parent directory must exist. Project creation is private mode0700
and refuses an existing path. For a universal input import requires explicit
`--arch arm64|x86_64|all`; it extracts each chosen slice before invoking
Ghidra. Reimporting an already imported immutable identity is idempotent.
An image operation requires a unique `--image ID` and/or `--arch` when the
workspace has multiple images. A function selector accepts one of
`--name EXACT`, `--function-id ID`, `--address 0xUNSLID_VA`, `--rva 0xRVA`, or
`--file-offset 0xOFFSET`. Duplicate names return candidates. Address-based
selectors identify **function entries**.

`--rva` is relative to the Mach-O's preferred image base. `--file-offset`
is relative to the selected Mach-O slice, including in a universal
binary. A function offset must map to one file-backed section and a
saved entry. Both selectors reject a disagreement between the Mach-O
and recorded Ghidra image bases. All three address forms use hexadecimal
numbers.

Use `disasm --range START:END` to read committed Ghidra instructions
across function boundaries. Both addresses are unslid hexadecimal VAs
and the end is exclusive. A range covers 1 to 4,096 bytes and selects
one imported image. It uses its own selector in place of a single-function
selector.

```sh
macscope disasm --project workspaces/calculator --arch x86_64 \
  --range 0x100000510:0x100000552 --json
```

The result lists whole saved instructions in address order and reports
their function IDs. Identical records from overlapping functions appear
once. Missing records, conflicting decodes, and instructions cut by a
range boundary are separate gap reasons. Gap ends are exclusive. A range
with gaps exits 6 and reports the number of covered and requested bytes.
An unmapped range yields an empty instruction list with a gap. Use `bytes`
for file-backed bytes whether or not Ghidra decoded them. Range queries
read a committed snapshot and start no worker.

The installed wheel verified 27 ranges across six stock Ghidra captures
of the owned O0 calculator tool, covering both thin architectures and
symbol states and both slices of a symbol-bearing universal binary. All
534 returned instruction addresses and 2,013 bytes matched LLVM and the
original slices. The x86_64 range that crossed two functions reported the
intervening padding gap. The unresolved switch reported its missing case
range. The universal queries matched their thin counterparts after
remapping image and function identities and container offsets. Exports
stayed byte-identical and no range query created a worker job. The report
SHA-256 is `464079202b7bbe8c5aed15db6655b66c80acc6ae5bab73f6b924377d56df3c4d`.

`functions list --name-contains TEXT` is a literal filter. Collection cursors
bind to project, full analysis ID, filter and sort order. Changing any of
these rejects the cursor. Pagination coverage distinguishes page truncation
from global discovery truncation. `--all` means bounded engine-recognized
functions, not every possible routine in the binary.

`search QUERY` matches a literal, case-insensitive query of up to 256 printable
characters against the selected committed image. `--in names` covers
function and symbol names, `--in strings` covers Ghidra-defined strings,
`--in pseudocode` covers saved decompiler text, and `--in comments` covers
current user comments. The default `all` searches all four scopes.
Each matching source record returns one bounded excerpt
with image identity, engine address when available, and a function ID when
the record identifies a function. Pseudocode addresses identify the function
entry. Use `--limit` and `--cursor` to page through the hits. A partial source
facet yields partial coverage even when there are no matches. Search uses
the saved evidence and requires no engine startup.

`xrefs --to 0xVA` and `xrefs --from 0xVA` select a single unslid address.
They read the committed image-wide reference capture, which includes data
and Ghidra external-entry markers alongside code references. Each row keeps
Ghidra's reference type, source and operand index where available. Targets
reported for computed control flow are labeled `indirect_or_inferred`.
When a saved computed call or jump has no reported target, `--from` emits
its instruction evidence with a null target. These rows describe static
Ghidra evidence.

Use `--limit` and `--cursor` to page an address query. When the saved
capture is complete, an empty list means Ghidra recorded no references
in that direction at the address. Older snapshots and capped captures
reuse available function samples and return partial coverage. The
function-selector form retains `--direction to|from|both`. Both forms
use committed evidence without starting a worker.

The installed wheel checked 32 address queries on owned arm64 and x86_64
executables against separate exact queries on read-only Ghidra Program
copies. All 34 returned reference records matched, including references
from a data pointer and external-entry markers. LLVM confirmed the direct
and indirect call sites. Reanalysis reproduced each snapshot. All 32
queries also matched on the corresponding universal slices.

On the stripped x86_64 O0 calculator, the image capture included every
reference sampled by the function views. The stock unresolved switch
still reported a null jump target. A separate owned fixture reached the
16,000-record cap and returned paged evidence with partial coverage and an
unknown total.

| Report | SHA-256 |
| --- | --- |
| Exact-address and legacy-snapshot checks | `7d9b615c7cfcd4365e86dfc04d806c35d344759f90dc7a74c78e5df4705825e7` |
| Universal slice parity | `47ebc7a7216aeee32b8826d0089b167c00cd81a69951f767ebcf32da274ed51f` |
| Reference capture limit | `3daedd252d12e970ab676bd5858b21757cb547a57fc5f198bb35b5d9eb2c97c5` |
| Stripped calculator reanalysis | `7e6518ece15b1ed34ac650164d04732214f6904035ee687611f0d4760a8ecfb5` |

`calls` follows recorded direct call references breadth-first, by function
entry, with `--direction callers|callees|both` and `--depth 1..8`. The default
is both directions at depth 1. The graph reports the instruction address,
reported target and resolution on each edge. It preserves indirect calls and
inferred target hints without traversing them. Incoming references with
ambiguous or unavailable instruction ownership retain an unresolved caller.
Depth defines the requested scope. A reached `--max-edges` bound (default 500,
maximum 2000) or incomplete scanned facets produces partial coverage. Call
traversal uses the selected snapshot and does not enumerate runtime targets.

## User labels and comments

```sh
macscope rename 'Checked addition' --name _calc_add --project workspaces/calculator --json
macscope comment set 'Review the overflow path' --name 'Checked addition' \
  --project workspaces/calculator --json
macscope comment list --project workspaces/calculator --json
macscope annotations history --name _calc_add --project workspaces/calculator --json
```

Labels are separate from Ghidra names. Both can select a function, subject
to the usual ambiguity check. Comments can target a function or a saved
instruction via `--instruction 0xVA`. Use `rename --clear` or
`comment remove` to append a removal revision. Repeating the same edit is
idempotent. Each revision records its author label, time, prior value,
creation analysis ID, and exact image/function scope.

These edits update the private SQLite index and preserve input bytes,
saved Programs and committed analysis snapshots. They follow the same
immutable image and engine entry across analyses. Default exports omit
annotations. Use `export --include-annotations` to include current records
as a separate field. History retains edits and removals and supports
`--limit` and `--cursor`. Search and annotation cursors that depend on labels
or comments are tied to the annotation revision.

Use the dedicated private transfer format to preserve the full history
including removed values, author labels, timestamps, original analysis
IDs, and original workspace/revision identities. It keeps text verbatim.

```sh
macscope annotations export --project workspaces/calculator \
  --json --output private-annotations.json
macscope annotations import private-annotations.json \
  --project workspaces/second-calculator --accept-type-hints --json
```

The destination must have the same imported image and a committed
analysis whose functions and instructions match the active annotations.
Import appends the missing history in one transaction, assigning local
revision numbers. Replaying an existing prefix makes no edits. Diverging
histories, invalid targets and malformed files are rejected before any
revision is written. Importing type-hint revisions requires the explicit
`--accept-type-hints` flag. The transfer file is limited to 64 MiB.

`type set --return-type TYPE --accept` records a user-supplied return type
for a selected function. Supported types are `void`, `bool`, and the signed
and unsigned fixed-width integer typedefs from 8 to 64 bits. Invalid types
leave existing revisions intact. Use `type list` to inspect current hints
and `type clear --accept` to remove one.

```sh
macscope type set --name _calc_add --return-type uint64_t --accept \
  --project workspaces/calculator --json
macscope decompile --name _calc_add --fresh --with-type-hints \
  --project workspaces/calculator --experimental-trusted-input --json
```

The explicit hint view applies accepted types to the private Program copy
inside a rolled-back Ghidra transaction. It uses a distinct identity and
reports applied revisions and resolved types. The hint view always starts a
fresh worker and leaves the unassisted cached analysis available separately.
The owned arm64 and x86_64 tests verified changed hinted output and unchanged
original Programs and snapshots. This first hint workflow covers return types.

## Input preflight

`bundle list APP` inventories physical files by relative path. `--kind images`
selects Mach-O candidates and identifies the main executable named by
`Info.plist`. `--kind resources` selects regular non-image files. Records
include byte size and SHA-256 when hashing completes. The default `all`
also lists symlinks and special files as metadata. The scan follows physical
directories, including versioned framework directories, without traversing
symlinks or mount boundaries.

Inventory is bounded to 10,000 scanned entries, depth 16, 256 MiB per file
and 512 MiB of hashing. Read or budget gaps are partial. Pagination rescans
the selected scope and rejects a cursor when the inventory changes.
Header candidates can be checked with `inspect` before import.

Bundle import includes the main executable by default. Repeat
`--include-images PATH` to add exact bundle-relative image paths or use
`--include-images all` for the complete physical image inventory. Relative
framework links are resolved through the bundle's own directory descriptors.
Escaping, absolute, cyclic, and over-limit links are rejected. The result
records each canonical relative path and keeps the ordinary immutable image
identity. Selection is limited to 64 images and 512 MiB in aggregate.

A universal image still requires an explicit architecture selection. The
selected architecture applies to every image in the import. A failure after
an earlier image has been committed reports partial completion and the failed
bundle path. Repeating an import reuses an already imported identity.

`inspect` is a bounded stdlib preflight for thin/fat/fat64 little-endian
64-bit arm64, arm64e and x86_64 executable/dylib/bundle images. It resolves a main
`.app/Contents/Info.plist` executable and reports companion debug dylibs.
Ordinary input paths open each component without following symlinks.
Encrypted images, x86_64h, other CPU subtypes, 32-bit images, relocatable
objects and malformed ranges receive explicit failures. The arm64e path
is data-only. Engine import supports ordinary arm64 and x86_64. The
preflight is **not** a complete Mach-O/dyld parser or a security proof.
Select the ordinary slice explicitly when a universal input also contains
arm64e. An all-slices import requires every slice to support engine import.

## Persistence, identity and freshness

`headers`, `segments`, and `sections` query imported Mach-O metadata and
work before analysis. Older imports can recover the added header and segment
fields from their digest-verified slice. The `loader` record includes
`LC_MAIN`, the preferred image base, dylib paths and versions, rpaths,
symbol table ranges, linkedit payload ranges, function starts, and
data-in-code entries. An incomplete decoded table makes the header result
partial. Dyld stream, export trie, chained fixup and signature ranges are
recorded as extents.

`exports --source dyld` reads declared exports directly from the
digest-verified slice, including before analysis. It accepts modern
`LC_DYLD_EXPORTS_TRIE` and legacy dyld-info export extents. It reports
regular, weak, absolute, thread-local, re-export, and stub/resolver records
with raw flags and slice/container offsets. Thread-local addresses refer
to the image descriptor. Re-exports preserve the library ordinal, declared
path and import name, with no resolved runtime address. Absent evidence,
unsupported flags and traversal limits receive partial coverage. Malformed
tries and conflicting extents produce typed errors. Use `--name-contains`,
`--limit` and `--cursor`. The default `--source ghidra` reads the existing
saved analysis facet. [Apple Mach-O export encoding](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)

Apple's `dyld_info -exports` agreed on 392 name/offset pairs across 16
manifest-verified calculator binaries and four locally linked legacy
variants. Six separately compiled arm64 and x86_64 dylibs added 14 checked
records covering absolute, weak, thread-local, re-export and dynamic
resolver entries. LLVM's export-trie display independently matched the
stub and resolver offsets. The public CLI paginated both architectures
after a universal dylib import with analysis still pending.

`fixups` reads the digest-verified imported slice before or after analysis.
Use `fixups --input FILE` to read an owned Mach-O directly. Select a slice
with `--arch arm64|arm64e|x86_64` for a universal input. File pagination
binds to the artifact digest and exact slice.

The decoder supports ordinary 64-bit chains and the arm64e userland
formats 1, 9 and 12 with uncompressed names and import record formats 1–3.
Authenticated records include the key, diversity and address-diversity flag.
Rebase records carry
unslid targets. Bind records carry declared symbols, ordinals, weak flags
and addends, with an unresolved runtime address. The ordinary 64-bit
legacy rebase, bind, weak-bind and lazy-bind opcode streams are also
decoded. Records preserve stream identity where streams share a pointer
address. Threaded legacy binds, other chained pointer formats, and
compressed names receive partial coverage. No dependencies are loaded.
Use `--kind bind|rebase|all`,
`--limit` and `--cursor` to inspect the evidence.

On 16 owned fixtures, `dyld_info -fixups` agreed on all 3,296 rebase
addresses/targets and 594 bind addresses/symbols. Those binaries used
`DYLD_CHAINED_PTR_64_OFFSET` and import format 1.
An independently linked arm64e fixture used format 12. Two derived copies
exercised formats 1 and 9, tagged targets and negative inline addends.
Apple's static tool matched all 18 raw words, targets or symbols, and
authentication fields. The tool displays the raw 19-bit addend. The CLI
reports its signed value as used by the loader. The same test verified
universal arm64/arm64e selection and pagination. [Apple pointer layouts](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h) · [Apple loader addend decoding](https://github.com/apple-oss-distributions/dyld/blob/main/common/MachOLayout.cpp#L1882)

The arm64e decoder also handled 12,000 seeded mutations of the owned
fixup words and chain tables. It returned 7,056 typed errors, 3,234
partial results and 1,710 complete decodes within its bounds. The
mutation report SHA-256 is
`0eb4cd9f34a3dd1a71c6665d1cf7226c2b35bc59510414da9bd018abbd01806e`.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/integration_arm64e_fixups.py \
  --output-dir /private/tmp/new-arm64e-fixup-check
```

An isolated full-Ghidra probe of a separate owned arm64e call fixture
imported under the Apple Silicon language and matched LLVM's authenticated
instruction mnemonics. Its low p-code omitted the signing operations for
`pacibsp` and `paciza`, modeled `blraaz` as an ordinary indirect call,
and modeled `retab` as an ordinary return. Engine import and analysis
for arm64e remain gated on authenticated instruction semantics. The
probe report SHA-256 is
`9b959c2592f39d01a880f1552a9e9fe9e5761512a74d53baa0803a84f50b9330`.

Four separately linked owned tools and AppKit binaries using
`-Wl,-no_fixup_chains` matched Apple tooling on 906 rebases, 142 ordinary
binds and 38 lazy binds. Synthetic tests cover weak binds and a backward
address delta emitted by the linker.

`objc classes`, `objc methods`, and `objc selectors` read static declarations
and selector references from the immutable slice. Class records include the
metadata address and a local or external superclass reference. Method
records distinguish instance and class declarations and preserve category
names when present in the linked image. Absolute and relative method records
include selector and implementation evidence. Selector declarations and
reference slots remain separate, and none imply a resolved runtime dispatch.
Use the reported implementation address with `functions show --address` in
an analyzed project. The views work before analysis and support filtered,
paginated output. [Apple Objective-C runtime structures](https://github.com/apple-oss-distributions/objc4/blob/main/runtime/objc-runtime-new.h)

Apple's `dyld_info -objc` agreed on the 16 class records and 216 method
addresses across eight owned calculator app builds. Separately compiled
arm64 and x86_64 probes also matched for instance, class and category
methods. The views currently cover class, method and selector evidence.

`swift symbols` lists Swift mangling candidates from the Mach-O symbol table,
including raw names, definition state, available VAs and detected Swift
sections. The command works before analysis. Use `--demangle
--experimental-trusted-input` to demangle the current page using Xcode's
local Swift demangler. Results identify its version and digest and preserve
names it did not recognize. `macscope demangle NAME --experimental-trusted-input`
uses the same helper for a standalone Swift name. The sandbox denies network
and file writes. Symbolic references and broader Swift metadata decoding
remain outside the name view. [Swift ABI mangling reference](https://github.com/swiftlang/swift/blob/main/docs/ABI/Mangling.rst)

Two owned Swift libraries built for arm64 and x86_64 and their stripped copies
matched `nm` on all 38 reported candidates. All eight retained names in the
imported stripped arm64 library demangled before Ghidra analysis.

`bytes` reads 1–4096 bytes from the immutable selected slice before or after
analysis. Use `--address 0xVA` or `--rva 0xRVA` for a range within one
unambiguous file-backed section. Use `--file-offset 0xOFFSET` for any byte
range within the slice, including its header. The response includes both
slice and container offsets. VA, RVA, and address space are null where the
file range has no unambiguous section mapping.

The installed CLI compared VA, RVA, and slice-offset selection on six
owned stock Ghidra calculator captures. All selectors returned the same
function views and byte ranges. Annotation edits and history resolved to
the same entries. Both slices of a newly imported universal binary returned
the same bytes through all three selectors before analysis. Header reads
retained the correct container offsets. Two fresh queries selected by RVA
and file offset replayed the original receipts without starting another
worker. Saved exports remained byte-identical. The calculator report
SHA-256 is `3b640173dd5bddb805400d2c77ad9c145a8ba9f2da02815058610b3cf3e54f36`.
Separately linked arm64 and x86_64 dylibs and bundles also agreed with
the Mach-O base, Apple `nm` entry and original bytes. Each had a preferred
and Ghidra image base of zero. The four-probe report SHA-256 is
`d259b2d072ae0f59239df071bf28c510e3171a2102c0b3799aabc5a2746fbe31`.

`imports`, `exports`, `symbols`, and `strings` query the saved engine
collections. The first three accept a literal `--name-contains` filter.
`strings` searches Ghidra-defined string records with `--contains` and
`--min-length` in bytes. All collection commands support `--limit` and
`--cursor` and report the coverage of the selected facet. They run without
starting Ghidra.

Import passes `-noanalysis` to Ghidra, disables loading/reexporting/linking
libraries, and records the actual language/compiler pair. A no-analysis
loader can still create entry/stub/external function seeds; these are recorded
as loader output, not confused with automatic analyzer work. Tested pairs:
`AARCH64:LE:64:AppleSilicon/default` and `x86:LE:64:default/gcc`.

Inputs are private immutable copies with SHA-256 for the whole container and
selected slice. The original binary is never changed. A saved full Ghidra
Program database is retained. Each analysis clones the pristine no-analysis
import, so a retry cannot silently inherit preceding analyzer mutations.
The default bridge profile remains `macscope-binary-only/1`. It resets and
records every effective analysis option and disables source/DWARF/PDB/debug/
external/library and demangler options. See the
[deep analysis profile](#deep-analysis-profile) and
[parameter inference profile](#experimental-binary-derived-parameter-inference)
for the explicit alternatives.

SQLite points only to completed, digest-checked immutable JSON snapshots.
A writer lock serializes import and analyze; readers continue using the
previous snapshot if a job fails. Snapshot publication and explicit output
writes are atomic and refuse overwrites without `--force`. Failed worker
output is never published as a completed analysis. No automatic schema
migration or stale job cleanup is attempted.

Analysis IDs include artifact/slice identity, the pristine Program database
hash, effective options, language/compiler, engine distribution-tree hash,
bridge/native/JDK component digests, profile and limits. Function IDs belong
to that analysis and address space, not global names. Function entry/instruction
locations carry image, architecture, address space, unslid VA, RVA, and nullable
slice/container offsets. External functions have `entry_va: null` and a typed
`EXTERNAL` engine location, not a fabricated image VA.

By default, function, disassembly, decompile, xref, CFG and export commands
query the committed snapshot without starting a JVM. `decompile --fresh`
requires an exact function selector and the trusted-input flag. It opens a
private copy of the selected saved Program with `-readOnly -noanalysis`,
inherits its analysis profile, and asks the native decompiler for that one
function. The result identifies the original analysis and the new query job.
The worker requires the Ghidra distribution recorded by the saved analysis.
Fresh queries preserve the committed snapshot and the original Program.
`--fresh` supports the same worker time and Java heap limits as analysis.
On the owned arm64 and x86_64 tools, fresh queries matched the cached
pseudocode under both profiles. The integration checks verified one
decompile attempt and preserved the saved Program and snapshot.

For a supported x86_64 dispatch function, request return recovery in the
fresh query copy with the same full Ghidra distribution used for analysis.

```sh
macscope decompile --project workspaces/calculator --arch x86_64 \
  --name _calc_dispatch_table --fresh --recover-dispatch-return \
  --experimental-trusted-input --json
```

The option requires one selected function and is mutually exclusive with
`--with-type-hints`. The worker uses an immutable table, both return paths,
a caller that observes both registers, and agreement among the table's
callees. `origin.dispatch_return_recovery` records `applied` or `skipped`,
the policy and request digest, and the register storage or skip reason.
A skip returns the ordinary fresh pseudocode. The cached pseudocode,
function signature, CFG, and unresolved indirect references remain the
saved evidence. [Owned fixture validation](dispatch-tables.md#installed-cli-validation)

Direct-call signature recovery is available for a separate fresh query.

```sh
macscope decompile --project workspaces/calculator --arch x86_64 \
  --name _calc_apply_op --fresh --recover-direct-signatures \
  --experimental-trusted-input --json
```

The policy checks exact direct-call bytes and linker entries along a
bounded call path. A caller must observe both result registers, and each
eligible call must forward those registers to the return. The worker
commits the inferred callee signatures in the read-only copy after
checking argument storage and agreement on the return ABI.
`origin.direct_signature_recovery` records the applied call sites or a
skip reason. The option uses its own query, separate from dispatch
recovery and accepted type hints. [Direct-call validation](direct-signatures.md)

For a supported scalar call, request scalar signature recovery in its
own fresh query.

```sh
macscope decompile --project workspaces/calculator --arch x86_64 \
  --name _calc_engine_input_op --fresh --recover-scalar-call-signatures \
  --experimental-trusted-input --json
```

The policy verifies an observed full-width x86_64 result or the arm64
Mach-O binding for the libSystem stack-check failure import.
`origin.scalar_signature_recovery` records the applied call sites and
ABI or the reason recovery was skipped. [Scalar signature validation](scalar-call-signatures.md)

To infer parameters for verified direct callees of one selected function,
use a separate fresh query.

```sh
macscope decompile --project workspaces/calculator --arch arm64 \
  --name _calc_engine_input_op --fresh --recover-callee-parameters \
  --experimental-trusted-input --json
```

The bridge uses Ghidra's native register-parameter inference along
verified call paths. The result records the applied sites or skip
reasons in `origin.callee_parameter_recovery`.
[Scope and validation](callee-parameters.md)

For an observed integer result forwarded through a direct call, use
`decompile --fresh --recover-forwarded-return` with one selector and
the trusted-input flag. The query verifies the wrapper epilogue and
an independent full-width caller store. The result records the
evidence or a skip reason in `origin.forwarded_return_recovery`.
[Forwarded return validation](forwarded-return.md)

Cached and fresh results report partial coverage when a recorded computed
jump lacks a destination or Ghidra emits an explicit jump-recovery warning.
The original pseudocode, edges, and printer status remain available.
`control_flow_gaps` identifies the Ghidra evidence and
`control_flow_review` identifies the reporting policy. Selected pseudocode
and CFG queries with an observed gap exit 6. The check also applies when
reading existing snapshots. It leaves analyzer settings and stored
snapshots intact. [Held-out and calculator validation](heldout-switch.md#measured-results)

To recover an eligible x86_64 switch in one fresh trusted query, use
`decompile --fresh --recover-switch-table` with one function selector.
This option has its own query scope, separate from type hints and other
recovery options. It requires a guarded relative table whose bytes and
extent match the immutable Mach-O and the saved Program. Ghidra verifies
the omitted case blocks and prints the resulting switch with its native
override warning. `origin.switch_table_recovery` records the verified
case indexes and ordered targets, including repeated destinations, or
the reason recovery was skipped. If the saved signature came from analysis
of the incomplete body, the worker can refresh it from the restored body.
It keeps the refresh only when Ghidra finds additional register arguments
and preserves existing parameter storage. The `prototype` field records
the saved source, the saved and native parameter counts, and whether the
worker kept a refresh. Cached analysis remains independent of the query.
[Stock engine validation](heldout-switch.md#stock-engine-fresh-query)

The CLI also reports a function-boundary conflict when a linker-confirmed
function falls through into a competing Ghidra function entry inside the
same linker extent. Both entries carry the evidence, and cached, fresh and
replayed pseudocode report partial coverage. The original function records
and Program are preserved. [Owned app-main measurement](phase1-findings.md#controlled-core-instruction-audit)

To apply guarded boundary recovery to a new analysis copy, use:

```sh
macscope analyze --project workspaces/calculator --repair-split-boundaries \
  --experimental-trusted-input --json
```

The opt-in works with either analysis profile. It uses the complete
function-start table from the verified Mach-O slice. A join requires
adjacent fallthrough into a default-named competing entry, continuous
decoded instructions within the same executable linker extent, and no
recorded outside reference anywhere in the competing body. Analysis
reports each join or refusal under `boundary_recovery`. A refusal or a
reached scan bound yields partial coverage.

The policy and request digest form part of the new analysis identity.
Fresh queries use the saved repaired Program, and job replay restores the
recorded policy. The pristine import and preceding analysis remain
available. [Held-out validation](heldout-fallthrough.md#production-validation)

New analyses and fresh queries can include `address_spans` from Ghidra's C
markup. `text_start` and `text_end` are zero-based UTF-16 offsets into the
returned pseudocode, with the end excluded. Each `ranges` entry is an
inclusive pair of unslid addresses in the selected function body. Ghidra
supplies links only for tokens with machine-address evidence. The bridge
checks that token text aligns with the printed pseudocode and caps links at
1,024 per function and 40,000 per job. If display redaction changes the code,
its raw offsets are unavailable in the normalized result.

The four owned thin/fat64 integration exports contained 9,742 token links
across 144 completed function records. All linked addresses matched exported
instruction starts and the pseudocode matched the preceding bridge version.
Fresh and cached links matched for `_calc_add` on both architectures.

`status` and `jobs list` show up to 100 recent worker records.
`jobs show JOB_ID` reads a particular job and includes its limits and
engine digests. Live status requires an ownership lock held by the
supervisor. Without that lock, an earlier running record is reported as
`unknown_after_disconnect`.

```sh
macscope jobs show JOB_ID --project workspaces/calculator --json
macscope jobs cancel JOB_ID --project workspaces/calculator --json
```

Cancellation records a request for that exact live owner. The supervisor
handles the request and signals its own worker group. Poll `jobs show` for
the final state, since a worker can finish while a request is being written.
A confirmed cancellation exits 130 in the original command and preserves
the prior committed snapshot.

Restart an eligible analysis, import slice or fresh decompile with its
recorded request.

```sh
macscope jobs resume JOB_ID --project workspaces/calculator \
  --experimental-trusted-input --json
```

The restart verifies the stored immutable artifact and selected slice. It
preserves the recorded worker limits and, for analysis, uses the pristine
import Program and recorded profile. Select the same Ghidra and JDK used by
the original job, including any explicit `--ghidra` or `--java-home` paths.
The CLI also verifies the recorded isolation policy before launching.

For a partial import batch, use the `failed_job_id` in the error's partial
results to restart that slice. The workspace's artifact copy is sufficient
even if the original input path has disappeared. Other committed slices stay
available. If Ghidra finished and the import journal was written, the CLI can
verify the saved Program and finish publishing it without running Ghidra again.

For a fresh decompile, the restart opens the original saved Program and
uses the recorded function, label and accepted return hints, even if
a later analysis or annotation revision is current. Signature recovery
rechecks the original slice and snapshot against the recorded request digest.
The restart returns the stored result if the original or restarted query
already published one. Replay preserves the active analysis and annotation
revisions.

The result and its publication receipt commit together. Repeating a
successful restart returns the recorded result. Analysis restart also
checks that its preceding active analysis is still current.

New Ghidra jobs record the process group before releasing the launcher.
If the supervisor disconnects during the same macOS boot, `jobs show`
reports `stopped_after_disconnect` when the CLI can verify that the group
is gone or that the launch guard never released it. Such jobs can be
restarted explicitly. A live worker, a job with unconfirmed exit or an
older job without a recorded request remains ineligible. The process-group
check requires the recorded macOS boot identity and sends no signal to
the worker.

Raw bridge JSON and job manifests/logs remain private in the workspace.
Normalized exports sort function and unordered cross-reference records (retaining
duplicate references), omit volatile Program-info/timing fields and
installation paths, and redact `/Users/<name>` prefixes even when embedded
in recovered binary strings. Raw evidence is retained separately. These
exports can still contain sensitive recovered code/strings; never publish
them by default. Logs are bounded per job but retained until the owner removes
the workspace; no automatic retention or deletion task is installed.

## Comparing committed exports

```sh
macscope diff old.json new.json --scope functions --json
macscope diff old.json new.json --scope pseudocode --limit 50 --json
macscope diff old.json new.json --scope metadata --json
```

Both inputs are single JSON envelopes from `macscope export --json`.
The comparison records their export, analysis, artifact and slice identities
and runs without opening a worker or workspace. `--cursor` binds to both
ordered input file digests and the comparison scope.

`metadata` compares the image layout, loader records and saved Ghidra
imports, exports, symbols and strings. It shows short values directly and
summarizes larger collections by size and digest. `functions` reports
changed attributes, the count of differing decoded instruction offsets
and the first difference. `pseudocode` compares the saved printed text,
with content digests and the first differing line. Both function scopes
require the same architecture.

For the same slice bytes, matching memory entries use their recorded
address. Across builds, a unique qualified engine name or a unique complete
instruction fingerprint can suggest a pair. The result labels those pairs
as candidates and records which evidence supports them. Conflicting or
non-unique candidates retain bounded samples of alternatives. An unmatched
row shows an observation for which the comparison found no pair. Incomplete
facets and ambiguous matches return partial coverage. Results describe
saved evidence and printed text.

The installed CLI checked owned arm64 and x86_64 pairs with a changed
constant, a changed branch, a renamed function, an added function and
duplicate bodies. LLVM and DWARF verified the body fingerprints. Both
symbol-bearing pairs reported the constant and branch changes, paired
the rename by complete bytes and left the duplicate bodies ambiguous.
Both stripped pairs still matched the renamed bytes and left the changed
routines unmatched. An `LC_RPATH` change appeared in metadata while all
decoded instructions matched. The thin and universal comparisons paired
all eight checked entries by same-slice address. The validation report
SHA-256 is `a35f371455cded1cf8f96c73672a5e3e975f816bf8e239d8c259371bc55dca2d`.

## Experimental binary-derived parameter inference

Baseline remains the default. To request Ghidra's generic whole-program
`Decompiler Parameter ID` analyzer, explicitly select the alternate profile:

```sh
macscope analyze --project workspaces/calculator --profile parameter-inference \
  --experimental-trusted-input --json
```

This is a binary-only inference pass, not source recovery or a calculator-
specific call rewrite. It takes no source declarations, dSYMs, symbol-server
data or manual prototype hints. Symbol-bearing inputs can still provide their
embedded names. All source/external analyzers disabled by baseline remain
disabled. The only changed analyzer option is `Decompiler Parameter ID=true`.

Baseline's analyzer configuration and default selection are unchanged; new
provenance fields and canonical cross-reference ordering change serialized
exports. Analysis identities already include bridge component hashes, so this
is not a promise of identical IDs or bytes across code versions. Existing
snapshots are not rewritten or migrated.

The profile is `parameter-inference/1` with Program marker
`macscope-binary-only-parameters/1`. Baseline remains `baseline/1`.
The requested configuration is in the job manifest, normalized snapshot,
analysis identity and analyze response; the bridge records the applied marker,
inference flag, source description, semantic-validation status and complete
effective options. Missing, incomplete or mismatched policy evidence rejects
the result before snapshot publication. `doctor` lists supported profiles.

Each profile starts from the same pristine import. Switching back to baseline
does not reuse inferred parameter commits. Existing snapshots stay immutable,
and cached queries return whichever profile is active. The internal reopened
query inherits the saved profile and uses `-readOnly -noanalysis`; it never
silently falls back to baseline or reruns inference.

Inferred argument counts, parameter types, return types and calling-convention
labels may be wrong. Whole-program inference changes many functions, not just
the known arm64 invalid-digit call. The tests establish the recorded policy,
profile isolation and selected static properties, **not semantic equivalence**.
There is no automatic promotion, automatic profile selection or hidden fallback.

A source-aware fixture matrix covers arm64/x86_64, O0/O2, symbol-bearing/stripped,
and the owned AppKit app main/command-line tool. It does not launch the app,
execute recovered pseudocode or validate broad ObjC/Swift behavior:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/integration_profiles.py \
  --fixture-build-root build/review-v2 \
  --output-dir /private/tmp/new-macscope-profile-matrix \
  --experimental-trusted-input
```

The schema-2 fixture manifest and each input digest must match. The output
directory must be new; private evidence remains there even on failure.
Use an absolute build-root path when running from a separate worktree.
See [the profile evidence review](parameter-inference.md) for measured scope
and remaining limits.

## Deep analysis profile

```sh
macscope analyze --project workspaces/calculator --profile deep \
  --experimental-trusted-input --json
```

`deep/1` enables Ghidra 12.2's `Decompiler Parameter ID` and the Reference
analyzer's `Create Address Tables` option. The Reference analyzer can
define pointer entries at addresses referenced by instructions. Relocation
guidance stays enabled. The profile checks that Reference switch-table
inference and the Aggressive Instruction Finder stay disabled, and retains
the baseline exclusions for source and external analyzers. The export
records the full option inventory and the Program marker
`macscope-binary-only-deep/1`. Fresh decompilation verifies the saved
profile on the read-only Program. Analysis restart verifies and reuses the
recorded profile and limits. Address-table references are inferred data
evidence. Unresolved indirect jumps keep their explicit coverage gaps.

The [owned packed-table fixture](../analysis/heldout_address_table.S)
contains a table referenced by an instruction, a second unreferenced table
with the same pointer bytes, and an indirect jump with an unknown
destination. Build it with the macOS command-line tools from the repo root.

```sh
fixture_dir=$(mktemp -d /private/tmp/macscope-deep-fixture.XXXXXX)
xcrun clang -arch arm64 -nostdlib -lSystem -Wl,-no_fixup_chains,-e,_main \
  -o "$fixture_dir/arm64" analysis/heldout_address_table.S
xcrun clang -arch x86_64 -nostdlib -lSystem -Wl,-no_pie,-no_fixup_chains,-e,_main \
  -o "$fixture_dir/x86_64" analysis/heldout_address_table.S
```

Import each binary into a separate disposable project and export after
analyzing under each of the three profiles. Use `xcrun nm -n` to locate
`_owned_table`, then query its three consecutive 8-byte entries with
`macscope xrefs --project PROJECT --from ADDRESS`. On both architectures, the installed CLI
reported 22 references under baseline and parameter inference and 25 under
deep. Each of the three additions matched the pointer bytes and the
linker address of its target. The unreferenced control table gained no
references, and the unresolved jump kept the same coverage gap under all
three profiles. The fixture's analyze and export commands exit 6 because
of that gap. Repeated deep exports matched byte for byte, fresh
decompilation used the saved deep Program, and switching back reproduced
the baseline exports. A cancelled arm64 deep job preserved the previous
snapshot. Its restart reproduced the deep export, and a second restart
request returned the saved receipt. The validation report SHA-256 is
`81170c7a32865b1131fd4939d3e824fa015e96a27c7516f3f603df34181e9132`.

## Limits and safety boundaries

Defaults: one worker; 300s total wall deadline; 15s per decompilation;
1000 functions; 1024MiB Java heap. Allowed ranges are documented by help.
Fixed bridge bounds include 2000 instructions/function, 500 blocks and
500 edges/function, 200 references/direction/function, 10000 symbols/category,
5000 strings, 100000 defined-data entries scanned, and 64MiB result output.
Address cross-reference capture retains up to 16000 references per image
and up to 10000 computed control-flow sites from 100000 scanned instructions.
Every cut facet has explicit partial coverage; some totals are unknown.

The worker launcher log is sampled at 8MiB and combined job storage at
512MiB. The runner checks both again after process-group cleanup, before
accepting any result. These are sampled checks and can overshoot.
`--max-memory-mib` is rejected because a hard process-memory limit
is not enforceable here. `--heap-mib` limits only the Java heap, not native
memory or total process RSS. `--jobs` values other than 1 and independent
`--startup-timeout` are rejected. `--timeout` bounds startup plus analysis
plus export as one owned worker wall deadline.

The worker starts a private process group and records an ownership token.
The supervisor observes the launcher exit without reaping it, stops
remaining group members while the child PID is still reserved, then
reaps the launcher. Timeout, interruption, and failure preserve prior
committed results.

The macOS seatbelt profile denies network access and restricts user-home
reads to the private project, bridge, exact engine/JDK paths, and listed
ancestor directories. Each worker gets a newly created writable job
directory with its own HOME, Java settings, working directory, and
temporary files. The launcher also uses `/dev/null`. Saved inputs,
snapshots, the index, and previous jobs are outside the write scope.
Program copies with symbolic links fail before a worker launches.

The installed canary check allowed reads of staged inputs and writes
to the current job. It denied writes to the index, a saved snapshot, an
input, a prior Program, and the shared workspace home. The kernel also
denied writes through a hard link staged in the input directory and
through a symlink aimed at an outside file. Creating a new hard link
from outside the job and connecting to a loopback listener were denied.
Non-home reads remain broadly available. The policy is for trusted owned
inputs. Missing or broken isolation fails closed.

Every job records a digest of its exact path-specific policy. Restart
validates the cancelled job against that original path. The replacement
worker gets a new private path and policy digest. An import publication
journal binds the policy to the job that produced the Program. Earlier
committed snapshots and published query receipts remain readable.
An unfinished job carrying an older policy returns `job_resume_engine`
before launch.

The installed-wheel matrix covered both profiles in four scopes.
It used symbol-bearing arm64 and stripped x86_64 with stock Ghidra 12.2,
and stripped arm64 and symbol-bearing x86_64 with the experimental tree.
All eight scopes imported, analyzed, and reproduced their cached C in
fresh queries. Saved Programs and exports retained their hashes. All
eight receipts replayed. A prior published receipt also replayed. On a
copy with the receipt removed, a simulated unfinished job using the old
policy was rejected before launch.

A separate live trial cancelled and restarted import, analysis, and
fresh decompilation, then replayed each receipt. Import restarted from
the staged bytes after removal of the scratch original. The cancelled
analysis and query preserved the previous export. A repeated baseline
analysis produced the same analysis ID and byte-identical export in a
different job. A final wheel reproduced the archived forwarded-return
query and rejected symlink aliases for both an imported Program and
an earlier analysis job before starting the worker.

| Local report | SHA-256 |
| --- | --- |
| `canaries/report.json` | `d0872264aca79c01fc49238884295d4a97c6a70fe8dc89b42f4f364b73cc71b3` |
| `matrix/report.json` | `f9ed662dc4945045084a2573f628068b95aef35fcf2e213838658b9267387496` |
| `restart/report.json` | `ed0d16685dc8c2d3b0891b32d5dc1737171b03c9d22af22576f72ed95250be01` |
| `repeat/report.json` | `ca918e4e59bf5642269db799a0accb139adff91ff3118123cf296ca0de4e4af1` |
| `final-check/report.json` | `ba81b9eba2326e3e58e80cbfb4edae7e94cfaf2f2865c0e3cf108056383a73cb` |

The reports are under `/private/tmp/macscope-job-isolation.RNU3U6`.
The previous workspace-wide policy was measured separately in
`/private/tmp/macscope-worker-isolation.X9QyEf/matrix/report.json`.

No source/dSYM discovery, dependency execution, arbitrary user scripts,
network symbol fetches, input execution, remote model calls, or automatic
installs are part of the CLI. Installed dependencies themselves remain a
trusted part of the execution environment.

### Targeted malformed Mach-O payloads

The installed data-only parsers processed 20,480 seeded mutations in
owned arm64 and x86_64 calculator copies. A bounded worker denied network
access and user-home data reads. Each fixture and parser pair used 2,048
mutations with one to four byte flips inside a fixup, export-trie, or
Objective-C metadata extent. The random seed was `0x67686472612D6F30`.
The worker checked that the staged inputs retained their original bytes.

| Parser | Complete | Partial | Typed errors |
| --- | ---: | ---: | ---: |
| Dyld fixups | 3,362 | 856 | 3,974 |
| Dyld exports | 2,289 | 383 | 5,520 |
| Objective-C methods | 2,482 | 292 | 1,322 |

The trial calls the installed parser entry points and measures this
sample of payloads. The local report at
`/private/tmp/macscope-baseline-callees.89xYWz/parser-audit/report.json`
has SHA-256 `447a7877637d6ca538063aa84742774d302826137286f903de4f4f7706f0758f`.

## Envelopes, errors and explicit omissions

Workspace opens validate the manifest structure, schema version, and
workspace identifier before using the index. Malformed manifests
return `workspace_manifest` and exit 5. An unsupported version
returns `workspace_schema` and exits 3. An installed-wheel check
reopened an earlier schema 1.0 workspace and reproduced its export
byte for byte before and after five manifest error cases. The saved
index retained its digest. The local report in
`/private/tmp/macscope-forwarded-return.gwE9OS/workspace-check/report.json`
has SHA-256 `d6ebd323819fa8b5dc31f8372ad39978b776d75c6430459047c23bf4761d6211`.

The SQLite index is validated for the required schema 1.0 tables and
columns before a project opens. Damaged indexes and missing core schema
return `workspace_index` and exit 5. A lock during the check returns the
retryable `workspace_index_busy` error and exits 8. An installed-wheel
trial reproduced an earlier valid export byte for byte and verified
that failed opens preserved the test indexes.

The local index report in
`/private/tmp/macscope-worker-isolation.X9QyEf/index-check/report.json`
has SHA-256 `4f6af5740a007ecf698c8525ce215665b99049a0996d3568aecca36bc863cad0`.
On the same saved workspace, 20 paired cached queries produced
byte-identical JSON with the earlier and current wheels. The observed
95th percentiles were 0.167 s and 0.143 s on the development Mac.


Bundled `envelope.schema.json` and `function.schema.json` use schema1.0.
Every JSON response has command, status, analysis_id (nullable), data,
diagnostics and coverage. A stdlib subset validator validates those schemas
and emitted function records. `complete` denotes completion within the
recorded coverage. Unavailable pseudocode and unknown coverage totals are
null. Token/address spans include a separate availability field.

Exit codes: 0 complete, 2 usage/ambiguity/cursor, 3 unsupported capability,
4 dependency missing/incompatible, 5 malformed/integrity, 6 partial result,
7 timeout/resource limit, 8 workspace/output conflict, 10 unexpected worker/
internal failure, 130 interrupt. A bounded collection page can have partial
coverage while the page request itself exits0; use `next_cursor`.

Remaining capabilities include richer Objective-C and Swift views,
compound type hints, HTML exports and manual function
corrections. Additional release requirements include stronger isolation,
hard RSS/disk quotas, schema migrations, signed packaging, x86_64 host
workers and expanded fuzzing. The [progress checklist](current-status.md)
tracks behavior validation and the separately gated work.

## Reproduce validation

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/integration_macscope.py
```

The integration script uses only owned calculator binaries already built in
`build/analyst/DebugAnalysis-{arm64,x86_64}-sym/CorpusFixture`, synthesizes a
fat64 container, exercises both thin and explicit universal selections,
checks every phase-2 command/schema and atomic exports, and compares
pseudocode/instruction content by slice digest. It creates fresh
`build/cli-integration-*` evidence on every run. Performance here is a local
measurement, not a release target or cross-machine benchmark. See the
[20-round CLI benchmark](benchmark.md) for the measured development host.
