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
macscope cfg --project workspaces/calculator --name _calc_add --format dot
macscope search calc_add --in all --project workspaces/calculator --json
macscope calls --name _calc_add --direction callers --depth 2 --project workspaces/calculator --json
macscope status --project workspaces/calculator --json
macscope export --project workspaces/calculator --json --output private-results.json
```

A project parent directory must exist. Project creation is private mode0700
and refuses an existing path. For a universal input import requires explicit
`--arch arm64|x86_64|all`; it extracts each chosen slice before invoking
Ghidra. Reimporting an already imported immutable identity is idempotent.
An image operation requires a unique `--image ID` and/or `--arch` when the
workspace has multiple images. `--name EXACT`, `--address 0xUNSLID_VA`, and
`--function-id ID` are mutually exclusive; duplicate names return candidates.
Addresses identify **function entries**, not an arbitrary containing function.

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
64-bit arm64 and x86_64 executable/dylib/bundle images. It resolves a main
`.app/Contents/Info.plist` executable and reports companion debug dylibs.
Ordinary input paths open each component without following symlinks.
Encrypted images, arm64e, x86_64h, other CPU subtypes, 32-bit images,
relocatable objects and malformed ranges receive explicit failures. The
preflight is **not** a complete Mach-O/dyld parser or a security proof.

## Persistence, identity and freshness

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
external/library and demangler options. `deep` is explicitly unsupported,
not an alias. See the explicit alternate profile below.

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

`status` shows at most 100 job
records; interrupted/disconnected running markers become
`unknown_after_disconnect`, with no attempt to signal stale PIDs.

Raw bridge JSON and job manifests/logs remain private in the workspace.
Normalized exports sort function and unordered cross-reference records (retaining
duplicate references), omit volatile Program-info/timing fields and
installation paths, and redact `/Users/<name>` prefixes even when embedded
in recovered binary strings. Raw evidence is retained separately. These
exports can still contain sensitive recovered code/strings; never publish
them by default. Logs are bounded per job but retained until the owner removes
the workspace; no automatic retention or deletion task is installed.

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

## Limits and safety boundaries

Defaults: one worker; 300s total wall deadline; 15s per decompilation;
1000 functions; 1024MiB Java heap. Allowed ranges are documented by help.
Fixed bridge bounds include 2000 instructions/function, 500 blocks and
500 edges/function, 200 references/direction/function, 10000 symbols/category,
5000 strings, 100000 defined-data entries scanned, and 64MiB result output.
Every cut facet has explicit partial coverage; some totals are unknown.

The worker launcher log is sampled at 8MiB and combined job storage at
512MiB. These sampled checks can overshoot; they are not hard filesystem
quotas. `--max-memory-mib` is rejected because a hard process-memory limit
is not enforceable here. `--heap-mib` limits only the Java heap, not native
memory or total process RSS. `--jobs` values other than 1 and independent
`--startup-timeout` are rejected. `--timeout` bounds startup plus analysis
plus export as one owned worker wall deadline.

The worker starts a private process group, records an ownership token,
and terminates only its live owned group, including remaining descendants
if the launcher exits first. Timeout/interrupt/failure manifests preserve
prior committed results. There is no PID-file based kill/recovery operation.

The tested macOS seatbelt profile denies network and user-home reads/writes
outside the private project, bridge, and exact engine/JDK paths. HOME, Java
user state, cwd and temporary files are private to the workspace; environment
variables are whitelisted. The profile still broadly permits system data and
non-home filesystem access. **It is not a complete hostile-input security
sandbox.** Missing/broken isolation fails with no automatic unsandboxed
fallback. The explicit experimental flag is required on each engine command.

No source/dSYM discovery, dependency execution, arbitrary user scripts,
network symbol fetches, input execution, remote model calls, or automatic
installs are part of the CLI. Installed dependencies themselves remain a
trusted part of the execution environment.

## Envelopes, errors and explicit omissions

Bundled `envelope.schema.json` and `function.schema.json` use schema1.0.
Every JSON response has command, status, analysis_id (nullable), data,
diagnostics and coverage. A stdlib subset validator validates those schemas
and emitted function records. `complete` denotes completion of a backend
operation, **not** semantic correctness or exhaustive runtime behavior.
Unavailable pseudocode is null; unknown coverage totals are null.
Token/address spans are currently unavailable and explicitly marked as such.

Exit codes: 0 complete, 2 usage/ambiguity/cursor, 3 unsupported capability,
4 dependency missing/incompatible, 5 malformed/integrity, 6 partial batch,
7 timeout/resource limit, 8 workspace/output conflict, 10 unexpected worker/
internal failure, 130 interrupt. A bounded collection page can have partial
coverage while the page request itself exits0; use `next_cursor`.

Not implemented: public uncached refresh, annotations/types, rich ObjC/Swift
views, search commands, bundle/resource inventory, auxiliary images, REA,
HTML exports, diffs, manual function corrections, source-equivalence proof,
strong hostile-input isolation, hard RSS/disk quotas, migrations, signed
packaging, x86_64 host workers, or release-wide fuzzing/SBOM/notices review.
Unknown commands fail through the parser rather than fabricating support.

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
