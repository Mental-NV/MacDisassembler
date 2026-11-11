# Owned copy-on-write feasibility protocol (proposed)

## Decision and boundary

Measure whether an explicit macOS file clone is worth a later product proposal.
This is an analysis-only experiment, not a CLI option, retention change, cleanup
policy, or proof of reduced physical storage. No production code changes or native
Ghidra/app execution. Review this protocol before implementing or running it.

Base: documentation checkpoint `40469bd`; runtime source is unchanged from the
previous reviewed hybrid workflow baseline. Record the exact runtime tree digest,
Python/macOS versions and filesystem facts before any measurement.

## Inputs and preservation

Use only the already-owned approximately 1 MiB Ghidra Program fixture identified
by the operator, copied into a NEW private scratch root. Record its original full
inventory before and after the experiment; never mutate, overwrite or remove it.
An optional deterministic 64 MiB regular-file tree is an owned scale control, NOT
a valid Ghidra Program. Do not load either tree in Ghidra. No user application data.

Refuse symlinks, sockets, devices, FIFOs and other nonregular entries, including
symlink roots/ancestors. Require quiescent input, disjoint canonical source and
output trees, fresh exclusively-created output paths and no pre-existing targets.
Inventory directories and regular files by relative path/type/length/SHA256;
record mode separately. Do not claim metadata equivalence beyond checked fields.
Recheck inventories after each arm. A failure leaves artifacts intact for review.
This is not an adversarial concurrent-filesystem sandbox.

## Compared APIs (proposed)

1. Baseline: standard `shutil.copytree`, with unchanged default `copy2` file copier.
   Record Python version; do not assume every Python uses the same macOS fast-copy
   implementation. The observed Python 3.14 implementation uses fcopyfile data copy.
2. Explicit clone: walk the validated tree; create each directory exclusively;
   for each regular file call macOS libc `clonefile(src, dst, 0)` through `ctypes`
   (`use_errno=True`, declared argument/return types). This explicitly requests a
   clone, not a hardlink or silent ordinary copy. Apply `copystat` only to the NEW
   destination. Check distinct `(st_dev, st_ino)` pairs for every file.
3. Unsupported-clone fallback control: only `ENOTSUP`, `EXDEV`, or `ENOSYS` permits
   a separately labelled ordinary exclusive-create byte copy plus `copystat`.
   Never fall back for `EEXIST`, permission, I/O, or unknown errors. Verify a failed
   clone left no destination before fallback. Inject `ENOTSUP` in a dedicated arm;
   label it an injected decision-path test, not evidence about the actual volume.

The native clone arm must report actual errno on unsupported filesystems, not be
silently reclassified as a successful clone. No installations or settings changes.

## Integrity and isolation controls

Compare complete content inventories across baseline and cloned copies before
mutation. On dedicated scratch copies ONLY, modify a selected destination byte,
append to a destination and separately modify a source-scratch byte; after each
operation verify the other side remains byte-for-byte unchanged. Never modify the
original owned Program. Include zero-length files and nested directories in a
small synthetic control. Capture distinct inodes before and after mutations.

Attempt copying to an occupied target containing a sentinel: require failure and
unchanged sentinel, with no fallback. Test symlink and FIFO refusal using owned
scratch controls, without traversing them. Unit tests should exercise syscall error
classification, pre-existing target, unknown errors and partial-destination refusal.

## Measurements and report

Measure traversal/validation, copy and full content hashing separately using a
monotonic clock. Do not include hashing in the copy timer. Use fresh outputs for
all trials, alternate baseline/clone order and record each sample (suggested three
per fixture); disclose warm caches and small sample limits. Record logical byte
counts, `stat.st_blocks` and `du` separately if available: none measures unique APFS
physical allocation across clones. Optional volume-free observations are noisy and
must not be called clone storage savings. No source/evidence cleanup.

Report actual clone success/refusal, hash and mutation-isolation results, timings,
errors and limitations before any product decision. A speed benefit on these owned
fixtures does not establish improvement for large production Program databases or
safe lifecycle/retention behavior.

## Proposed harness and review gates

Use `analysis/owned_cow_copy.py` with no imports or modifications of product engine
code, and `tests/test_owned_cow_copy.py` for engine-free portable unit controls.
The Mac operator supplies the frozen owned input identity and private scratch root;
the harness validates the input digest before copying. Emit an experimental JSON
report only, no public job/receipt or automatic publication. Native clone execution
is macOS-only and fails explicitly elsewhere. Review implementation and unit tests
before any Mac run; retain all failed attempts. No native work is authorized by
this document alone.
