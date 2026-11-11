# Evidence from explicitly selected saved query jobs

The owned practical writer assessment records manual pinned JSON manifest creation
as a remaining orchestration cost. Add `evidence --query-job JOB`, repeatable,
as an alternative to `--leads FILE`. The two inputs are mutually exclusive and
one is required. Existing manifest loading, exported schema and default behavior
are unchanged. The shortcut is read-only and never selects the newest job, runs
an engine, starts analysis, or guesses an entry/image from a name.

Accept one to sixteen unique exact job IDs in caller order, covering at most four
images. Only published import-focused decompile receipts qualify in this slice;
analyzed queries, failed/unpublished producing results, ambiguous/missing images and stale or
conflicting Program pins fail closed for the whole invocation. Duplicates are an
explicit input error, not silent deduplication. Read job records through existing
bounded/symlink-safe helpers; treat all stored identity fields as unverified
until current image/input/Program and complete receipt checks succeed.

For each requested ID derive the candidate image, entry and Program digest from
its focused request. Reconcile image/architecture/artifact/slice/current import
pin, recompute exact extent, validate publication/retry identity and saved result
hashes, and verify captured instruction bytes using existing focused receipt
validation. Preserve the requested job ID even when a valid resumed producer
published its result. Never follow an unrelated retry or use a stale import.

Construct an ordinary versioned leads manifest with address leads, IDs
`job-<requested-ID>`, exact validated pins, and query_job=requested ID. Validate
it through the existing manifest validator, then use the unchanged export path.
Equivalent manually supplied manifests produce byte-identical evidence outputs.
Do not write a manifest to disk automatically. All existing opt-in views remain
available; arbitrary explicit address leads do not supply an Objective-C owner
class slot, so they do not magically acquire exact declaration context.

Acceptance: actual owned four-receipt and writer receipt success without engine;
current/manual-manifest output equivalence and deterministic repeat; malformed,
duplicate, over-budget, stale, missing, unpublished, wrong-image and wrong-retry
rejection; existing manifest CLI compatibility; unchanged project files/jobs;
full primary/analysis tests, installed CLI and independent review.

A failed original request with a valid completed resumed producer remains valid
under existing receipt semantics. Selecting that original or its publishing
retry preserves the explicit requested ID; unrelated retries must fail.

## Usage and measured owned replay

```sh
macscope evidence --project WORKSPACE --query-job JOB_ID --format dossier
macscope evidence --project WORKSPACE --query-job FIRST_JOB --query-job SECOND_JOB --objc-sends --format json
```

The IDs are explicit published focused-query jobs already in that project, not
placeholders to search for automatically. Use `--leads` when you need named leads,
exact Objective-C class-slot selection, analyzed snapshots or other manifest-only
selection features. The shortcut does not select those on the user's behalf.

The four source-known ARM64 return-control receipts produced byte-identical JSON
through the shortcut, repeated shortcut and equivalent ordinary manifest with
nonexistent engine paths. Every portable project file hash stayed unchanged.
A temporary installed CLI also generated the original practical Swift writer's
dossier directly from its job ID, preserving partial exit6 and existing unknowns.
The implementation's changed runtime files were compared byte-for-byte to that
installed package. Independent review approved reuse of exact receipt validation;
regressions include original/producer retry identity and an unrelated retry that
must be rejected. No fresh engine, app execution or system installation is needed.
