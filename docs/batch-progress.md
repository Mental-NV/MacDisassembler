# Saved batch progress

`macscope batch-status --project PATH --export-id DIGEST --json` reads one saved
export manifest and atomic index without launching Java, checking dependencies,
acquiring the writer lock, touching Program copies or verifying function files.
It is usable during a long export or after interruption. The exact export ID is
the directory name under `batch-exports/` and appears in export results/errors.

## Contract

- Validate the content-addressed manifest, supported schema/semantics/coordinator,
  image/analysis IDs, ordered unique canonical addresses (at most the current
  10,000 captured functions), and chunk size (1–128).
- Read at most 64 MiB each for manifest and index using existing no-symlink
  regular-file checks. No directory crawl or pseudocode load.
- Validate index identity, selected addresses, hash shape, terminal recorded
  statuses, and whole-chunk membership. An absent index means zero indexed
  entries; a corrupt or symlinked index is an error, not zero progress.
- Report indexed/unindexed functions and chunks, recorded outcomes and the
  canonical index digest. `record_integrity` and `worker_state` explicitly remain
  `not_checked`. A concurrent atomic index update may make the result stale.
- Unindexed does not mean failed: it includes pending/running/failed work. Even
  all entries indexed does not prove worker teardown, cleanup, intact function
  files, exhaustive discovery, or pseudocode accuracy. `--resume` retains its
  stricter validation before work. No ETA or native timing is invented.
- CLI exit 0 means a valid progress snapshot was read, not completed native work.
  The envelope coverage is the progress query; output carries the frozen export
  selection scope. Invalid metadata fails explicitly.
- Common `--output` cannot target managed `batch-exports/` evidence.

Tests cover absent/partial/full indexes, malformed identities/shapes, incomplete
chunks, dangling symlinks, corrupt function files (reported as unverified), no
native dependencies/trust path, and output overwrite protection. This is static
metadata tooling, not a decompiler speedup or a native engine release.
