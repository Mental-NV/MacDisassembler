# Canonical temporary fixture paths (F5c)

Tests that require a physical path must resolve their own freshly created
TemporaryDirectory before passing it into storage/CLI operations. macOS may
spell its temporary directory through `/var` or `/tmp` aliases. Fixture path
identity is the contract here, not that OS-provided spelling.

This is a test-only adjustment. Do not resolve arbitrary user input inside
production code or relax checked_path, output publication, traversal, symlink,
receipt identity, or race checks. Negative tests must still pass uncanonicalized
symlink paths intentionally and confirm rejection plus unchanged target bytes.

Acceptance:
- Partial-output and evidence-summary tests pass with aliased and canonical
  temporary directory roots. Saved-slice evidence fixtures use physical paths.
- An independently owned symlink-to-temporary-directory fixture demonstrates
  canonical output succeeds and the uncanonicalized parent is rejected, even
  with force. Existing leaf-symlink and output race/security tests remain intact.
- Run the full primary suite on macOS; record macOS/Python separately from Linux.
  If native validation is unavailable, mark the native gate blocked, not passed.
- No system CLI installation, private artifacts, or changes to external apps.

## Verification

- Cloud Linux: 764 primary and 115 analysis tests passed; all three new alias
  regressions passed. Independent review approved the test-only patch.
- No production files changed. Existing output-race, parent/leaf-symlink and
  receipt/source-mismatch tests remain enabled.
- Cloud Linux full primary suite also passed all 764 tests with an intentionally
  symlink-aliased temporary-directory root.
- Native macOS 27.0.1 (26A434), Python 3.14.6: unchanged default temporary-directory
  spelling through `/var/folders` reproduced the baseline failures (761 primary
  tests: two failures and 18 errors). With the test-only patch, all 764 primary
  tests passed. No TMPDIR override was used for either run.
- Native baseline and patched analysis suites each passed all 115 tests. The
  initial minimal transfer omitted the owned `fixture/build/write_manifest.py`
  helper; after transferring that exact baseline dependency, analysis was rerun
  successfully. This was a validation-package omission, not a product defect.
- Product `src` files were byte-identical across native baseline and candidate.
  The user's checkout and installed CLI were untouched; no external app was
  restarted. This closes the F5c native test-path gate, not other native-analysis
  or end-to-end practical-readiness requirements.
