# Recorded pseudocode token/address preview

Extend the opt-in `evidence --format dossier` reading view with a bounded token
preview. Existing raw evidence, JSON, other presentations, receipts and exit
codes are unchanged. This is navigation assistance, not improved decompilation.

Use only the dossier's selected pseudocode source: saved query when it supplies
a pseudocode field, otherwise the explicitly labeled saved-function fallback.
Never combine query text with snapshot spans. Validate the recorded UTF-16 spans
against that exact text with the existing `pseudocode.address_spans` validator.
For query-shaped coverage, require available=true, complete/partial status and
UTF-16 offsets before adapting its recorded coverage for validation. No code,
address, line mapping, body ownership or execution is inferred from token text.

Display at most four token entries, with half-open UTF-16 text offsets, the exact
recorded token text (bounded/escaped for display), and at most two recorded
inclusive address ranges each. Token offsets are not Python character offsets,
source lines or whole-line mappings. State that tokens may fall outside the
clipped code snippet. Keep partial coverage and exact omitted token/range counts;
whole evidence remains accessible with --format json/text. The dossier footer
counts preview-cap and rendering-budget omissions together; unknown counts are
explicit when malformed input prevents counting.

Processing caps before validation: 524288 text characters, 4096 spans, 16 ranges
per span. Oversize or malformed inputs make only the preview unavailable, with
an explicit reason; raw pseudocode still displays. Do not weaken upstream span
validation or silently accept malformed tails beyond the first four entries.
Missing/redacted/unavailable span coverage remains unavailable. Bounds are for
this view, not new limits on capture or raw reports. Existing dossier 12 KiB/96
lines per lead and 64 KiB/512-line total limits remain enforced.

Owned acceptance: ASCII/non-BMP tokens, valid and split surrogate boundaries,
partial/absent/malformed coverage, out-of-range/reordered offsets, invalid ranges,
query/snapshot separation, clipped text, processing caps, omission totals and
terminal controls. Include a reading exercise where a token can be matched to
its recorded instruction range without claiming semantic equivalence. Preserve
source objects and deterministic engine-free replay. No native analysis or
Taskovsky session is required for this presentation-only increment.

## Validation record

- Seven focused tests cover exact non-BMP UTF-16 extraction, split-surrogate and
  malformed-tail rejection, coverage/source separation, processing limits,
  omission counts, clipping and terminal controls. Full primary suite: 904 passed;
  analysis suite: 115 passed on Linux and macOS.
- Native verification used exact implementation commit 6740cb2 on macOS 27.0.1
  (26A434), Python 3.14.6, with default TMPDIR unchanged. No engine, compiler, UI,
  installed CLI or external app was changed or run for that test gate.
- Independent review approved the projection and budgets. Reviewer and separate
  synthetic-report reader both requested explicit endpoint conventions, now
  visible as half-open UTF-16 offsets and inclusive address ranges.
- The separate reader saw only the generated owned dossier and correctly found
  `return`, its UTF-16 interval after a two-unit emoji, its recorded machine range,
  selected-query provenance, and the distinction between zero preview omissions
  and partial recorded coverage. No semantic or performance benchmark is claimed.
- An isolated installed wheel's actual console entry point exported a saved
  synthetic snapshot with a positive token mapping twice outside the checkout
  with nonexistent engine paths. Output matched source rendering byte-for-byte;
  no new jobs appeared and the fixture's existing partial exit 6 was retained.
  This is owned offline presentation replay, not fresh native decompilation.
