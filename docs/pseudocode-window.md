# Bounded recorded-token pseudocode window

Opt in on decompile or jobs resume with `--format window` and exactly one of
`--window-token-start N` (exact recorded half-open UTF-16 token start, zero-based)
or `--window-address 0xVA` (unslid address inside an inclusive recorded range).
No fuzzy text or nearest-address match. Missing/conflicting anchors, or anchor
options with another format, are usage errors before execution. Existing native
command semantics stay unchanged; offline use resumes an already published job.

Support exactly one function, not implicit batch selection. Validate all spans
against untouched pseudocode using existing UTF-16 and surrogate-boundary rules.
Bounds before validation: 1 MiB UTF-16 text, 8192 spans and 8192 total ranges.
Missing/invalid/stale/oversized maps are unavailable, not guessed. Address matches
in multiple spans remain ambiguous: show count and up to eight exact token starts
for explicit reselection, never silently choose. Unique anchor displays original
half-open offsets, escaped token text (up to 160 characters), full token presentation-line extent, at most eight inclusive ranges, mapping
status, function identity and source job. No whole-line ownership is claimed.

At most 40 code lines and 16 KiB total: up to ten lines preceding first anchored
line, remainder after; near EOF shift left to use available context. Preserve
one-based newline-separated presentation indices including blank lines, not
recovered source line numbers. Multiline anchors outside the window are explicitly
counted. Clip each line to 256 original characters before terminal escaping, mark
clipping, warn the visible prefix may not include the anchor. Mapping always uses
full original text, never clipped/escaped coordinates. Reserve footer space and
report exact omitted context/anchor-line counts when byte budget reduces output.
Raw data, receipts, defaults and existing exit statuses remain unchanged.

Acceptance: owned beyond-line40 anchor, repeated address ambiguity, multiple
ranges, non-BMP/multiline/newline boundaries, invalid/missing spans, empty code,
limits/escaping, query and snapshot coverage, no mutation; full suites, independent
review, installed offline replay without jobs, blind owned-fixture reader check.


Example offline navigation:

```sh
macscope jobs resume SAVED_JOB --project WORKSPACE --format window --window-address 0x1000
macscope jobs resume SAVED_JOB --project WORKSPACE --format window --window-token-start 654
```

An ambiguous address reports candidate UTF-16 starts; explicitly choose a token
start from those recorded coordinates. Window availability does not change the
underlying command exit status: a complete receipt can yield an unavailable
presentation anchor. Read the visible window result, not exit0 alone.

## Validation record

932 primary and 115 analysis tests passed on Linux. Independent review approved
full-map validation, UTF-16 boundaries, ambiguity reporting and early batch
rejection. Its worst-case metadata/control-character check stayed within 16 KiB.
An isolated installed wheel replayed an owned cached 80-line function and exposed
the mapped `owned_increment` token on line56, outside the former initial preview.
Repeated output was identical, partial exit6 persisted and every project file
hash remained unchanged. A blind reader found the anchor, correctly limited the
mapping to its token, and identified partial coverage and omitted context without
inferring execution. Feedback led to explicit token text and clearer presentation
line wording. This fixture tests evidence access, not decompiler accuracy.

The same final installed CLI also resumed the actual owned native writer receipt
with nonexistent engine paths. Two outputs were identical, retained complete
receipt exit0, showed source job and exact token coordinates, and changed no
project file hashes. No fresh native capture, native full-suite run, inspected app
execution, system CLI installation or Taskovsky session was performed in this
presentation slice. Existing raw JSON and receipt contracts were not changed.

## Ambiguous-anchor candidate previews

A saved-receipt workflow exposed a concrete navigation cost: an address can map
separately to a call name, arguments and punctuation, but numeric token starts
alone require manual extraction from the full JSON to choose a token. Add text
previews only to the existing ambiguous-window presentation, after full mapping
validation. Preserve the first eight matching spans in existing recorded order,
exact UTF-16 half-open start/end and total/omitted counts. For each display at most
80 Unicode code points of the exact recorded token, terminal-escaped, with an
explicit clipping marker. Do not trim or reconstruct token text. Newlines and
controls must stay on one escaped presentation line. Preserve the 16 KiB total
window bound by stopping previews before the escaped header plus preview bytes
exceed 15 KiB, reserving 1 KiB for fixed footer/omission text. Report preview
omissions separately from omitted numeric starts. Preserve raw JSON, receipts,
ambiguity status and inherited command exit.

Do not automatically select a candidate, rank meaning, infer line ownership,
interpret punctuation or follow a target. An explicit start still uses the same
validator; invalid duplicate/overlapping starts remain rejected rather than resolved. No new command,
engine job or semantic claim. Acceptance: independently authored tokens sharing
an address (including punctuation, non-BMP, multiline/control and long text),
more than eight candidates, invalid-map refusal, deterministic output, unchanged
input, output budget and existing explicit-anchor behavior; independent review,
full suites and isolated installed offline replay. No private code in tests/docs.

### Candidate-preview validation

973 primary and 115 analysis tests passed in the cloud. Independent review caught
and corrected a combined escaped-metadata/preview byte-budget overflow; the
regression now verifies explicit omissions within 16 KiB. All 12 focused window
tests passed independently. Generic owned fixtures cover non-BMP coordinates,
controls, punctuation, clipping, candidate caps and invalid-map refusal.

An isolated installed wheel repeated a private saved-receipt replay with engine
paths unavailable. The ambiguous view now exposes bounded candidate text while
remaining ambiguous and requiring explicit selection. Existing dossier, links,
JSON and explicit-token window stayed byte-identical to their pre-change outputs;
partial evidence exits remained partial. Project file hashes and existing job
inventory stayed unchanged after separately recorded transfer/setup. No new
capture, app execution, system installation, Taskovsky session, fresh full Mac
suite or general pseudocode-accuracy claim is made. Private evidence is not part
of the repository or these independently authored tests.
An independent reader compared the saved before/after view and confirmed that
candidate text removes manual token extraction while preserving explicit
selection and ambiguity. That is a scoped navigation assessment, not live use.
