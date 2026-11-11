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
