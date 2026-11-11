# Small scalar Objective-C declaration context

## Goal and boundary

The existing exact-function declaration sidecar rejects an entire method when
it encounters common Boolean or small-integer parameters. Extend the conditional
register-role context, not engine type recovery: no Ghidra signatures, raw
pseudocode, saved receipts or application state are modified. This helps a reader
match a declared flag/index to machine registers; it does not prove execution,
source types, runtime dispatch, or the absence of a variadic tail.

## Contract before code

Add version `darwin-objc-word-registers/2`, accepting only the previous subset
plus encoding codes c/C, s/S, i/I and B on arm64 and x86_64 Darwin. Report value
widths 8/16/32 (B: 8-bit storage representation, not a claim about upper bits),
integer signedness except B (Boolean representation, signed=null) and c
(integer representation, signed=null because source plain-char signedness is not recovered). A `c` encoding
cannot distinguish source signed char, plain char or a legacy BOOL typedef.
No source-level Boolean semantics are inferred from c.

Retain the full GP register container names x0..x7 / rdi,rsi,rdx,rcx,r8,r9;
`width_bits` is the declared value width, not register width, and no upper-bit
extension/validity is promised. The return register container remains x0/rax.
Argument ordinal, including hidden self/_cmd, still allocates registers.
Reject all stack overflow, floating-point/vector, block, aggregate, unvalidated
qualifier and unknown encodings, preserving all reasons. Do not add l/L.

Preserve report compatibility: newly requested sidecars use v2; validation and
diff must still recompute v1 reports using the original v1 rules byte-for-byte.
Reject unknown policies. No silent upgrade of a replayed report. Existing
reports without sidecars, defaults and graph completeness/exit codes do not
change. Dossiers must explain value width versus register container.

## Acceptance before readiness

Compile an owned no-SDK Objective-C fixture on Darwin arm64 and x86_64 with
current Apple Clang; inspect independently the encodings and emitted register
roles for each added code, mixed widths, and full register limits. Source is an
oracle, not input to the product's inference. Do not execute the fixture.
Unit tests cover both architectures, every added code, signedness/width,
legacy v1 reconstruction, unknown policy rejection, unsupported mixtures and
register overflow. Run full primary and analysis suites, independent review,
and a selected-method consumer example retaining unsupported/partial evidence.
If native validation is unavailable, report the blocker and do not claim the
extension compiler-validated or publish-ready.

## Validation record

The integrated candidate includes merged address-linked rendering (PR45); its
CLI and addressed-renderer blobs were independently checked against remote main
`2f0abfbeac1f1055679a927555249a4af67f6244`. On Linux, 915 primary and 115 analysis
tests passed. An independent reviewer recomputed v1 sidecars with the baseline
implementation for five supported/unsupported encodings and found byte-identical
results; final review also approved the conservative unknown c signedness.

An installed wheel, executed outside the checkout with unavailable engine paths,
replayed an owned Boolean-return method twice with identical dossier bytes,
retained partial exit 6 and created no new artifact paths. A blind reader correctly
separated the metadata's Boolean declaration from a contradictory saved engine
void signature and did not infer runtime execution or upper-bit validity. Return
width is now displayed explicitly following that feedback. The tool does not
reconcile or rewrite contradictory declarations and engine signatures.

Native macOS validation of implementation commit `d00febc` passed 915 primary
and 115 analysis tests. The compile-only arm64/x86_64 compiler oracle confirmed
c/C/s/S/i/I/B encodings, value widths and GP/return register containers. These
checks do not guarantee upper-bit validity; plain c signedness remains unknown.
The subsequent candidate commit changes documentation only. The owned fixture is
`analysis/owned_objc_small_scalar_fixture.m`, SHA-256
`afcbd2c39bc7ec6a31e859ada75e1b4f4e74ef0dccbfebdce51660b5a9562ccf`.
