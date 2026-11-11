# Bounded opaque Objective-C pointee metadata

## Demonstrated need

The frozen owned stateful fixture records its predicate argument as `^?`.
Decoder v1 rejects the entire declaration, losing independently recorded return
and other argument types. Machine code calls a pointer and consumes W0, but does
not establish the source Boolean contract. No automatic signature inference is
justified.

## Contract

Decoder v2 accepts `?` only as the immediate unqualified target of `^` and
represents an unknown pointee. It does not identify a function, callable ABI,
argument list, return type, object class, or runtime target. Bare `?`, qualified
unknown targets, and malformed encodings remain unsupported or invalid. Existing
depth, node, input and output budgets remain enforced. Pointer qualifiers and
nested pointer containers retain their literal recorded structure.

The containing pointer retains the existing conditional Darwin pointer-register
container projection; this is not a callable signature or evidence of execution.
Pseudocode, engine signatures and saved receipts are never modified.

Version decoder output explicitly. Retain v1 decoding and type-sidecar replay,
redaction and comparison under the recorded decoder policy. Never recompute an
old v1 unsupported declaration under v2 and treat it as the original observation.

## Acceptance

- Owned `Q40@0:8r^{?=qQII}16Q24^?32` preserves return, receiver, selector and three
  explicit arguments; the last pointee is explicitly unknown.
- Bare/qualified unknowns, truncated pointers, budgets and trailing bytes fail
  conservatively; no implicit Boolean or function signature.
- v1 output and saved sidecar validation remain reproducible.
- v2 sidecars reject tampered decoded facts and policy mismatches.
- Raw focused pseudocode and original project bytes remain unchanged.

## Validation

The candidate passed 969 primary and 115 analysis tests. Independent review ran
30 focused tests and compared 28 cases against the genuine pre-change v1 decoder
with exact equality. A fresh installed wheel decoded the actual owned method
metadata twice identically and replayed all three native receipts with unavailable
engine paths and unchanged project-file hashes. These are cloud replay tests of
native evidence, not a fresh native test suite for the changed Python decoder.

No inferred callback signature or Boolean return contract was added. Recorded
`^?` now preserves surrounding metadata without making the unknown pointee known.
