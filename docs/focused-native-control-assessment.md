# Owned native-control assessment

This records the [negative-control protocol](focused-native-controls.md), not a
public feature. It complements the [positive feasibility result](focused-parameter-assessment.md)
and the [unimplemented opt-in design](focused-callee-product-design.md).
No production source, ordinary receipt or installed CLI changed. No fixture
application or Taskovsky session was run.

## Observed outcome

The three controls each passed once and repeated once in separate disposable
Program copies and worker/JVMs using stock pinned Ghidra 12.2. All six produced
`expected_refusal_checked` only after both native stages and host validation.

| Control | Exact native refusal | Meaning |
| --- | --- | --- |
| `prep_digest` | `Program extent bytes differ from the verified slice` | Deliberately mismatched proof rejected before preparation. |
| `prep_rollback` | `Invalid tail-call source or destination` | Deliberately invalid tail proof rejected after disassembly; observable state restored after the script transaction ended. |
| `ast_scope` | `Native operation outside independently pinned extent` | Real Java guard rejected a deliberately inserted out-of-extent operation in an otherwise checked HighFunction. |

These are **injected negative controls**. They do not show that the decompiler
naturally escaped the selected body, that genuinely unsupported instructions were
handled, or that all possible mutations/ABIs/inputs are covered.

The fixed owned input remains SHA-256
`53345f8f9ae61fb42d41136fdf1d1733c9bdd7bf6410bbe676ebb03a09e5eaa0`,
caller `[0xc2c,0xc98)` and callee `[0xbec,0xc2c)`. Native source was pinned to
remote commit `98396ac1e8eb9441878cdce3708ff028234f2325`, tree
`f0df57feb31a6a6490038126d4bba5e138127e88`, before testing.

## Evidence and preservation

Each report binds the pending first-stage observation and its hash to the final
second-stage report. Before/after inventory strings and hashes agree exactly;
repeat final reports are identical without normalization. Every Program copy
matched its normalized import pin, and the original project's 180-file inventory
remained unchanged. Process checks after each worker found no remaining owned
Ghidra/decompiler processes. Existing failed attempts were not rewritten.

Preparation snapshots contain 58,391 actual code-unit rows and are 1,705,764 UTF-8
bytes each. AST snapshots contain 58,262 rows and are 1,704,343 bytes each. All have
26 block records, below the unchanged 4 MiB inventory and 100000-unit caps. The
compact representation retains one row per observed unit, not grouped ranges or
hashes substituted for content.

The actual Program map records `__LINKEDIT[0xd978,0xffff]` and
`EXTERNAL[0x10000,0x105ff]` as uninitialized and non-mapped. Their unit values are
explicit nulls, not fabricated zeros. The caller/callee records still contain
real bytes checked against their immutable extent hashes. Marker equality means
equal reported range/initialization state, not knowledge of unavailable contents.

AST controls report a prior positive callee scope check, the injected operation
at end-exclusive address `0xc2c`, and no successful check appended for that
rejected graph. All controls report zero parameter commits, no inference and no
graph export. No synthetic graph was passed to a later decompilation or published
as pseudocode. These statements concern the reviewed code path and recorded
observable evidence, not a comprehensive audit of every internal Program state.

The frozen packet contains 60 raw/staged/report/snapshot/provenance/diagnostic
files, with manifest SHA-256
`ce70dce5ed3733b1711af7a215b7ef4a72a443100dc69ab1ec63b9e79b20d378`.

An independent evidence-only reader verified all 60 hashes and recomputed the
request, control-request, pending-stage and inventory bindings. It compared the
actual before/after strings, not just reported hashes, and confirmed byte-identical
requests, stages, snapshots and final reports within each repeat pair. The unit
table accounts for 67,072 contiguous address bytes, including 11,400 explicit
uninitialized null-byte rows. This review inspected neither source/oracle nor
executed an engine or fixture application.

## Retained failures and harness corrections

Two earlier `prep_digest` attempts failed **before** reaching the intended refusal:

1. The initial snapshot attempted to read uninitialized `__LINKEDIT` padding at
   `0xd978`. Host validation correctly rejected the missing control report.
   Explicit live-map-backed uninitialized markers replaced that read; ordinary
   initialized read failures and mapped/unknown/cross-block units still fail.
2. Repeated per-unit metadata exceeded the snapshot byte cap. Deduplicated block
   and kind tables plus compact unit tuples removed repetition without omitting
   units, grouping them, or increasing any cap.

Neither is counted as a passing control. Separately, source review caught that
nested script transactions defer rollback until the outer script ends. Two
consecutive pre-scripts now observe the refusal and then verify restored state
across that actual transaction boundary; no manual transaction ownership changes
were introduced.

Review also caught omitted JSON null fields. An explicit null-preserving Gson
configuration is used throughout control serialization. The standalone owned
serializer test passed on the pinned Mac toolchain before controls ran; it is a
JSON unit test, not fixture application execution or decompiler validation.
Its source hash is
`21c59206a1b9d7686e4b525796900ade75bd3378a92b185aea039a778061f3b3`;
the pinned Gson jar hash is
`dd0ce1b55a3ed2080cb70f9c655850cda86c206862310009dcb5e5c95265a5e0`.

Twenty-four structural/mock Python tests passed independently. No full product
suite or remote-CI success is claimed for this analysis/docs-only checkpoint.

## Diagnostics and remaining product gates

All workers retain `OS Truststore load failed: X509 trusted CA certificates not
found` and the known cache-maintenance daemon null-pointer exception. Startup is
not described as clean. No cache permission, network or trust override was added;
raw logs remain part of the evidence despite successful control reports.
The recorded heap cap is 2048 MiB, but there is no hard process-memory limit.
The 512 MiB storage monitoring threshold is not a hard filesystem quota.

These results close the **specified owned injected-control experiment**, not the
public implementation matrix. The proposed opt-in request, receipt and origin
identities remain unimplemented. Production-path isolation/publication,
provenance and strict offline replay/resume, legacy compatibility, consumer
integration and native end-to-end regression still require implementation and
independent validation before shipping. No automatic callee discovery, source
signature injection, hidden-context recovery, inferred indirect target, persistent
worker, performance or hostile-input safety claim follows from this result.
