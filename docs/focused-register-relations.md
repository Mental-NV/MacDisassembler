# Saved focused-query register relationships

Spec first. Add an engine-free `register-relations` command requiring project,
exact published import-focused query job, explicit unslid `START:END` (exclusive
end), and explicit `--abi aapcs64`. JSON/text only. It derives conditional machine
register facts, not pseudocode corrections, source prototypes, Swift ABI recovery,
indirect targets or runtime effects. Existing commands/receipts remain unchanged.

Verify the published job using existing explicit-receipt selection and focused
query integrity validation (including original/resumed producer, image, saved
slice, extent and instruction bytes). Require arm64 and an aligned, nonempty
range wholly inside the exact selected function extent, at most128 instructions
(512 bytes). All selected rows must be unique/contiguous and match imported bytes.
No silent nearest-boundary selection or fallback engine capture.

Reuse callback_evidence's reviewed byte interpreter through an explicitly derived
in-memory selection, not by presenting it as an original disassembly receipt.
Bind parent envelope digest and image/slice/Program/function/requested/publication
job identities, selected range, shared decoder policy and derived-input digest.
Expose selected call sites with register-input provenance, memory-load/store facts,
call/unsupported-instruction gaps and interpretation end. Keep legacy callback
role requirements out of this new view. New policy:
`macscope-focused-register-relations/1`; shared decoder policy remains separately
recorded. No existing decoder-policy meaning changes.

Explicit hypothesis: execution reaches the selected range; direct callees return
normally and obey the selected AAPCS64 preservation convention, with arbitrary
memory effects. Register origins are range-local inputs; only when range begins
at verified function entry are they also entry-register values. Post-call
`call_clobbered` values remain opaque register values identified by call site,
not typed/meaningful return values. x20 can be observed but is not labelled as a
verified Swift object or argument. No assumed target from a matching field offset.

Use existing no-conditional-path mode. TBZ and other unsupported instructions
stop interpretation with a visible barrier; do not delete or skip them. A local
range after a guard may be explicitly selected, but its reachability from entry
remains unknown and its facts cannot be composed across the omitted guard.
For the owned assessment, the full caller range can expose the first direct call
then stops at TBZ; a separately selected range beginning at the projection call
can expose post-call register forwarding up to BLR. Neither proves a whole-function
path or that the indirect call reaches the concrete sink.

Always return partial evidence (exit6) with explicit static/path/ABI limitations,
even if the selected straight-line prefix decodes fully. Bound the canonical JSON data report (not pretty/text envelope output)
to1MiB and reject oversize rather than silently omit dependencies. Preserve source
query status and coverage/gaps separately; don't upgrade a partial source query.
No annotations, saved receipt changes, new jobs, engine calls or installation.

Acceptance before publication: independently authored positive register moves,
post-call forwarding, prologue prefix and memory effects; overwritten-register,
intervening-call, unsupported/TBZ, wrong slice/bytes, malformed/noncontiguous range,
boundary/cap and wrong/unpublished/stale job negatives. Range after a barrier must
remain explicitly range-local. Existing callback tests/output unchanged. Full
primary/analysis suites, independent design/code review, isolated installed replay
of owned native receipts with engine paths unavailable and unchanged file hashes.
Do not publish private application evidence. Any unsupported full-path requirement
remains a blocker, not a reason to weaken the interpreter.

## Usage and validation

```sh
macscope register-relations --project PROJECT --query-job PUBLISHED_JOB \
  --range START:END --abi aapcs64 --format json
```

Replace START:END with exact lowercase unslid hexadecimal addresses within that
receipt's selected function. Selecting a later local range does not establish
that execution reaches it. Use text for the same report tree; it is not a compact
pseudocode rewrite. `call_clobbered` identifies an opaque register value after a
particular call, not a declared return type. Errors remain errors rather than
being downgraded to partial evidence.

981 primary and115 analysis tests passed in the cloud, including eight new
regressions. Independent review approved the unchanged decoder reuse, receipt
validation, provenance separation and conservative barriers; additional128-row
stress tests remained within the canonical-data budget. Actual CLI tests verify
exit6 and reject altered saved input bytes. Legacy callback tests remain green.

An isolated installed wheel replayed the owned Swift caller's full range and
separate post-projection range twice in JSON and text, with nonexistent engine
paths. All eight invocations returned6 and repeated outputs matched byte-for-byte;
all portable project hashes stayed unchanged. The full range exposes the first
call's unchanged entry x0/x1/x2 then stops at TBZ. The separately selected local
range exposes the prior call's opaque x0 value copied into x20 before BLR, without
proving the local range is reached or identifying the indirect callee. Source
query completeness is preserved separately from relationship-view partial status.
No native recapture, system install, Taskovsky restart, prototype injection,
raw-pseudocode edit, private evidence publication or fresh full Mac suite is claimed.
An independent output reader confirmed both register relationships are now visible
while TBZ remains a barrier, the local range remains independently conditional,
and the indirect target stays symbolic. This is a scoped evidence-usability check,
not live runtime verification or a stronger Swift decompiler accuracy claim.
