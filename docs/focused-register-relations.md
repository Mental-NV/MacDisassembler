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

## Explicit bit-test fallthrough (v2, spec first)

Add `--bit-test-fallthrough` only to register-relations. Default v1 stays identical
and still stops at TBZ/TBNZ. Opt-in produces relationship policy2 and shared byte
interpreter policy8; it adds no public callback-command option. It allows only
fallthrough of byte-decoded ARM64 TBZ/TBNZ under explicit bit predicates, not
branch following, merges or inferred runtime reachability. The mode cannot mix
with the interpreter's separate CBZ/CBNZ or checked-add fallthrough modes. Those
forms and all other unsupported forms remain barriers in this v2 view.

Decode bit number as b5:b40 (bit31 and bits23:19), operation bit24, signed14-bit
PC-relative immediate from bits18:5 scaled by4, register bits4:0. Bits0..31 test
W register bits;32..63 test X register bits. Register31 means zero, never SP.
TBZ fallthrough requires the tested bit be set; TBNZ requires it be clear. Record
site/bytes, tested register/value, bit index, width, target/fallthrough address,
exact predicate, unverified versus statically satisfied and taken path unanalysed.
Do not interpret the guard as a Boolean source type or equate a post-call value
with a typed return. Retain every preceding normal-return/memory-effect obligation.

At most16 branch predicates; reject a self/backward target and stop. A known
non-relocated integer constant/zero-register or independently represented
zero-extended32-bit value can
make a predicate statically satisfied or impossible. Contradictory requirements
for the same bit of the same identity-bearing value stop interpretation. A moved
value preserves identity; an intervening call, clobber or different memory-read
site does not. Unknown values remain conditional, not satisfied by default.
Unslid ADR/ADRP addresses are not known runtime bits: their load slide is unknown.
In mode8, address-involving register ADD remains symbolic rather than folding to
a supposedly fixed integer; a genuine W result still zero-extends. Default mode7
output remains unchanged. No general SAT/path solving, alternate target inspection
or loop unrolling.

Expose path_obligations and path_mode in v2. Subsequent sites carry the guard-site
condition. Parent receipt, source coverage, ABI assumptions and all v1 limits
remain. The owned full caller may now conditionally connect the first call's bit0
set result to the later opaque x0-to-x20 flow and indirect invocation. It still
cannot prove the bit is set at runtime, the projection helper's type, the indirect
target, concrete save effect, durable storage or UI behavior.

Acceptance: independently assembled TBZ/TBNZ W/X bits0/31/32/63 and ZR; positive
and negative displacements; constant satisfied/impossible, contradictory same-bit
versus independent bits, copied/clobbered value identities, branch budget,
unsupported near-miss and mixed-mode rejection. Preserve all v1 outputs/tests.
Independent review, full suites and installed replay on actual owned native
receipts must show guard retained and later facts conditional, with bytes/jobs
unchanged and engine unavailable. No claim a conditional static path is feature
parity or runtime execution. No signature/pseudocode modification.

### Bit-test validation checkpoint

990 primary and 115 analysis tests passed in the cloud, including nine new bit-path
regressions. Independent design/code review caught two important requirements:
relocated addresses must not supply known runtime bits, and exact copied-address
identity must still detect contradictory predicates. Both fixes and regressions
are included only in mode8; old mode7 remains unchanged.

[The owned assembler oracle](../analysis/owned_bit_test_oracle.s) was assembled
statically with Apple clang21.0.0 (clang-2100.3.34.2), target
arm64-apple-macos14, and independently disassembled with Apple llvm-objdump.
Its source SHA256 is
`80ffcd5f02b112a5fc9ab7bcafca791852318675b65d8e91a6039d8617446eb9`.
Exact byte fixtures verify W/X bit boundaries, both operations, ZR, forward and
negative displacements. No object code was executed.

An isolated installed wheel replayed the existing owned Swift receipt in three
cases (default whole range, default local range, opt-in whole range), twice each
in JSON and text: 12 invocations, all exit6, byte-identical repeats and unchanged
portable file hashes/job inventory. Both default cases exactly match their saved
v1 outputs. In the opt-in whole range, the initial call's input registers and
later context forwarding are now connected only under the recorded, unverified
bit0-set predicate and both preceding normal-return obligations. The interpreter
stops at indirect invocation; no concrete destination or entire runtime execution
is proved. An independent output reader confirmed that the guard was retained,
not skipped, and runtime/prototype/target uncertainties remain visible.

Example (explicit hypothesis, not a recommended assumption for arbitrary code):

```sh
macscope register-relations --project PROJECT --query-job PUBLISHED_JOB \
  --range START:END --abi aapcs64 --bit-test-fallthrough --format json
```

This records a conditional selected path, not feature parity, native execution,
Swift type reconstruction or changed raw pseudocode. No fresh Ghidra capture,
system CLI installation, Taskovsky restart, private application artifact or full
Mac regression suite is part of this checkpoint.
