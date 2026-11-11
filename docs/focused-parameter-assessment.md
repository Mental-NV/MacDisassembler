# Owned import-focused parameter feasibility result

This is a **non-shipping experiment**, following the
[specification](focused-parameter-feasibility.md) and the earlier
[analyzed-query assessment](owned-swift-parameter-assessment.md).
No product CLI option, ordinary receipt, installed runtime, or `src/` behavior
changed. No fixture application or Taskovsky session was executed.

## Decision

The owned positive supports a useful, limited route: prepare one explicitly
selected direct leaf callee in a disposable no-analysis import copy, then infer
its ordinary register inputs. This improves the selected caller's displayed
argument flow without whole-image analysis. It does not establish a safe public
API, complete Swift ABI recovery, source declarations, or runtime dispatch.

## Frozen protocol and evidence

The positive is the same owned Swift binary with SHA-256
`53345f8f9ae61fb42d41136fdf1d1733c9bdd7bf6410bbe676ebb03a09e5eaa0`.
Its source oracle remains
`d9c5740cc8e15d0028be9f74a1b42cf9668bbec2e5736880a199581ff2bfead1`.
The caller extent is `[0xc2c,0xc98)` and the selected leaf extent is
`[0xbec,0xc2c)`, connected by the direct BL at `0xc48`.

Each condition used a fresh Program copy and separate worker/JVM from the same
pristine import-only clone:

- **A:** caller preparation only.
- **B:** caller and explicitly selected callee preparation.
- **C:** B plus explicit parameter-only inference.

All three conditions ran twice. All six passed the experiment's host checks,
with complete caller reports and verified process teardown. A fresh, source-blind,
condition-visible reader verified all 54 packet files and its manifest hash
`e3e63dcec4d962ee47fb6d243d5a34dfce9726bf0bcca4f732d097292ee9427c`.
Each repeat pair's entire parsed caller function result was identical. The
reader froze its report before the source-aware reconciliation below.

## What changed, and what did not

A prints `func_0x00000bec()` without arguments. B gives that same zero-argument
call an imported symbol name, but does not recover its argument list. C displays
three inputs: `(param_1,param_2,param_3)`. Thus preparation alone is not the
observed argument-flow improvement.

C reports only the selected callee's `x0/8`, `x1/8`, and `x2/1` inputs as applied,
with `return_unchanged: true`. Both repeats record 20 callee native operations in
each check, twice before commit and once afterward. These checks use the pinned
callee extent, not a body expanded by inference. The caller independently reports
21 native operations within its own extent, with no reported outside operation.

Across all six captures, the caller's instructions, body ranges, CFG, recorded
xrefs, signature metadata and native-scope report are identical: 27 instructions,
three blocks and five reported edges. The low-bit branch and return provenance
remain unchanged. This is not new control-flow recovery. Source-aware inspection
of the frozen oracle and existing assembly agrees with the newly visible direct
call inputs: an inout record plus an optional integer lower to three machine
quantities. **Three inferred machine inputs are not three Swift parameters.**

The selected **caller's own four displayed input types** change to `long *`,
`long`, `char`, and `long`. This is separate from the three inputs displayed at
its call to the selected callee. These are inferred presentation, not verified
source declarations. The stored signature
still has an unknown calling convention and undefined/void metadata.
`return_unchanged` means preserved stored return type/storage, not a proven
source-correct return ABI.

The helper at `0xc98`, its returned context moved into `x20`, and the later
indirect target remain incompletely represented. No concrete runtime target,
full hidden-context ABI, feature parity, or source reconstruction is established.

## Owned unsupported-context control

The separately frozen [assembly](../analysis/owned_hidden_parameter.s) forwards
an input through `x20` to a leaf load. Source SHA-256 is
`92796990b2d3473b374ac51fde8e90f9ca256a912c747b97209b3aafcf62dc55`;
compiled binary SHA-256 is
`210b766cf884c408b39abbebcff34d6e1ac74440883da86b03987d2aeab745f1`.
It was compiled for static inspection, never executed.

A/B/C and one repeat each passed host checks. Both C captures skipped parameter application
with `unsupported_callee_parameters`, after checking two native operations before
commit. No after-commit check or applied entry was emitted because no parameters
were committed. This does not distinguish an unsupported inferred register from
zero inferred ordinary parameters; it does not prove explicit hidden-register
detection. Each repeat pair has identical complete function records. The frozen
negative packet manifest is
`18adae85aee7dec93aec0499c5d06c3191f4f5598aac40e4d2efc6930050a77b`.
The independent source-blind addendum verified all 54 file hashes and confirmed
that B and C have identical entire caller function records. The generic skip
report does not supply the rejected parameter list, nor make the empty displayed
argument list source-correct.

## Failures and diagnostics retained

The first positive A attempt finished natively but failed host provenance checks:
the experimental harness wrote indented tail-request JSON while the unchanged
verifier requires canonical compact JSON plus a newline. The failed attempt was
retained. The harness now uses the shared canonical serializer; byte-level tests
cover actual empty and nonempty tail-request file hashes. The verifier was not
relaxed, and the corrected run was a new attempt.

Fourteen structural/mock tests passed independently. These are not native
negative-gate results. The Java subclass compiled and ran on the Mac. The
original positive project's 180-file inventory remained unchanged. The negative
original and clone retained equal import-engine digests, byte-identical indexes
and zero analyses. All twelve worker Program copies matched their normalized
pins. Each run also
checked its source import, copied Program, binary/extent and dependency pins.

Every worker log retained `OS Truststore load failed: X509 trusted CA certificates
not found` and a
`FileCacheMaintenanceDaemon` null-pointer exception, despite successful scripts
and empty bridge warning/error arrays. Pinned Ghidra 12.2 source places the latter
in a separate cache-cleanup daemon with an unchecked `dir.listFiles()` iteration.
It is not evidence of decompiler-thread failure; a sandbox cause is plausible,
not proven by that stack. No cache permission, trust override or network access
was added. Startup must not be described as clean.

## Remaining gates and next step

Do not expose this as an automatic or generally validated product option. Before
public adaptation, exercise native preparation-failure and explicit scope-check
rejection controls, then specify versioned opt-in selection/provenance and replay
semantics with compatibility tests. An injected AST checker-negative test must be
labelled separately from an actual native decompiler escape; neither is supplied
by the positive captures or forged-report unit tests.

Keep selection explicit and bounded, preserve return/storage refusals and
read-only originals, and retain skips/partial results. No recursive expansion,
source-supplied signatures, inferred indirect targets, persistent-JVM lifecycle
claim, performance claim, or hostile-input safety conclusion follows here.
