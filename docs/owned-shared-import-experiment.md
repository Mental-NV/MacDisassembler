# Owned shared-import preparation experiment

Test-only feasibility work for [the import bulk design](import-bulk-preparation.md).
It does not add a production command, change the exporter, or promise speedup.

## Run on the supported Mac toolchain

```
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/integration_shared_import.py \
  --run --out /private/tmp/macscope-owned-shared-NEW
```

The destination must be new. The harness accepts no target binary, function
selection, custom script or arbitrary-input flag. It compiles the fixed repo-owned
`fixture/batch/owned_batch.c` using existing clang, imports it without autoanalysis,
and selects exactly `_owned_add`, `_owned_select`, `_owned_mix`. No fixture is
executed. Every job and raw result is retained; no automatic cleanup occurs.

The custom Java script is staged inside each disposable job and uses the existing
Seatbelt profile, worker ownership/start gate, startup/chunk timeout and sampled
storage/log limits. It uses read-only Program persistence and no autoanalysis.
The baseline import hash and copied Program content hash are checked after every
trial (only existing backup-file exclusions). Plan/script hashes must still match.
The existing worker supervisor finishes teardown before the next trial starts.
This does not establish a new per-entry native disposer fence.

## Experiment boundary

Three fixed entries, three shared sessions, five calls each:

- Ascending preparation, calls A/B/C/A/B.
- Descending preparation, calls A/B/C/A/B.
- Ascending preparation, calls B/A/C/B/A.

The complete selection, executable byte extents, existing-body conflicts and call
order are checked before preparation. Bounded disassembly computes all bodies
before functions are created. This tiny owned experiment rejects decoding gaps;
it is not a general partial-output implementation. No tail-call flow overrides or
type/signature recovery are applied. Preparation is frozen before decompilation.

Captured records contain entry/name, signature, body ranges, instruction
addresses/bytes/flow, C text and completion/error. Same-membership preparation
records must agree. All captured fields are compared for repeated/cross-order
calls. This is **not full production evidence**: xrefs, CFG, tokens, ownership,
flow-gap proofs and detailed coverage facets are outside this experimental record.

Three separate production `decompile --from-import` receipts are retained as
baselines. Comparison to them is explicitly only C text, body ranges and
instruction addresses/bytes. No type/body/coverage fields are normalized away to
claim full equivalence. `sampled_order_acceptance` means only these sampled
preparation/repeated-record checks; it is not production acceptance.

## Observations

On the owned fixture, preparation records matched and captured records were stable
for the sampled call orders. All15 calls and three isolated calls completed.
Bodies and instruction bytes matched isolated baseline for all three functions.
C matched for two functions; `_owned_mix` differed: shared preparation resolved
callee names `_owned_select` and `_owned_add`, whereas isolated output used
address-based `func_0x...` names. This is visible shared-state behavior, not a claim
of semantic equivalence or recovered original source. Both modes still inferred
an imperfect return signature for this fixture.

The original import and disposable on-disk Program contents remained unchanged.
The initial smoke attempt stopped on a harness checkpoint overwrite error after
two successful shared jobs; it is retained separately. The corrected checkpoint
explicitly replaces only the experiment's own aggregate trials record.

## Remaining gates

No cancellation/timeout/malformed native request, worker death, publication
interruption, maximum-scale, adversarial overlap/stub/shared-tail or broad
order-dependence matrix has been run. Python unit guards test bounded orders,
existing-output refusal and incomplete/mismatched output rejection. No live
fault-injection success is implied. No timing comparison or performance claim is
made. Additional owned controls and independent review are required before
implementing a production shared-import coordinator or touching TickTick exports.

## Reviewed evidence identities

Final run (14 November 2026), SHA-256:

- Harness: `cdeda221b720753697e0a0c986ce334075e79baa96e1701c2a293a6f93f244ba`.
- Java script: `c650d233a720df646135b404185c9ec6f1c81bf53dfe50fc10baf5727d3c3581`.
- Fixture source: `ea5becc98546d65503ea71e49c39b1af6f2795116839ae53df5bf33338e09115`.
- Built owned input: `1fd6ec22d7019f3a4334d53cd1e62a2002b7705cf1c95689089f5d10c63f9df3`.
- Comparison report: `292ecf40afc8375dfb5a0655a5bb707ea5ec7224b25d828346e6b9ac7908d615`.
