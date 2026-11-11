# Non-shipping focused parameter experiment

This harness is an experimental consumer of existing internals, not a CLI option.
No application execution, automatic callee discovery, public receipt publication,
resume contract, or modifications to `src/` are involved.

## Operator preparation and review gate

Do not run native captures until independent implementation review is complete.
First create an owner-private **full disposable clone** of the original owned
no-analysis import project. Inventory the original before and after the session.
The harness requires no active analysis and always copies `import_program_path`,
never an analyzed Program. Leave original imports, index, binaries and receipts
unchanged. Source/import/dependencies/scripts and clone metadata are pinned and
rechecked. Each invocation creates a separate private attempt and whole worker;
there is no multi-job JVM. Do not retry after uncertain termination/integrity.

Run from this checkout, with its `src` on `PYTHONPATH`:

```sh
PYTHONPATH=src python analysis/focused_parameters/harness.py \
  /private/path/to/disposable-import-project caller \
  --ghidra /path/to/ghidra_12.2_PUBLIC --java-home /path/to/pinned-jdk \
  --trust-owned-input --disposable-import-clone
```

Run `prepared`, then `inferred` only after inspecting each prior attempt. Repeat
each arm once if the first runs are sound. Each uses a new Program copy. The
explicit clone/trust flags are operator assertions, not permission expansions.
The unchanged sandbox only permits writes under the attempt's worker subtree.
The supervisor request, pins, sandbox and operation metadata are outside it.
The wrapper, superclass, preparation and bridge scripts occupy one script bundle.

## Frozen inputs

Only two reviewed owned binary identities are allowed in source. There is no
arbitrary binary hash/address command-line override.

- Swift positive: `53345f8f9ae61fb42d41136fdf1d1733c9bdd7bf6410bbe676ebb03a09e5eaa0`, caller `0xc2c`, callee `0xbec`, BL `0xc48`.
- Hidden-context assembly control: `210b766cf884c408b39abbebcff34d6e1ac74440883da86b03987d2aeab745f1`, caller `0x2c0`, callee `0x2d4`, BL `0x2c8`. Source is the separately frozen owned `analysis/owned_hidden_parameter.s`. Its `x20` live-in does not authorize ordinary-parameter or runtime identity claims. Report the actual skip/failure/result rather than presume which reason Ghidra will return.

Both functions use the unchanged exact-focus selector. The selected direct edge
is decoded from pinned caller bytes; function extents are independent and bounded.
Native wrapper validates all p-code operations, including dead operations returned
by `getPcodeOps()`, against the separately pinned callee extent before parameter
commit and after redecompilation. Unknown/nonmemory/outside addresses, zero or more
than 100000 operations fail closed. Existing return/storage/eligibility guards
remain inherited. No signature is supplied from source.

## Artifacts and interpretation

`experiments/<id>/operation.json` is a **supervisor-only experimental operation**.
Its `mode=query`/`job_id` fields only activate the existing launch/ownership gate.
An operational `complete` is not evidence approval. `assessment.json` means raw
reports passed pinned checks, not source correctness or product readiness.
`failure.json` retains failures; all raw worker reports/logs remain private.
No `query-result.json` or normal publication exists.

Independently compare caller pseudocode and machine evidence across A/B/C, source
and assembly. Preparation alone (B) can affect the result. Check exact parameter
and unchanged-return reports, and don't promote static evidence to runtime claims.
Native preparation-failure and unsupported-input controls remain required.
The structural tests below only test host-side guard rejection; they do **not**
claim to have injected native escaped p-code or to have run Ghidra. A native scope
checker rejection control and actual native escape are distinct, still-unrun gates
until separately recorded. No performance/product-readiness claim is permitted.

```sh
PYTHONPATH=src python -m unittest discover -s analysis/focused_parameters/tests -v
```

## Separate owned native controls

After independent review, use a private full import-only clone of the frozen
positive Swift project. Each command gets a fresh Program copy and whole JVM:

```sh
PYTHONPATH=src python analysis/focused_parameters/controls.py \
  /private/path/to/disposable-import-project prep_digest \
  --ghidra /path/to/ghidra_12.2_PUBLIC --java-home /path/to/pinned-jdk \
  --trust-owned-input --disposable-import-clone
```

Run `prep_rollback` and `ast_scope` separately, inspecting each result first.
`prep_digest` tests an injected extent-digest refusal before preparation;
`prep_rollback` tests an injected invalid-tail refusal after disassembly and
transaction rollback; `ast_scope` tests a deliberately injected dead AST operation
outside the selected body. None demonstrates a naturally occurring decode failure
or native decompiler escape. Repeat successful controls only in fresh workers.

Reports use `macscope-owned-native-controls/1`, with exact refusals, independently
bound memory proofs, preserved observable-state snapshots and runtime checks.
`control-assessment.json` is not an inference assessment or a product receipt.
No synthetic graph is exported or allowed to reach parameter commit. Generic
errors, missing evidence, snapshot read failures or unexpected mutation remain
failures, not successful negative controls. No retry on uncertain teardown.
