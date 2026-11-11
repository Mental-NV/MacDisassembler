# Stage B validation record

Validation dates: 10–11 November 2026 (UTC). All inputs in this record are project-owned
assembly fixtures. They were built and inspected statically, never loaded or
executed. No installation, third-party app analysis or Linux execution was
performed.

## Source and cloud checks

Base: PR #5 head `54565019d66fe568e1923d1f38c1ac8c2f6dd00d`, tree
`aebf97f5b3d4d515fe48480be8f785631c1f7b33`.

Runtime source fingerprint:
`0e3a72e7722fd21a0283a951522b32f3ebe129010539d9d865774c757e5ccf42`.
This is SHA-256 of compact, key-sorted JSON mapping repository-relative `src/`
Python/Java/JSON paths to their SHA-256 values, excluding bytecode. Both cloud
and Mac independently computed the same 69-file manifest.

The following passed from the source tree:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python3 -m unittest discover -s tests -q
# 602 tests
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:analysis \
  python3 -m unittest discover -s analysis/tests -q
# 106 tests
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests python3 -m unittest \
  test_flow_gap_evidence test_flow_gap_classification test_flow_gap_policy_resume \
  test_saved_flow_gap_evidence test_trap_flow test_focused_boundaries \
  test_focused_tailcalls test_flow_boundaries test_query_resume -q
# 129 tests
```

The dependency-free wheel builder produced
`macscope-0.2.0-py3-none-any.whl`, SHA-256
`bc942a233e4b743b6720fefb03bee86d84a4a1c8c35ddae52d565946941b43ff`.
All 69 packaged runtime members matched their source bytes. The wheel was not
installed. `git diff --check` passed.

Independent review found an ARM64 false-positive risk: an unrelated unknown
jump could enter the LDR/BR portion of the wrapper. The classifier now refuses
promotion when such an entry cannot be excluded, including when that jump's
CFG block is absent. Positive ordinary-handler cases remain accepted. Negative
tests also cover fabricated/rehashed receipts, malformed source collections,
weak/flat/ambiguous bindings, byte and policy mismatches, and legacy replay.
The final analyzed-request review additionally required a policy pin so removing
every result extension cannot downgrade validation, and moved the body-range
cap ahead of instruction indexing. Production rehash attacks, no-gap captures,
legacy request resumption and unsupported switch-policy combinations are covered.

## Live owned focused checks

The final runtime used an existing Mac toolchain: Ghidra 12.2,
JDK 25.0.5.0.3 and Python 3.14.6.
No toolchain was installed or updated. Use a nonhidden output directory because
Ghidra rejects project paths containing hidden components.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
MACSCOPE_GHIDRA="$GHIDRA" MACSCOPE_JAVA_HOME="$JDK" \
python3 tests/integration_flow_gap_evidence.py \
  --output-dir "$ARTIFACTS/final-live" --arch both
```

The command passed. Each architecture was compiled and imported separately,
without whole-image autoanalysis. All eight focused queries used public
`decompile --from-import --address ... --arch ...` with the explicit owned-input
trust flag. The result matrix was the same on both architectures:

| Selected function | Outcome | Residual gap evidence |
| --- | --- | --- |
| Handler | Complete, exit 0 | No residual gap |
| Import-pointer wrapper | Partial, exit 6 | Verified linkage boundary; runtime target unresolved |
| Wrapper-named register jump | Partial, exit 6 | Unclassified |
| Same-image branch escape | Partial, exit 6 | Unresolved internal transfer |

The handler's full selected bytes independently matched the fixture slice:

- arm64: `020040b95f00016b40000054010000b9c0035fd6`.
  LDR/CMP, BEQ over STR, RET.
- x86_64: `393774028937c3`.
  CMP, JE over MOV, RET.

The checked byte oracle establishes the owned local compare/conditional-write
behavior. The wrapper-to-handler direct call was separately linked from
selected receipt bytes. It does not resolve the subsequent runtime import
implementation or establish any real application's behavior.

On x86_64, Apple disassembly and dyld fixups independently showed the
RIP-relative import-pointer jump and `_puts` binding. Ghidra reported an
outside-body computed edge to a synthetic destination instead of a missing
computed-jump destination. The implementation correlates this raw edge with
the exact source and independently decoded slot; it preserves the synthetic
edge destination and both original warning-only gaps.

The original fixture hashes and on-disk imported Program digests remained
unchanged. Final fixture SHA-256 values:

- arm64: `5bebce46cbcb0d4551864bd82f46275f26f2e7f56215bceff284c5c04eed8d1a`.
- x86_64: `b01b9e1363a5a0b139f322711d2f0ff777ec007980858a50c87141820e7b101f`.

Final Program digests:

- arm64: `af9229cea5de118f2eb432409ab29b5d3d2da7972c03622003f97b9b131f2440`.
- x86_64: `b0f5c016f211553c35acc968ab4caf8ccbfce440e91522c51c11d367e16df0be`.

With the original external fixture paths temporarily unavailable and engine/JDK
paths set to nonexistent locations, saved receipt replay and repeated selected
JSON/HTML exports passed. Immutable project slices remained present for byte
verification. The receipt bytes were unchanged and no offline job was created.
The final reader also replayed all ten original PR #5 focused receipts without
adding new fields or changing pseudocode/instructions/gaps, and reproduced
that corpus's JSON/HTML exports deterministically.

Restart of an interrupted original v2 job under changed runtime identity was
safely rejected as `job_resume_engine` without a new job. It is not counted as
a successful cross-runtime restart. Same-runtime v2 policy preservation is
covered through the production-path unit regression.

An optional corruption test on a private copied project stopped at the
read-only immutable slice with `PermissionError`. No permission change or
alternate write was attempted; no bytes or original receipts changed. This
specific live tamper attempt is not counted as an integrity-rejection test.
Actual source-byte comparison and malformed-byte unit negatives passed.

## Scope of acceptance

- **B1:** Passed on both separately compiled architecture builds: supported owned handler
  effect, separate verified call, and retained unresolved import boundary.
- **B2:** Passed: internal escape remains partial; raw warning sites and unknown
  register transfers stay explicitly unavailable/unclassified.
- **B3:** Passed for implemented paths: focused live capture/replay/handoff,
  unchanged legacy receipts, and production cached/fresh analyzed projection
  and validation regressions. Unpinned legacy snapshots and switch-assisted
  fresh queries deliberately keep their old contract.
- **B4:** Passed: name/selector labels do not establish linkage or a unique
  runtime callee. Positive linkage retains `runtime_target=unresolved`.
- **B5:** Final live focused source/identity, partial exits and deterministic
  exports passed. Public trust/timeout/cancellation details are recorded below.

The [current contract](flow-gap-evidence-v2.md) documents unsupported encodings,
bounds, conservative classifications and the analyzed-query exception. Stages
C/D, installation, Linux execution and a batch command remain separate work.

## Final-runtime public lifecycle checks

These checks used the final runtime fingerprint above and new jobs in the
owned arm64 project; successful query receipts were preserved.

- Omitting `--experimental-trusted-input` returned exit 3,
  `isolation_required`, without creating a job.
- A real `--timeout 1` focused query returned exit 7, `worker_timeout`, in
  1.813 seconds. The job persisted as `timeout` with no query receipt.
- `jobs cancel` against a running focused query returned exit 0. The supervised
  worker command exited 130 with `worker_cancelled`; the job persisted as
  `cancelled` with no query receipt.

A blocked host process-list check was not retried. The lifecycle conclusions
come from the exited public commands, supervisor results and saved job
manifests, not an unsupported claim to have enumerated all host processes.

Private generated receipts, Apple-tool output, deterministic handoffs,
`summary.json`, `final-verification.json` and lifecycle command/results are
retained outside the repository in the owned validation artifact directory.
No generated binary or recovered fixture output is published with the source.
