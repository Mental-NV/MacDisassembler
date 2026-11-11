# Owned Swift: explicit callee-parameter recovery assessment

Protocol frozen before capture. This is a bounded source-aware experiment using
an existing opt-in feature, not automatic signature injection, new product code,
a default-policy change or private application analysis.

The [frozen owned Swift fixture](owned-swift-value-assessment.md) demonstrated a
direct call printed without inputs although recorded instructions preserve three
entry registers. Register relationships now expose that discrepancy but do not
change the pseudocode. Test the existing `--fresh --recover-callee-parameters`
option before considering any import-focused adaptation.

## Inputs and limits

Use unchanged OwnedValueDispatch source (SHA256
`d9c5740cc8e15d0028be9f74a1b42cf9668bbec2e5736880a199581ff2bfead1`)
and the previously captured arm64 dylib (SHA256
`53345f8f9ae61fb42d41136fdf1d1733c9bdd7bf6410bbe676ebb03a09e5eaa0`).
The prior image ID is `843eca84ff008bdaaab52b6f7a2b97a02d16ef4bd76482185b12c63d8c9c5cc5`;
it is not the binary hash. Create a new owner-private project. Never modify the original import-only
assessment, original binary/source or system CLI. The input is an owned fixture,
not an application to execute. Do not build/run it or invoke Taskovsky.

Pin actual CLI package/bridge, Ghidra/JDK and binary digests. Use stock pinned
Ghidra12.2 with existing isolation/trust checks. Import and analyze only this tiny
fixture under baseline with library loading disabled. Allow at most256 enumerated
functions, one worker, 2048MiB Java heap,240s total/120s startup/25s per-function
limits per engine operation. Preserve failures rather than silently retrying or
switching to a patched engine. If unavailable, report the blocked gate.

Select only the known caller at unslid0xc2c for fresh queries. Addresses and
questions are evaluator-selected, so this is not blind function discovery.
Capture ordinary fresh and explicit parameter-recovery output, then repeat each
once from the same unchanged analyzed snapshot (four selected queries maximum).
No return recovery, supplied source types, type hints or other recovery flags.
The existing feature may infer/commit parameters inside its disposable Program
copy; it must preserve return contracts and the saved original Program.

## Comparisons and decision gate

Freeze all receipts and their hashes before source-aware adjudication. Compare:

1. Previous import-focused output versus ordinary analyzed fresh: isolate what
   baseline analysis changes before attributing anything to parameter recovery.
2. Ordinary analyzed fresh versus explicit recovery: record verified paths,
   applied/skipped decisions, machine argument storage and return-unchanged proof.
3. Repeats and source/snapshot/Program identities: distinguish new query jobs from
   mutations to authoritative inputs or analyzed state.

An independent reader examines frozen outputs/instructions before consulting the
source oracle. Then compare with the original source/compiler assembly. Check
argument visibility/arity, guard preservation, post-call implicit context, return
contract, indirect-target uncertainty and coverage. Do not equate machine inputs
with source parameters or accept a plausible new prototype without evidence.
A skipped option is a valid observation, not a reason to force a signature.

Only a demonstrated useful improvement with no misleading recovered relationships
justifies a separately reviewed import-focused proposal. Otherwise record the
limitation and keep raw pseudocode unchanged. No performance or runtime-behavior
claim, product integration, installation or private evidence publication follows
from this experiment.

## Observed result

The experiment used stock Ghidra12.2, bridge1.15.0 and JDK25.0.5.0.3 on macOS
arm64. Import and baseline analysis succeeded; 40 functions were enumerated and
28/28 requested decompilations completed. All four selected fresh queries
completed. No fixture/application was executed, and no installed CLI or product
runtime was changed. This tests an existing isolated package, not a claim that
the latest repository wheel or a fresh full Mac regression suite was validated.

A fresh reader received only eight frozen captured JSON records and their hash
manifest, including prior focused results and baseline caller instructions. All
hashes matched. The reader froze a source-blind, condition-visible report before
source-aware reconciliation; this was not randomized blinding. The source and
compiler assembly were then checked separately.

Baseline analysis resolves symbolic names but the ordinary fresh caller still
prints the first direct call without arguments. Explicit recovery applies:

| Selected call | Inferred machine inputs | Observed pseudocode effect |
| --- | --- | --- |
| Caller to update helper | x0/8bytes, x1/8bytes, x2/1byte | Previously absent argument list becomes three explicit inputs. |
| Caller to projection helper | x0/8bytes, x1/8bytes | Two inputs recorded by recovery; ordinary pseudocode already displayed two. |

The update helper has two Swift source parameters, lowered into three machine
components: record address, Optional payload and Optional discriminator. Thus the
restored three inputs are supported, but are not three recovered Swift parameters.
Caller pointer/type presentation also changes; `long`/`char` and array offsets
remain inferred C-like representations, not reconstructed Swift declarations.

The recorded instructions and source support the same rejection tests, two-slot
update, wrapping revision increment, conditional protocol call and returned update
result. No changed branch polarity, return expression or indirect target expression
was found. This is static source/assembly reconciliation, not execution equivalence.
The source's wrapping increment must not be treated as portable signed-C arithmetic.

### Persistent omission and uncertainty

The projection helper's returned x0 still moves through x2 into implicit-context
x20 before the indirect call, but both pseudocode variants make the helper result
look unused. Recovery fixes call-input visibility, not this hidden result flow.
The separate register-relationship view remains useful for that omitted evidence.

Neither output resolves the indirect target or actual receiver. The source uses
an existential protocol value; merely including one concrete implementation in
the fixture does not prove every invocation selects it. `skipped: []` in the
recovery decisions does not mean every call or ABI detail is resolved.

Both selected callees report `return_unchanged: true`. Bridge inspection confirms
parameter-only commit using `ReturnCommitOption.NO_COMMIT`, followed by return
storage/type equality checks. This preserves stored return information; it does
not establish that information is source-correct or repair hidden-context flow.

### Repeatability, preservation and pins

Ordinary repeats match exactly after removing only `data.origin.job_id`; recovered
repeats do too. Normalization uses sorted-key compact UTF-8 JSON. The ordinary
normalized SHA256 is
`b629a464ad8a8f5e7e8faaee120bb75df48d6ee414d16575ce345dfad5bedc4c`;
recovered is
`5f40ac9e0c2dc497512ae40b4eb579f05c511a64af8bb2af4e43ce311ee958d6`.

Original source/binary/project, new import Program and snapshots were independently
inventoried before/after. The analyzed Program directory was not independently
inventoried around every query: CLI source/copy integrity checks protected it,
then an independent final check verified it and all four query copies against
recorded digest
`cfad0502f3abed548e501d28d9a82861c9c99aa3d3a6927743bc3f0784f42d0d`.
Do not relabel this as an independent per-query analyzed-tree measurement.

| Artifact | SHA256 |
| --- | --- |
| Experiment manifest | `4d82ea7cf5c7b4859425eaefcc6c43d0143a835e9baeeacf2de691e5ddaeb808` |
| Reader-packet manifest | `18b52d90b8e0e4c047330c472b3a8ec32df988740f70cc97d5babfbdb3027629` |
| Existing isolated package tree, excluding pyc | `06b69765a687f58d623e9bf7081f76de8adae7156080e1f8ddf8e77b670de352` |
| Bridge | `57d37fa1624103fb714f1ded8d4c72272b2b3ceaf0eca69efa91268182985aed` |
| Ghidra tree | `72b7d1c417bf822927ba839647d1cc85268a165e9680e06781fa5f54ba1e9dbc` |
| Native decompiler | `bbbe0c16cb5446ab6c338faa28f777a3d923e30cfd5546fab661ccf51c95f6cb` |
| Prior compiler assembly | `2342191ae46b9c4382ba0128e79475f6eba487b8a638e63a0935bfc859ac6e56` |

## Next proposal, not an implemented focused option

This result supports designing an explicitly selected import-focused adaptation
of existing parameter-only recovery. It does not justify enabling the analyzed
option on imports by bypassing its snapshot validation, automatic neighbor
selection, return inference, implicit-context recovery or indirect-target claims.

Before implementation, independently review a versioned request/receipt contract:
caller and each callee must be explicitly selected, on the same pinned image,
connected by byte-verified direct-call edges, with independently bounded,
nonoverlapping extents and cumulative resource limits. Prepare only those bodies
in a disposable no-analysis import copy; preserve source import and ordinary
focused behavior. Reuse existing parameter-storage eligibility and unchanged-return
checks; retain applied/skipped decisions, warnings and original comparison output.
Bind replay to every selected proof and policy.

The next feasibility gate is whether this minimal preparation supplies the needed
function/reference state without contaminating caller scope or introducing
unsupported inference. Owned positive and negative controls must cover wrong
edges/entries, overlaps, stale bytes, unsupported registers, misleading inference,
failures and budgets. A successful source-aware experiment on an analyzed Program
is not proof that an import-focused implementation is safe or already available.
