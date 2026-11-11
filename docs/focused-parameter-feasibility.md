# Explicit focused parameter preparation: non-shipping feasibility

Spec first, following the [owned analyzed-query result](owned-swift-parameter-assessment.md).
No public CLI option or ordinary focused receipt changes. Do not bypass the
analyzed-snapshot requirements in engine.run. This experiment tests whether one
explicit callee can provide useful, bounded parameter inference without whole
image analysis. No source-supplied prototypes, return recovery, implicit-context
recovery, indirect target inference, automatic discovery or recursive expansion.

## Selection and three arms

Initial positive input is the unchanged owned Swift dylib with SHA256
`53345f8f9ae61fb42d41136fdf1d1733c9bdd7bf6410bbe676ebb03a09e5eaa0`.
Explicit caller0xc2c and callee0xbec must both pass unchanged focused.select;
verify their unique nonoverlapping mapped extents and direct BL at0xc48 from the
caller to exactly that callee. At most one callee,8192bytes per extent and16384
combined. The selected callee is initially a bounded leaf: no calls, indirect
jumps or out-of-extent branches; ordinary return and verified internal branches
are permitted. Unsupported cases fail or explicitly skip, never gain guessed
parameters. Negative fixtures must be owned, separately frozen and identified.

Each arm uses a new disposable copy of the same pristine saved no-analysis import
and a separate bounded worker/JVM. Never use the analyzed experiment's Program.
Compare A: caller preparation only; B: caller and explicit callee preparation;
C: the same two bodies plus parameter-only inference. Repeat each once after
successful first runs. Preparing a callee alone may affect the caller, so B is a
required control. No application/binary execution or Taskovsky session.

## Isolation and honest artifacts

Use a separate harness under analysis/, no changes to src/ or installed CLI.
Reuse existing dependency verification, sandbox renderer and subprocess supervisor,
including launch gate, ownership, deadlines, log/storage limits and full worker
teardown. Every run ends before the next JVM starts; this is not batch reuse and
does not claim to solve asynchronous disposer fencing within a persistent worker.

The operational manifest is explicitly experiment-specific, not a product query
receipt or analyzed snapshot. Do not invoke ordinary query publication or create
query-result.json. Keep supervisor request/operation metadata outside the worker's
sole writable subtree. A lower-level supervisor may label the native operation
mode=query for its existing launch gate, but the experiment schema/kind and lack
of product publication must remain explicit. No resume/replay integration claimed.
Copy pinned existing Java preparation/bridge sources plus reviewed experimental
wrapper into the allowed worker subtree; any permission change requires review.
No silently broadened read, execute, write or network permission.

Bind source/script/dependency, image/slice/import Program and both extent hashes,
edge bytes, arm and limits in each request. Recheck before launch and after worker
exit. Preserve original Program/source and captured failure artifacts. Worker
exit0 alone is insufficient: validate all required reports against supervisor pins.

## Native validation before inference

Prepare only the selected bodies using existing exact-focus semantics. Recheck
actual Program bytes, exact body ranges, direct edge and no-analysis state.
An experimental wrapper may reuse RecoverCallSignatures parameter eligibility
and commit checks, but must validate every HighFunction used by inference:
scan at most100000 native p-code operations; reject unavailable, truncated,
unlocatable or outside-selected-body operations BEFORE committing parameters.
Revalidate after any subsequent decompilation used to check a commit. Existing
highFunction() completion alone is insufficient. Preserve existing signatures,
custom-storage refusals and return type/storage checks. Source-correctness of
inferred types or an unchanged return is not established by this validation.

Independently verify the final caller's instruction bytes, body, CFG/native scope
and full focused coverage against its own proof. Callee preparation must not expand
caller scope. Record raw warnings, partials/skips and parameter decisions without
suppressing them or rewriting pseudocode. Do not publish an experiment as a normal
successful focused receipt.

## Gates

Review design before harness implementation and implementation before native runs.
Unit controls: wrong edge/entry, overlaps, stale bytes, limits, invalid modes and
request identities. Native owned controls must exercise preparation failure and
unsupported input storage; test the scope guard's rejection path explicitly and
distinguish injected checker controls from an actual native out-of-body case.
Preserve operational failures as failures. Positive A/B/C evidence must show
which step changes pseudocode, unchanged caller machine evidence, preserved stored
return information and source-consistent call input visibility.

Use stock pinned Ghidra12.2, one worker,2048MiB Java heap,240s total/120s startup/
25s decompiler budgets. Request/run/artifact bounds remain no weaker than existing
focused execution. Stop on uncertain teardown or integrity, do not retry silently.
No performance claim or product readiness follows from a successful owned trial.
A public adaptation still requires its own versioned API/receipt/replay design,
compatibility tests and broader native negative controls.

## Recorded assessment

See the [owned native assessment](focused-parameter-assessment.md) for the
three-arm results, retained failure and diagnostics, and outstanding product gates.
