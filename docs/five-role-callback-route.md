# Conditional five-role callback route

Spec first. Join the previously separate owned alternative assignment/invocation
and two-thunk writer views using explicit saved receipts. This is the practical
end-to-end static candidate, not another edge-count or presentation milestone.

Allow assignment and invocation receipt pins together with the existing explicit
via and target pins, with five distinct receipt IDs. Retain every existing scope,
ABI, context pin, invocation fallthrough and destination guard requirement. Reuse
ordinary composition checks for assignment pair/layout, live invocation operands,
unsupported barriers, exact role identities and writer-call obligations.

Require the independently complete two-B route and static register forwarding.
Represent the inner thunk as a fifth role. Do not fabricate a direct outer-to-writer
transfer: record `forwarding_route` with its actual two edges. The final writer's
store relations remain independently scoped to inner and writer receipts; do not
rename their operands or replace facts with conditional values. All role ranges
must be disjoint, and all writer-cycle/reentry checks must include both thunks.

Only after both composition and forwarding checks pass, expose separate
conditional invocation-to-writer entry bindings by matching exact scoped outer
inputs against the existing invocation-to-outer bindings and the static route
bindings. Keep runtime target identity, slot identity, memory stability, execution
order, context ABI/lifetime, branch conditions and direct-call hypotheses visible.
Writer arithmetic and guarded stores remain symbolic and conditional. Overall
status stays inconclusive; `conditional_candidate` is not observed runtime dispatch
or persistence. No new assignment target is inferred or automatically selected.

The existing four-role route retains policy 3 and its output; five-role view uses
policy 4 and `route_kind=two_exact_B_thunks`. The ordinary three-receipt view is
unchanged. Missing proofs or unsupported destination guard remain gaps, not errors
hidden by the forwarding view. Invalid CLI combinations fail before native work.

Acceptance: actual owned alternative assignment target d78 plus existing invocation,
inner bb0 and checked writer a90 forms a conditional candidate only with explicit
ABI/context/fallthrough/guard/writer obligations. Original b34 assignment and unknown
stored target remain negative. Guard and writer flags off remain negative. Partial
inner extent, reused IDs, cycle/overlap, stale receipts and unsupported paths fail
closed. Full cloud suites, installed replay and independent review required; no
new native capture, input execution, installation or consumer restart.

## Invocation and validation

Use the existing disassembly receipt command with all five explicit pins:

```sh
macscope disasm --project PROJECT --from-import --range START:END \
  --receipt OUTER --callback-via-receipt INNER --callback-target-receipt WRITER \
  --callback-assignment-receipt ASSIGNMENT --callback-invocation-receipt INVOCATION \
  --callback-evidence --callback-abi aapcs64 --callback-context-register x20 \
  --callback-invocation-fallthrough --callback-destination-checked-add-fallthrough \
  --callback-writer-call-obligations --format json
```

The register pin and opt-ins must match independently inspected evidence; the
command is not permission to infer a context ABI for arbitrary binaries.

The actual owned optimized fixture's surviving alternative assignment at bd8:be4
materializes d78. Its saved invocation at c80:ca0 and route d78→bb0→a90 now form a
conditional five-role candidate. The checked writer's store at abc retains guard
aa4 and call ab8; context load c88 retains invocation guard c84 and call c94.
The original assignment to b34 and unknown-target assignment remain negative for
this explicitly selected alternative route. Omitting each required fallthrough,
checked-guard or writer-call opt-in independently leaves a gap. No facts are
substituted, no direct d78→a90 instruction is fabricated, and runtime identity
remains unknown.

`tests/integration_native_five_role.py PROJECT` pins seven actual native receipt
hashes, runs positive and negative cases twice in JSON plus text, and snapshots
all portable project bytes to verify immutable engine-free replay. The project is
an external union of previously captured owned jobs sharing the same verified
image/import/project identity; no native capture or native database is added.

897 primary and 115 analysis tests passed in the cloud. Independent review passed
35 composition/forwarding/writer tests and 42 route/text/invocation/arithmetic tests,
plus the actual native gate. Recommended explicit overlap and writer reentry
(to outer and inner) regressions were added and passed. An isolated installed
wheel passed the five-role gate and existing positive/counterexample, two-hop and
terminal-pseudocode gates. These are actual saved-native receipt replays, not a
new full Mac run, system installation, execution of the input, consumer session
or completion claim for unsupported callback patterns.
