# Bounded assignment-selection diagnostics

Specification first. The owned native negative gate exposes a usability gap:
wrong-address and unresolved-input assignment stores both report only
`unique_paired_assignment_not_proven`. Their distinct next evidence needs are
buried in the full independent-evidence tree.

Add `assignment_diagnostic` to callback composition policy 3, with its own
`macscope-assignment-diagnostic/1` version. This is an additive explanatory view;
existing facts, candidate decisions, gaps, exit codes and receipts do not change.
The selected thunk entry is a comparison target, not a recovered runtime target.

Report exact decoded store counts, matching address-store count, other address
count and non-address value count. Reasons distinguish no observed stores,
no matching address store, multiple matching address stores, a unique match
without a unique paired lane, and a unique matched pair. A matched pair is not
proof that other composition requirements pass. No-store means no stores in the
decoded prefix, never no stores in the entire function.

Include at most 32 store summaries in instruction order: instruction VA, optional
lane, value kind, and only an address-valued target when present. Include exact
omitted count, decoded-prefix termination, gap count, selected range and source
envelope digest. No recursive values or inferred function names. All summaries
are scoped to the independent assignment receipt. Other address stores are not
automatically callback stores; non-address values are not automatically function
parameters. Unknown runtime identity, memory aliasing and persistence remain.

Each reason supplies one fixed, non-executing evidence recommendation: check the
selected prefix, independently identify a selected target, narrow ambiguous
store evidence, obtain a paired-lane observation, or inspect remaining chain
obligations. Never automatically follow a mismatched address or start jobs.

Acceptance: existing native overwritten/unknown examples retain distinct observed
values and unchanged inconclusive outcomes; owned synthetic no-store, duplicate,
unpaired and unique-pair cases; exact truncation at 32 summaries; gaps/termination
remain visible; deterministic immutable offline replay; full regression suites.

The diagnostic does not identify which unmatched store is a callback. Precise
subreasons are structural: `no_stores_in_decoded_prefix`,
`no_address_valued_store`, `no_matching_address_store`,
`multiple_matching_address_stores`, `unique_match_without_unique_companion_lane`,
and `unique_matching_pair_observed`. Non-address includes symbolic values and
integer constants; it does not mean runtime resolution is impossible. Prefix
barriers are retained independently as termination and gap count, not overwritten
by a more reassuring subreason. A unique matched pair may still fail another
composition requirement. Terminal text adds the precise subreason; its existing
bounded observed-store list remains unchanged. This adds one terminal line while
retaining the existing 64-line/16-KiB appended-section budget.

## Validation checkpoint

833 primary tests and 115 analysis tests passed. Independent review passed 14
focused presentation/diagnostic tests and the actual native text/JSON gate.
An installed wheel outside the checkout replayed the three owned configurations
in both formats twice each, with nonexistent engine/JDK paths and unchanged
job/receipt bytes. The positive reports `unique_matching_pair_observed`; the
other-address control reports `no_matching_address_store`; the selected-input
control reports `no_address_valued_store`. Each retains its exact assignment
selection/envelope identity and observed store accounting. Existing candidate
statuses and generic compatibility gaps remain unchanged.

This improves explanation, not decoder coverage. In particular, a mismatched
address is not automatically a valid next callback target; following it still
requires independently verified boundaries, instructions and explicit receipts.
