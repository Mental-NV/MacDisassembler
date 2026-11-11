# Bounded ivar diagnostics (F4c)

Additive contract: existing rows, gap codes, cursor identity and return pairs
remain compatible. Optional diagnostics are strings in the existing envelope;
they describe discovery before name filtering and pagination. Each event gives
a verified owning class VA, a record index (zero-based within its list) and a verified record VA, or
explicitly unknown if the full record mapping could not be proved. A list
failure has no record index. Never present an inferred address as verified.

Emit at most 128 detailed events per query, plus one omitted-event count and one aggregate record-budget summary.
The latter survives detail truncation and counts only reached lists whose
headers were verified, not unvisited classes.
A row-budget event reports the exact count of unvisited declared records as a
range summary, without allocating per record. That count is not a count of
valid ivars. Unsupported list formats cannot establish a record count.
Distinguish unsupported layout, pointer-resolution failures, external binding,
unmapped/ambiguous bytes, invalid record, missing offset and exhausted work.
Each event names missing evidence. Missing offsets retain null, legitimate
zero remains zero; independently valid rows survive bad records and tails.
Offset evidence gains a stable reason_code on failure, retaining legacy reason.
Name filtering reports its removed-row count separately and is not a gap.

Validation uses independently authored metadata, no proprietary artifacts:
bad names/types/alignment, external pointers, zero/missing/negative offsets,
unmapped tails, list layout, pointer and row budgets, cap/omitted counts and
deterministic repeat queries. No native execution or new worker is involved.

## Validation checkpoint

721 primary tests and 115 analysis tests pass. Eight new diagnostic tests cover
zero/null, negative/missing/external offsets, pointer budgets, ambiguous and
unmapped record bytes, unsupported layouts, invalid alignment, huge declared
counts and deterministic repeat queries. Existing selected-ivar CLI tests now
assert the name-filter summary; cursor and engine-free replay remain covered.
Independent review identified a lost unvisited-count summary at the detail cap;
the separate aggregate summary fixes that case and is regression-tested.
The installed local wheel passes 16 selected-ivar/diagnostic tests and its
`macscope objc ivars --help` entry point works. No native or private-app execution
was needed or performed for this metadata-only change.
