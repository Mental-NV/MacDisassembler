# Held-out switch validation contract

This owned command-line fixture is separate from the calculator and is
frozen before changing computed-jump reporting. The six operation values
select distinct unsigned 32-bit calculations. The gaps within the selector
range share a constant-return default. The compiler may emit a table,
comparison tree, or tail calls.

## Freeze and capture

1. Build from the committed `analysis/heldout_switch.c` with Apple Clang,
   `-std=c11 -g -O0` and `-std=c11 -g -O2`, separately for `arm64` and
   `x86_64`. Keep the linked binaries, linker maps and matching dSYMs in the
   evaluator store. Record the commit, source hash, compiler/SDK versions,
   binary UUIDs and slice hashes.
2. Give each analyzer job only its own symbol-bearing or `strip -S -x`
   copy. Verify that stripping preserves `__text` and leaves no
   `_heldout_dispatch` symbol in the stripped copy. Disable DWARF and
   source analyzers. Never send a source-derived address to a discovery
   run. Keep the stripped and symbol-bearing captures separate.
3. Enumerate functions and save the exports before using source, symbols
   from the evaluator copy, or dSYM addresses for evaluation. Use the
   evaluator UUID and independent linker start, LLVM disassembly, and
   table bytes where applicable to identify the dispatcher and its
   reachable case targets. Store addresses and case block evidence with
   each verdict.

## Scoring

For each dispatcher report whether the engine discovered its entry, which
of the six explicit operations and default it covered, and whether a
computed branch has absent or uncertain destinations. A binary-only
report can claim complete pseudocode only if it contains no known missing
reachable path and communicates any unresolved computed jump. A complete
report is not by itself behavioral evidence.

A path whose recovered C depends on an omitted block, a missing switch
target, or manually restored semantics counts as untestable. Never
rewrite pseudocode or supply corrected function types from this fixture
to improve the score. For this control-flow checkpoint the input
executables are data-only and no runtime equivalence claim is made.

Compare against the original owned calculator matrix separately, including
the x86_64 O0 dispatcher and the x86_64 O2 padding case. Preserve the
existing analyzer options and compare raw Program evidence as well as the
CLI coverage status.
