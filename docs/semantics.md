# Calculator fixture: signed-int64 semantics v1.1

Version 1.1 — frozen 9 November 2026 for the post-baseline corrections.
This document is the correctness oracle for current core tests and controller
journeys. It supersedes v1.0 for new builds, not for historical measurements.

The original **v1.0 baseline** remains historical: semantics and fixture at
commit `216f28b`, baseline evaluation at `1b6e6d7`. Its outputs must not be
relabeled v1.1. New v1.1 binaries need newly recorded build hashes and test
outputs before any new baseline evaluation.

Changes from v1.0:

- Format capacity is the actual rendered length plus NUL, not an unconditional
  21-byte minimum. This matches the existing formatter and its original test.
- Digit append preserves a negative entry's sign. An explicit negative-zero
  entry sign permits sign-before-digits, including direct `INT64_MIN` entry.
- Sign before a pending RHS begins that RHS without negating the LHS.
- Successful operator-triggered chained computations enter controller history
  exactly once. This fixes the implementation to satisfy the history rule
  already present in v1.0; failed chains and consecutive operators add nothing.

## 1 Domain

- All arithmetic is signed 64-bit two's-complement (`int64_t`).
- The display shows base-ten integers. The display is a decimal rendering of
  an integer value; it does not imply floating-point arithmetic.
- Every fallible operation returns a structured status, never a wrapped
  value or a trap:
  - `CALC_OK` — value is valid.
  - `CALC_ERR_OVERFLOW` — signed overflow (add/sub/mul/negate/abs,
    `INT64_MIN / -1`, digit entry or parsing outside the signed limits).
  - `CALC_ERR_DIV_ZERO` — division with a zero divisor.
  - `CALC_ERR_INVALID` — malformed input (bad operator, bad digit string,
    unknown dispatch character).

## 2 Operator semantics

| Op | Meaning | Error cases |
|----|---------|-------------|
| `+` | checked add | overflow |
| `-` | checked sub | overflow |
| `*` | checked mul | overflow |
| `/` | C truncating division toward zero | divisor 0 → `DIV_ZERO`; `INT64_MIN / -1` → `OVERFLOW` |

- `INT64_MIN / -1`: mathematical result `9223372036854775808` is not
  representable → `OVERFLOW`. (Also avoids the single C UB case.)
- Truncation toward zero: `-7 / 2 == -3`, `7 / -2 == -3`, `-7 / -2 == 3`.
- Remainder is not exposed as an operator in this fixture.
- Unary negate of `INT64_MIN` → `OVERFLOW`. Absolute value of `INT64_MIN`
  → `OVERFLOW`.
- Unknown operator character → `INVALID`, never a default operation.

## 3 Digit entry and parsing

- Digits `0`–`9` append to the magnitude in base ten, preserving the entry
  sign: nonnegative `display * 10 + digit`, negative `display * 10 - digit`.
  Thus `-12`, then digit `3`, becomes `-123`, not `-117`.
  `calc_digit_append(0, d)` is nonnegative; only engine state can retain an
  explicit negative-zero entry sign. Negative accumulation permits direct
  entry of `-9223372036854775808` without a positive intermediate overflow.
- If the append overflows, the engine latches an error (see §5) and keeps
  the previous display value.
- Bounded string parse (`calc_parse_digits`): optional single leading `-`,
  then 1+ ASCII digits, input length capped at 64 chars. Empty string,
  lone `-`, non-digit characters → `INVALID`. Representability overflow
  → `OVERFLOW`. No whitespace skipping, no `+` sign, no hex/octal.
- Formatting (`calc_format_int64`): plain base-ten with a leading `-` for
  negatives, including `-9223372036854775808`. The buffer must hold the actual
  rendered characters plus NUL: `1` needs 2 bytes, `-1` needs 3, `INT64_MAX`
  needs 20, and `INT64_MIN` needs 21. Insufficient capacity or a null buffer
  → `INVALID`, with no writes. A 21-byte buffer is sufficient for every value.
  Integer zero formats as `0`; the controller renders an active negative-zero
  entry as `-0` (an entry sign, not a distinct arithmetic value).

## 4 Engine (state machine)

State: `display`, `accumulator`, `pending_op` (0 if none), `last_op`,
`last_operand`, `has_last`, `fresh_entry`, `negative_zero`, latched error.
`negative_zero` is meaningful only when `display == 0` and an entry is being
edited. Computations treat signed entry zero as integer zero.

- `input_digit d`: ignored while an error is latched (must clear first).
  If `fresh_entry`, display becomes nonnegative `d`; else checked append (§3),
  using the negative entry sign if `negative_zero` is set. Leading zeroes
  preserve that sign until a nonzero digit makes the value negative.
  Clears `fresh_entry`.
- `input_op op`: ignored while latched. Unknown op char → latch `INVALID`.
  - No pending op: `accumulator = display`.
  - Pending op and `fresh_entry` set (consecutive operators, no new digits):
    replace the pending op with the new one — last wins, no computation.
  - Pending op and new digits entered: first compute
    `accumulator = accumulator pending_op display`; on error latch it,
    else store the new pending op.
  - Set `fresh_entry` and clear the negative-zero entry sign.
- `equals`:
  - Ignored while latched.
  - Pending op present: compute `display = accumulator pending_op display`;
    on success remember `last_op = pending_op`,
    `last_operand = <second operand as entered>`; clear pending op;
    set `fresh_entry`; clear the negative-zero entry sign.
  - No pending op but `has_last` (repeated equals): compute
    `display = display last_op last_operand`; set `fresh_entry` and clear
    the negative-zero entry sign.
  - No pending op and no history: no-op, display unchanged.
- `clear`: resets all state including latched error, entry sign and repeat
  history. Display is `0` and `fresh_entry` is set.
- `sign_toggle`: ignored while latched.
  - If a pending op has no entered RHS (`fresh_entry`), start a zero RHS and
    toggle its entry sign to negative. Leave the accumulator unchanged.
  - Otherwise negate the displayed value, checked (`INT64_MIN` → latch
    `OVERFLOW`). At zero, toggle `negative_zero` instead.
  - A successful sign toggle clears `fresh_entry`: the signed value is now an
    editable entry. A sign-only RHS counts as an entered zero operand, so a
    subsequent operator computes with it rather than replacing the pending op.
  - With no pending op, this edits the displayed value, including a result
    immediately after equals. Repeat-equals memory is unchanged.

Worked examples (normative):

- `3 + * 4 =` → pending `+` replaced by `*` (consecutive operators),
  result `12`.
- `2 + 3 = =` → first `=` gives `5`; second repeats `+ 3` → `8`.
- `2 + 3 * 4 =` → left-to-right with pending compute: `(2+3)=5`,
  then `5*4` → `20`. No precedence beyond pending-op chaining.
- `C ± 0 1 2` → `-12`; `C 8 ± 2` → `-82`.
- `3 + ± 4 =` → `-1`, with LHS `3` and RHS `-4`.
- `3 + ± ± 4 =` → `7`; the second sign toggle restores positive entry.
- `3 + ± * 4 =` → `12`, recording `3 + 0 = 3` and `3 * 4 = 12`.
- `2 + 3 = ± 4` → `-54`: sign edits the result and the digit appends to it.
- `C ± 9 2 2 3 3 7 2 0 3 6 8 5 4 7 7 5 8 0 8` → `INT64_MIN`.
- `C` after any error clears the latch; digits then work again.
- Any digit/operator/equals key while latched (except `C`) is a no-op.

## 5 Errors

- First error wins and latches: the engine keeps the display value from
  before the failing operation and shows an error indicator until `C`.
- Errors never wrap, trap, or produce a sentinel value in `display`.
- History records only successfully completed computations, never errors.

## 6 History

- Fixed ring of the last 16 completed binary computations
  (operand1, op, operand2, result).
- `history_sum` returns the checked sum of stored results (may overflow →
  `OVERFLOW`); empty history sums to `0` with `OK`.
- History is cleared by `clear`. Repeated equals appends each repetition.
- Operator-triggered chaining records the completed pending operation once,
  before later computations: `2 + 3 * 4 =` records `2 + 3 = 5`, then
  `5 * 4 = 20`. Pressing `=` again appends only `20 * 4 = 80`.
- Consecutive operators, sign/digit entry, no-op equals, view refreshes,
  invalid new operators and failed computations add no history. A failed
  later operation preserves earlier successful history until `clear`.

## 7 Dispatch table

- A static function-pointer table maps `+ - * /` to the corresponding
  checked routine. Characters outside the table → `INVALID` without
  calling any routine.

## Reference core coverage

The instrumented calculator reference tests reached 168 of 184 branch
directions before the added edge cases. They now reach all 184 directions
in `calc_core.c` and pass 59,211 assertions. The additional cases exercise
null state and history inputs, both sides of the unsigned ordering,
oversized strings, overflow while accumulating an unsigned magnitude,
a negative digit, and overflow on a repeated equals after a successful
first result. The original directed and seeded stateful sequences still run.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 analysis/reference_coverage.py \
  --output-dir /private/tmp/new-reference-coverage \
  --experimental-trusted-input
```

The test executable is built and run in a private, network-denied directory.
Apple Clang instruments the native arm64 reference and LLVM counts source
branch directions. The report records the tool and source fingerprints and
checks the 95% reference coverage requirement. Recovered-code coverage and
behavior are measured separately. The measured report SHA-256 is
`75ed6bf9766a6bf9aeba16d7db98496cffc430196490fc259f9c9f9467f87293`.
