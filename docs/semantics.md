# Calculator fixture: frozen signed-int64 semantics

Version 1.0 — frozen 9 November 2026, before any fixture code was written.
This document is the correctness oracle for the core tests, the UI journeys,
and the blind Ghidra baseline evaluation. Changes after the baseline require
a new version and re-freeze of outputs.

## 1 Domain

- All arithmetic is signed 64-bit two's-complement (`int64_t`).
- The display shows base-ten integers. The display is a decimal rendering of
  an integer value; it does not imply floating-point arithmetic.
- Every fallible operation returns a structured status, never a wrapped
  value or a trap:
  - `CALC_OK` — value is valid.
  - `CALC_ERR_OVERFLOW` — signed overflow (add/sub/mul/negate/abs,
    `INT64_MIN / -1`, digit entry past `INT64_MAX`, parse past limits).
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

- Digits `0`–`9` append in base ten: `display = display * 10 + digit`.
- If the append overflows, the engine latches an error (see §5) and keeps
  the previous display value.
- Bounded string parse (`calc_parse_digits`): optional single leading `-`,
  then 1+ ASCII digits, input length capped at 64 chars. Empty string,
  lone `-`, non-digit characters → `INVALID`. Representability overflow
  → `OVERFLOW`. No whitespace skipping, no `+` sign, no hex/octal.
- Formatting (`calc_format_int64`): plain base-ten with a leading `-` for
  negatives, including `-9223372036854775808`. Buffer must hold 21 bytes
  (20 digits/sign + NUL); smaller buffer → `INVALID`.

## 4 Engine (state machine)

State: `display`, `accumulator`, `pending_op` (0 if none), `last_op`,
`last_operand`, `has_last`, `fresh_entry`, latched error.

- `input_digit d`: ignored while an error is latched (must clear first).
  If `fresh_entry`, display becomes `d`; else checked append (§3).
  Clears `fresh_entry`.
- `input_op op`: ignored while latched. Unknown op char → latch `INVALID`.
  - No pending op: `accumulator = display`.
  - Pending op and `fresh_entry` set (consecutive operators, no new digits):
    replace the pending op with the new one — last wins, no computation.
  - Pending op and new digits entered: first compute
    `accumulator = accumulator pending_op display`; on error latch it,
    else store the new pending op.
  - Set `fresh_entry`.
- `equals`:
  - Ignored while latched.
  - Pending op present: compute `display = accumulator pending_op display`;
    on success remember `last_op = pending_op`,
    `last_operand = <second operand as entered>`; clear pending op;
    set `fresh_entry`.
  - No pending op but `has_last` (repeated equals): compute
    `display = display last_op last_operand`; set `fresh_entry`.
  - No pending op and no history: no-op, display unchanged.
- `clear`: resets all state including latched error and repeat history.
- `sign_toggle`: ignored while latched; `display = -display`, checked
  (`INT64_MIN` → latch `OVERFLOW`).

Worked examples (normative):

- `3 + * 4 =` → pending `+` replaced by `*` (consecutive operators),
  result `12`.
- `2 + 3 = =` → first `=` gives `5`; second repeats `+ 3` → `8`.
- `2 + 3 * 4 =` → left-to-right with pending compute: `(2+3)=5`,
  then `5*4` → `20`. No precedence beyond pending-op chaining.
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

## 7 Dispatch table

- A static function-pointer table maps `+ - * /` to the corresponding
  checked routine. Characters outside the table → `INVALID` without
  calling any routine.
