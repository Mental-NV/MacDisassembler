/*
 * calc_core.h — pure C integer calculation core for the MacDisassembler
 * calculator fixture.
 *
 * No AppKit, no UI, no I/O. Semantics frozen in docs/semantics.md v1.0.
 * Every fallible routine reports via calc_result_t / calc_status_t;
 * values never wrap and errors never trap.
 */
#ifndef CALC_CORE_H
#define CALC_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum calc_status {
    CALC_OK = 0,
    CALC_ERR_OVERFLOW = 1,
    CALC_ERR_DIV_ZERO = 2,
    CALC_ERR_INVALID = 3
} calc_status_t;

typedef struct calc_result {
    int64_t value;
    calc_status_t status;
} calc_result_t;

/* Checked binary operators (semantics §2). */
calc_result_t calc_add(int64_t a, int64_t b);
calc_result_t calc_sub(int64_t a, int64_t b);
calc_result_t calc_mul(int64_t a, int64_t b);
calc_result_t calc_div(int64_t a, int64_t b); /* truncates toward zero */

/* Checked unary operators. */
calc_result_t calc_negate(int64_t a);
calc_result_t calc_abs_checked(int64_t a);

/* Checked power: base^exp, exp >= 0, exp <= 62. Negative exp -> INVALID. */
calc_result_t calc_pow_checked(int64_t base, int64_t exp);

/* Switch dispatcher over '+', '-', '*', '/'. Anything else -> INVALID. */
calc_result_t calc_apply_op(char op, int64_t a, int64_t b);

/* Function-pointer dispatch table over '+', '-', '*', '/'. */
typedef calc_result_t (*calc_binop_fn)(int64_t a, int64_t b);
calc_result_t calc_dispatch_table(char op, int64_t a, int64_t b);

/* Bounded digit-string parse/format (semantics §3). */
calc_result_t calc_parse_digits(const char *text, size_t len);
calc_status_t calc_format_int64(int64_t value, char *out, size_t cap);

/* Display digit append: display * 10 + digit. digit must be 0..9. */
calc_result_t calc_digit_append(int64_t display, int digit);

/* Sign toggle: checked negate. */
calc_result_t calc_sign_toggle(int64_t display);

/* Signed and unsigned comparisons: -1, 0, +1. */
int calc_compare_s64(int64_t a, int64_t b);
int calc_compare_u64(uint64_t a, uint64_t b);

/* Engine state machine (semantics §4-§5). */
typedef struct calc_state {
    int64_t display;
    int64_t accumulator;
    char pending_op;      /* 0 when none */
    char last_op;         /* 0 when none */
    int64_t last_operand; /* second operand of last completed computation */
    int has_last;
    int fresh_entry;      /* next digit starts a new entry */
    int error_latched;
    calc_status_t error;
} calc_state_t;

void calc_state_init(calc_state_t *st);
void calc_engine_clear(calc_state_t *st);
void calc_engine_input_digit(calc_state_t *st, int digit);
void calc_engine_input_op(calc_state_t *st, char op);
void calc_engine_equals(calc_state_t *st);
void calc_engine_sign_toggle(calc_state_t *st);

/* History ring (semantics §6). */
#define CALC_HISTORY_CAP 16

typedef struct calc_history_entry {
    int64_t operand1;
    char op;
    int64_t operand2;
    int64_t result;
} calc_history_entry_t;

typedef struct calc_history {
    calc_history_entry_t entries[CALC_HISTORY_CAP];
    size_t count; /* total pushes ever; entries ring over the last 16 */
} calc_history_t;

void calc_history_init(calc_history_t *h);
void calc_history_push(calc_history_t *h, int64_t operand1, char op,
                       int64_t operand2, int64_t result);
size_t calc_history_len(const calc_history_t *h);
const calc_history_entry_t *calc_history_get(const calc_history_t *h,
                                             size_t index); /* 0 = oldest */
calc_result_t calc_history_sum(const calc_history_t *h);

#ifdef __cplusplus
}
#endif

#endif /* CALC_CORE_H */
