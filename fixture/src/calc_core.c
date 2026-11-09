/* calc_core.c — pure C integer calculation core. See calc_core.h. */
#include "calc_core.h"
#include <limits.h>
#include <string.h>

/*
 * Controlled no-inline subset (frozen for the baseline): these routines are
 * marked noinline in BOTH DebugAnalysis (-O0) and ReleaseAnalysis (-O2) so
 * the evaluator can map them by symbol even after optimization. Ordinary
 * inlining still applies to every other routine and is scored separately.
 * Marked: calc_add, calc_div, calc_apply_op, calc_dispatch_table,
 * calc_parse_digits, calc_engine_input_op, calc_engine_equals,
 * calc_history_sum.
 */
#if defined(__clang__) || defined(__GNUC__)
#define CALC_NOINLINE __attribute__((noinline))
#else
#define CALC_NOINLINE
#endif

CALC_NOINLINE calc_result_t calc_add(int64_t a, int64_t b) {
    calc_result_t r;
    if (__builtin_add_overflow(a, b, &r.value)) {
        r.value = 0;
        r.status = CALC_ERR_OVERFLOW;
    } else {
        r.status = CALC_OK;
    }
    return r;
}

calc_result_t calc_sub(int64_t a, int64_t b) {
    calc_result_t r;
    if (__builtin_sub_overflow(a, b, &r.value)) {
        r.value = 0;
        r.status = CALC_ERR_OVERFLOW;
    } else {
        r.status = CALC_OK;
    }
    return r;
}

calc_result_t calc_mul(int64_t a, int64_t b) {
    calc_result_t r;
    if (__builtin_mul_overflow(a, b, &r.value)) {
        r.value = 0;
        r.status = CALC_ERR_OVERFLOW;
    } else {
        r.status = CALC_OK;
    }
    return r;
}

CALC_NOINLINE calc_result_t calc_div(int64_t a, int64_t b) {
    calc_result_t r;
    if (b == 0) {
        r.value = 0;
        r.status = CALC_ERR_DIV_ZERO;
    } else if (a == INT64_MIN && b == -1) {
        /* The single representability trap of C two's-complement division. */
        r.value = 0;
        r.status = CALC_ERR_OVERFLOW;
    } else {
        r.value = a / b; /* C truncates toward zero. */
        r.status = CALC_OK;
    }
    return r;
}

calc_result_t calc_negate(int64_t a) {
    calc_result_t r;
    if (__builtin_sub_overflow(0, a, &r.value)) {
        r.value = 0;
        r.status = CALC_ERR_OVERFLOW;
    } else {
        r.status = CALC_OK;
    }
    return r;
}

calc_result_t calc_abs_checked(int64_t a) {
    calc_result_t r;
    if (a == INT64_MIN) {
        r.value = 0;
        r.status = CALC_ERR_OVERFLOW;
    } else {
        r.value = a < 0 ? -a : a;
        r.status = CALC_OK;
    }
    return r;
}

calc_result_t calc_pow_checked(int64_t base, int64_t exp) {
    calc_result_t r;
    int64_t acc = 1;
    int64_t i;
    if (exp < 0 || exp > 62) {
        r.value = 0;
        r.status = CALC_ERR_INVALID;
        return r;
    }
    for (i = 0; i < exp; i++) {
        int64_t next;
        if (__builtin_mul_overflow(acc, base, &next)) {
            r.value = 0;
            r.status = CALC_ERR_OVERFLOW;
            return r;
        }
        acc = next;
    }
    r.value = acc;
    r.status = CALC_OK;
    return r;
}

CALC_NOINLINE calc_result_t calc_apply_op(char op, int64_t a, int64_t b) {
    calc_result_t r;
    switch (op) {
    case '+':
        return calc_add(a, b);
    case '-':
        return calc_sub(a, b);
    case '*':
        return calc_mul(a, b);
    case '/':
        return calc_div(a, b);
    default:
        r.value = 0;
        r.status = CALC_ERR_INVALID;
        return r;
    }
}

static const struct calc_dispatch_row {
    char op;
    calc_binop_fn fn;
} kCalcDispatchTable[] = {
    {'+', calc_add},
    {'-', calc_sub},
    {'*', calc_mul},
    {'/', calc_div},
};

CALC_NOINLINE calc_result_t calc_dispatch_table(char op, int64_t a, int64_t b) {
    calc_result_t r;
    size_t i;
    for (i = 0; i < sizeof(kCalcDispatchTable) / sizeof(kCalcDispatchTable[0]); i++) {
        if (kCalcDispatchTable[i].op == op) {
            return kCalcDispatchTable[i].fn(a, b);
        }
    }
    r.value = 0;
    r.status = CALC_ERR_INVALID;
    return r;
}

CALC_NOINLINE calc_result_t calc_parse_digits(const char *text, size_t len) {
    calc_result_t r;
    int negative = 0;
    size_t i = 0;
    uint64_t mag = 0;
    r.value = 0;
    r.status = CALC_ERR_INVALID;
    if (text == NULL || len == 0 || len > 64) {
        return r;
    }
    if (text[0] == '-') {
        negative = 1;
        i = 1;
    }
    if (i >= len) {
        return r; /* lone sign */
    }
    for (; i < len; i++) {
        unsigned int d;
        char c = text[i];
        if (c < '0' || c > '9') {
            r.status = CALC_ERR_INVALID;
            return r;
        }
        d = (unsigned int)(c - '0');
        if (mag > (UINT64_MAX - d) / 10u) {
            r.value = 0;
            r.status = CALC_ERR_OVERFLOW;
            return r;
        }
        mag = mag * 10u + d;
    }
    if (!negative) {
        if (mag > (uint64_t)INT64_MAX) {
            r.value = 0;
            r.status = CALC_ERR_OVERFLOW;
            return r;
        }
        r.value = (int64_t)mag;
    } else {
        if (mag > (uint64_t)INT64_MAX + 1u) {
            r.value = 0;
            r.status = CALC_ERR_OVERFLOW;
            return r;
        }
        if (mag == (uint64_t)INT64_MAX + 1u) {
            r.value = INT64_MIN;
        } else {
            r.value = -(int64_t)mag;
        }
    }
    r.status = CALC_OK;
    return r;
}

calc_status_t calc_format_int64(int64_t value, char *out, size_t cap) {
    char tmp[20];
    size_t n = 0;
    int negative = value < 0;
    uint64_t mag;
    size_t need;
    size_t i;
    if (out == NULL || cap == 0) {
        return CALC_ERR_INVALID;
    }
    if (negative) {
        mag = (uint64_t)(-(value + 1)) + 1u; /* safe for INT64_MIN */
    } else {
        mag = (uint64_t)value;
    }
    if (mag == 0) {
        tmp[n++] = '0';
    } else {
        while (mag > 0) {
            tmp[n++] = (char)('0' + (mag % 10u));
            mag /= 10u;
        }
    }
    need = n + (size_t)(negative ? 1 : 0) + 1u; /* +NUL */
    if (cap < need) {
        return CALC_ERR_INVALID;
    }
    i = 0;
    if (negative) {
        out[i++] = '-';
    }
    while (n > 0) {
        out[i++] = tmp[--n];
    }
    out[i] = '\0';
    return CALC_OK;
}

calc_result_t calc_digit_append(int64_t display, int digit) {
    calc_result_t r;
    int64_t scaled;
    if (digit < 0 || digit > 9) {
        r.value = 0;
        r.status = CALC_ERR_INVALID;
        return r;
    }
    if (__builtin_mul_overflow(display, 10, &scaled) ||
        __builtin_add_overflow(scaled, (int64_t)digit, &r.value)) {
        r.value = 0;
        r.status = CALC_ERR_OVERFLOW;
        return r;
    }
    r.status = CALC_OK;
    return r;
}

calc_result_t calc_sign_toggle(int64_t display) {
    return calc_negate(display);
}

int calc_compare_s64(int64_t a, int64_t b) {
    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    return 0;
}

int calc_compare_u64(uint64_t a, uint64_t b) {
    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    return 0;
}

void calc_state_init(calc_state_t *st) {
    if (st == NULL) {
        return;
    }
    memset(st, 0, sizeof(*st));
    st->fresh_entry = 1;
}

void calc_engine_clear(calc_state_t *st) {
    calc_state_init(st);
}

static void calc_latch_error(calc_state_t *st, calc_status_t err) {
    st->error_latched = 1;
    st->error = err;
}

void calc_engine_input_digit(calc_state_t *st, int digit) {
    calc_result_t r;
    if (st == NULL || st->error_latched) {
        return;
    }
    if (digit < 0 || digit > 9) {
        calc_latch_error(st, CALC_ERR_INVALID);
        return;
    }
    if (st->fresh_entry) {
        st->display = (int64_t)digit;
        st->fresh_entry = 0;
        return;
    }
    r = calc_digit_append(st->display, digit);
    if (r.status != CALC_OK) {
        calc_latch_error(st, r.status);
        return;
    }
    st->display = r.value;
    st->fresh_entry = 0;
}

static int calc_op_valid(char op) {
    return op == '+' || op == '-' || op == '*' || op == '/';
}

CALC_NOINLINE void calc_engine_input_op(calc_state_t *st, char op) {
    if (st == NULL || st->error_latched) {
        return;
    }
    if (!calc_op_valid(op)) {
        calc_latch_error(st, CALC_ERR_INVALID);
        return;
    }
    if (st->pending_op == 0) {
        st->accumulator = st->display;
    } else if (st->fresh_entry) {
        /* Consecutive operators: last one wins, no computation. */
    } else {
        calc_result_t r = calc_apply_op(st->pending_op, st->accumulator, st->display);
        if (r.status != CALC_OK) {
            calc_latch_error(st, r.status);
            return;
        }
        st->accumulator = r.value;
        st->display = r.value;
    }
    st->pending_op = op;
    st->fresh_entry = 1;
}

CALC_NOINLINE void calc_engine_equals(calc_state_t *st) {
    if (st == NULL || st->error_latched) {
        return;
    }
    if (st->pending_op != 0) {
        int64_t rhs = st->display;
        calc_result_t r = calc_apply_op(st->pending_op, st->accumulator, rhs);
        if (r.status != CALC_OK) {
            calc_latch_error(st, r.status);
            return;
        }
        st->last_op = st->pending_op;
        st->last_operand = rhs;
        st->has_last = 1;
        st->pending_op = 0;
        st->display = r.value;
        st->accumulator = r.value;
        st->fresh_entry = 1;
        return;
    }
    if (st->has_last) {
        calc_result_t r = calc_apply_op(st->last_op, st->display, st->last_operand);
        if (r.status != CALC_OK) {
            calc_latch_error(st, r.status);
            return;
        }
        st->display = r.value;
        st->accumulator = r.value;
        st->fresh_entry = 1;
        return;
    }
    /* No pending operation and no repeat history: no-op. */
}

void calc_engine_sign_toggle(calc_state_t *st) {
    calc_result_t r;
    if (st == NULL || st->error_latched) {
        return;
    }
    r = calc_negate(st->display);
    if (r.status != CALC_OK) {
        calc_latch_error(st, r.status);
        return;
    }
    st->display = r.value;
}

void calc_history_init(calc_history_t *h) {
    if (h == NULL) {
        return;
    }
    memset(h, 0, sizeof(*h));
}

void calc_history_push(calc_history_t *h, int64_t operand1, char op,
                       int64_t operand2, int64_t result) {
    calc_history_entry_t *slot;
    if (h == NULL) {
        return;
    }
    slot = &h->entries[h->count % CALC_HISTORY_CAP];
    slot->operand1 = operand1;
    slot->op = op;
    slot->operand2 = operand2;
    slot->result = result;
    h->count++;
}

size_t calc_history_len(const calc_history_t *h) {
    if (h == NULL) {
        return 0;
    }
    return h->count < CALC_HISTORY_CAP ? h->count : CALC_HISTORY_CAP;
}

const calc_history_entry_t *calc_history_get(const calc_history_t *h, size_t index) {
    size_t len;
    size_t oldest;
    if (h == NULL) {
        return NULL;
    }
    len = calc_history_len(h);
    if (index >= len) {
        return NULL;
    }
    oldest = (h->count - len) % CALC_HISTORY_CAP;
    return &h->entries[(oldest + index) % CALC_HISTORY_CAP];
}

CALC_NOINLINE calc_result_t calc_history_sum(const calc_history_t *h) {
    calc_result_t r;
    size_t len;
    size_t i;
    int64_t acc = 0;
    r.value = 0;
    r.status = CALC_OK;
    if (h == NULL) {
        r.status = CALC_ERR_INVALID;
        return r;
    }
    len = calc_history_len(h);
    for (i = 0; i < len; i++) {
        const calc_history_entry_t *e = calc_history_get(h, i);
        int64_t next;
        if (__builtin_add_overflow(acc, e->result, &next)) {
            r.value = 0;
            r.status = CALC_ERR_OVERFLOW;
            return r;
        }
        acc = next;
    }
    r.value = acc;
    return r;
}
