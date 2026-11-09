/* calc_core_tests.c — durable automated tests for the calculator core.
 * Directed boundary cases plus seeded pseudorandom input/state fuzzing
 * against an independent bignum-style oracle (__int128, no builtin reuse
 * for the oracle path except as noted). Deterministic: fixed seeds.
 * Exit 0 on success, 1 on any failure. Counts are printed for records.
 *
 * Build: clang -O0 -g -Wall -Wextra -std=c11 calc_core.c
 *        calc_core_tests.c -o calc_core_tests
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "calc_core.h"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

/* Deterministic xorshift64 PRNG (fixed seeds -> reproducible). */
static uint64_t rng_state = 0x243F6A8885A308D3ull;
static uint64_t next_rand(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}
static int64_t rand_s64(void) { return (int64_t)next_rand(); }

/* Independent oracle for add/sub/mul via __int128 (not builtins). */
static calc_result_t oracle_add(int64_t a, int64_t b) {
    __int128 s = (__int128)a + (__int128)b;
    calc_result_t r;
    if (s > INT64_MAX || s < INT64_MIN) {
        r.value = 0; r.status = CALC_ERR_OVERFLOW;
    } else {
        r.value = (int64_t)s; r.status = CALC_OK;
    }
    return r;
}
static calc_result_t oracle_sub(int64_t a, int64_t b) {
    __int128 s = (__int128)a - (__int128)b;
    calc_result_t r;
    if (s > INT64_MAX || s < INT64_MIN) {
        r.value = 0; r.status = CALC_ERR_OVERFLOW;
    } else {
        r.value = (int64_t)s; r.status = CALC_OK;
    }
    return r;
}
static calc_result_t oracle_mul(int64_t a, int64_t b) {
    __int128 s = (__int128)a * (__int128)b;
    calc_result_t r;
    if (s > INT64_MAX || s < INT64_MIN) {
        r.value = 0; r.status = CALC_ERR_OVERFLOW;
    } else {
        r.value = (int64_t)s; r.status = CALC_OK;
    }
    return r;
}

static void test_directed_arithmetic(void) {
    calc_result_t r;
    r = calc_add(2, 3); CHECK(r.status == CALC_OK && r.value == 5);
    r = calc_add(INT64_MAX, 0); CHECK(r.status == CALC_OK && r.value == INT64_MAX);
    r = calc_add(INT64_MAX, 1); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_add(INT64_MIN, -1); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_add(-1, 1); CHECK(r.status == CALC_OK && r.value == 0);
    r = calc_sub(5, 5); CHECK(r.status == CALC_OK && r.value == 0);
    r = calc_sub(INT64_MIN, 1); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_sub(INT64_MAX, -1); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_sub(0, INT64_MIN); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_mul(6, 7); CHECK(r.status == CALC_OK && r.value == 42);
    r = calc_mul(INT64_MAX, 2); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_mul(INT64_MIN, -1); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_mul(0, INT64_MIN); CHECK(r.status == CALC_OK && r.value == 0);
    r = calc_mul(-1, INT64_MIN); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_div(7, 2); CHECK(r.status == CALC_OK && r.value == 3);
    r = calc_div(-7, 2); CHECK(r.status == CALC_OK && r.value == -3);
    r = calc_div(7, -2); CHECK(r.status == CALC_OK && r.value == -3);
    r = calc_div(-7, -2); CHECK(r.status == CALC_OK && r.value == 3);
    r = calc_div(1, 0); CHECK(r.status == CALC_ERR_DIV_ZERO);
    r = calc_div(0, 0); CHECK(r.status == CALC_ERR_DIV_ZERO);
    r = calc_div(INT64_MIN, -1); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_div(INT64_MIN, 1); CHECK(r.status == CALC_OK && r.value == INT64_MIN);
    r = calc_negate(5); CHECK(r.status == CALC_OK && r.value == -5);
    r = calc_negate(INT64_MIN); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_abs_checked(-5); CHECK(r.status == CALC_OK && r.value == 5);
    r = calc_abs_checked(INT64_MIN); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_pow_checked(2, 10); CHECK(r.status == CALC_OK && r.value == 1024);
    r = calc_pow_checked(2, 62); CHECK(r.status == CALC_OK && r.value == (INT64_C(1) << 62));
    r = calc_pow_checked(2, 63); CHECK(r.status == CALC_ERR_INVALID);
    r = calc_pow_checked(10, 19); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_pow_checked(5, 0); CHECK(r.status == CALC_OK && r.value == 1);
    r = calc_pow_checked(2, -1); CHECK(r.status == CALC_ERR_INVALID);
    r = calc_apply_op('+', 1, 2); CHECK(r.status == CALC_OK && r.value == 3);
    r = calc_apply_op('?', 1, 2); CHECK(r.status == CALC_ERR_INVALID);
    r = calc_apply_op('%', 1, 2); CHECK(r.status == CALC_ERR_INVALID);
    r = calc_dispatch_table('*', 6, 7); CHECK(r.status == CALC_OK && r.value == 42);
    r = calc_dispatch_table('/', 1, 0); CHECK(r.status == CALC_ERR_DIV_ZERO);
    r = calc_dispatch_table('x', 1, 1); CHECK(r.status == CALC_ERR_INVALID);
}

static void test_parse_format(void) {
    calc_result_t r;
    char buf[32];
    r = calc_parse_digits("0", 1); CHECK(r.status == CALC_OK && r.value == 0);
    r = calc_parse_digits("9223372036854775807", 19);
    CHECK(r.status == CALC_OK && r.value == INT64_MAX);
    r = calc_parse_digits("-9223372036854775808", 20);
    CHECK(r.status == CALC_OK && r.value == INT64_MIN);
    r = calc_parse_digits("9223372036854775808", 19);
    CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_parse_digits("-9223372036854775809", 20);
    CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_parse_digits("", 0); CHECK(r.status == CALC_ERR_INVALID);
    r = calc_parse_digits("-", 1); CHECK(r.status == CALC_ERR_INVALID);
    r = calc_parse_digits("12a", 3); CHECK(r.status == CALC_ERR_INVALID);
    r = calc_parse_digits(" 12", 3); CHECK(r.status == CALC_ERR_INVALID);
    r = calc_parse_digits("+12", 3); CHECK(r.status == CALC_ERR_INVALID);
    r = calc_parse_digits(NULL, 0); CHECK(r.status == CALC_ERR_INVALID);
    CHECK(calc_format_int64(0, buf, sizeof(buf)) == CALC_OK && strcmp(buf, "0") == 0);
    CHECK(calc_format_int64(-123, buf, sizeof(buf)) == CALC_OK && strcmp(buf, "-123") == 0);
    CHECK(calc_format_int64(INT64_MIN, buf, sizeof(buf)) == CALC_OK &&
          strcmp(buf, "-9223372036854775808") == 0);
    CHECK(calc_format_int64(INT64_MAX, buf, sizeof(buf)) == CALC_OK &&
          strcmp(buf, "9223372036854775807") == 0);
    CHECK(calc_format_int64(1, buf, 2) == CALC_OK);
    CHECK(calc_format_int64(12, buf, 2) == CALC_ERR_INVALID);
    CHECK(calc_format_int64(1, NULL, 0) == CALC_ERR_INVALID);
    r = calc_digit_append(12, 3); CHECK(r.status == CALC_OK && r.value == 123);
    r = calc_digit_append(INT64_MAX, 9); CHECK(r.status == CALC_ERR_OVERFLOW);
    r = calc_digit_append(0, 10); CHECK(r.status == CALC_ERR_INVALID);
    r = calc_digit_append(0, -1); CHECK(r.status == CALC_ERR_INVALID);
    CHECK(calc_compare_s64(-1, 1) < 0 && calc_compare_s64(1, 1) == 0 &&
          calc_compare_s64(2, 1) > 0);
    CHECK(calc_compare_s64(INT64_MIN, INT64_MAX) < 0);
    CHECK(calc_compare_u64(UINT64_MAX, 0) > 0 && calc_compare_u64(3, 3) == 0);
    /* u64 vs s64 disagreement case: -1 signed < 1, but huge unsigned. */
    CHECK(calc_compare_s64(-1, 1) < 0 && calc_compare_u64((uint64_t)-1, 1) > 0);
}

static void feed_digits(calc_state_t *st, const char *digits) {
    for (; *digits; digits++) {
        calc_engine_input_digit(st, *digits - '0');
    }
}

static void test_engine_directed(void) {
    calc_state_t st;
    /* 2 + 3 =  -> 5 */
    calc_state_init(&st);
    feed_digits(&st, "2"); calc_engine_input_op(&st, '+');
    feed_digits(&st, "3"); calc_engine_equals(&st);
    CHECK(!st.error_latched && st.display == 5);
    /* repeated equals -> 8 */
    calc_engine_equals(&st);
    CHECK(!st.error_latched && st.display == 8);
    calc_engine_equals(&st);
    CHECK(!st.error_latched && st.display == 11);
    /* consecutive operators: 3 + * 4 = -> 12 */
    calc_state_init(&st);
    feed_digits(&st, "3"); calc_engine_input_op(&st, '+');
    calc_engine_input_op(&st, '*'); feed_digits(&st, "4");
    calc_engine_equals(&st);
    CHECK(!st.error_latched && st.display == 12);
    /* chained pending compute: 2 + 3 * 4 = -> 20 */
    calc_state_init(&st);
    feed_digits(&st, "2"); calc_engine_input_op(&st, '+');
    feed_digits(&st, "3"); calc_engine_input_op(&st, '*');
    feed_digits(&st, "4"); calc_engine_equals(&st);
    CHECK(!st.error_latched && st.display == 20);
    /* divide by zero latches; input ignored; C recovers */
    calc_state_init(&st);
    feed_digits(&st, "1"); calc_engine_input_op(&st, '/');
    feed_digits(&st, "0"); calc_engine_equals(&st);
    CHECK(st.error_latched && st.error == CALC_ERR_DIV_ZERO && st.display == 0);
    calc_engine_input_digit(&st, 5);
    CHECK(st.display == 0 && st.error_latched);
    calc_engine_equals(&st);
    CHECK(st.error_latched);
    calc_engine_clear(&st);
    CHECK(!st.error_latched && st.display == 0);
    feed_digits(&st, "5");
    CHECK(st.display == 5);
    /* equals with no pending and no history: no-op */
    calc_state_init(&st);
    feed_digits(&st, "9"); calc_engine_equals(&st);
    CHECK(!st.error_latched && st.display == 9);
    /* sign toggle, incl. INT64_MIN latch */
    calc_state_init(&st);
    feed_digits(&st, "7"); calc_engine_sign_toggle(&st);
    CHECK(!st.error_latched && st.display == -7);
    calc_engine_sign_toggle(&st);
    CHECK(!st.error_latched && st.display == 7);
    /* INT64_MIN via parse path: enter max then +1 overflow latch */
    calc_state_init(&st);
    feed_digits(&st, "9223372036854775807");
    CHECK(!st.error_latched && st.display == INT64_MAX);
    calc_engine_input_digit(&st, 9 - 9 + 9); /* append 9 -> overflow */
    CHECK(st.error_latched && st.error == CALC_ERR_OVERFLOW);
    /* invalid operator latches INVALID */
    calc_state_init(&st);
    calc_engine_input_op(&st, '%');
    CHECK(st.error_latched && st.error == CALC_ERR_INVALID);
    /* invalid digit latches INVALID */
    calc_state_init(&st);
    calc_engine_input_digit(&st, 12);
    CHECK(st.error_latched && st.error == CALC_ERR_INVALID);
}

static void test_history(void) {
    calc_history_t h;
    calc_result_t r;
    size_t i;
    calc_history_init(&h);
    CHECK(calc_history_len(&h) == 0);
    r = calc_history_sum(&h);
    CHECK(r.status == CALC_OK && r.value == 0);
    CHECK(calc_history_get(&h, 0) == NULL);
    calc_history_push(&h, 2, '+', 3, 5);
    calc_history_push(&h, 5, '+', 3, 8);
    CHECK(calc_history_len(&h) == 2);
    CHECK(calc_history_get(&h, 0)->result == 5);
    CHECK(calc_history_get(&h, 1)->result == 8);
    r = calc_history_sum(&h);
    CHECK(r.status == CALC_OK && r.value == 13);
    for (i = 0; i < 20; i++) {
        calc_history_push(&h, 0, '+', 1, 1);
    }
    CHECK(calc_history_len(&h) == CALC_HISTORY_CAP);
    r = calc_history_sum(&h);
    CHECK(r.status == CALC_OK && r.value == 16);
    /* overflow in sum */
    calc_history_init(&h);
    calc_history_push(&h, 0, '+', 0, INT64_MAX);
    calc_history_push(&h, 0, '+', 0, 1);
    r = calc_history_sum(&h);
    CHECK(r.status == CALC_ERR_OVERFLOW);
}

static void test_seeded_random(void) {
    int i;
    /* 10,000 seeded add/sub/mul cases vs __int128 oracle. */
    for (i = 0; i < 10000; i++) {
        int64_t a = rand_s64();
        int64_t b = rand_s64();
        /* Bias every 8th case toward extremes to hit overflow paths. */
        if ((i & 7) == 0) {
            a = (i & 16) ? INT64_MAX - (int64_t)(next_rand() & 3u)
                         : INT64_MIN + (int64_t)(next_rand() & 3u);
        }
        if ((i & 7) == 4) {
            b = (int64_t)(next_rand() & 1u) ? 1 : -1;
            b *= (int64_t)(next_rand() % 5u);
        }
        {
            calc_result_t e = oracle_add(a, b), g = calc_add(a, b);
            CHECK(g.status == e.status && (g.status != CALC_OK || g.value == e.value));
        }
        {
            calc_result_t e = oracle_sub(a, b), g = calc_sub(a, b);
            CHECK(g.status == e.status && (g.status != CALC_OK || g.value == e.value));
        }
        {
            calc_result_t e = oracle_mul(a, b), g = calc_mul(a, b);
            CHECK(g.status == e.status && (g.status != CALC_OK || g.value == e.value));
        }
    }
    /* 2,000 seeded division cases incl. zero and INT64_MIN divisors. */
    for (i = 0; i < 2000; i++) {
        int64_t a = rand_s64();
        int64_t b = (i % 5 == 0) ? 0 : rand_s64();
        calc_result_t g = calc_div(a, b);
        if (b == 0) {
            CHECK(g.status == CALC_ERR_DIV_ZERO);
        } else if (a == INT64_MIN && b == -1) {
            CHECK(g.status == CALC_ERR_OVERFLOW);
        } else {
            CHECK(g.status == CALC_OK && g.value == a / b);
        }
    }
    /* 2,000 seeded engine state sequences: model-check display/err latch. */
    for (i = 0; i < 2000; i++) {
        calc_state_t st;
        int steps = 1 + (int)(next_rand() % 12u);
        int k;
        calc_state_init(&st);
        for (k = 0; k < steps; k++) {
            switch (next_rand() % 5u) {
            case 0: calc_engine_input_digit(&st, (int)(next_rand() % 10u)); break;
            case 1: calc_engine_input_op(&st, "+-*/"[next_rand() % 4u]); break;
            case 2: calc_engine_equals(&st); break;
            case 3: calc_engine_sign_toggle(&st); break;
            default: calc_engine_clear(&st); break;
            }
        }
        /* Invariants: no error -> display formatted; latch -> err set. */
        if (!st.error_latched) {
            char buf[32];
            CHECK(calc_format_int64(st.display, buf, sizeof(buf)) == CALC_OK);
        } else {
            CHECK(st.error == CALC_ERR_OVERFLOW || st.error == CALC_ERR_DIV_ZERO ||
                  st.error == CALC_ERR_INVALID);
        }
    }
    /* 1,000 seeded parse round-trips: format(n) then parse == n. */
    for (i = 0; i < 1000; i++) {
        int64_t n = rand_s64();
        char buf[32];
        calc_result_t r;
        CHECK(calc_format_int64(n, buf, sizeof(buf)) == CALC_OK);
        r = calc_parse_digits(buf, strlen(buf));
        CHECK(r.status == CALC_OK && r.value == n);
    }
}

int main(void) {
    test_directed_arithmetic();
    test_parse_format();
    test_engine_directed();
    test_history();
    test_seeded_random();
    printf("core_tests: pass=%d fail=%d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
