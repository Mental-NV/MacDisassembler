/* Compare raw recovered state operations without changing their bodies. */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "calc_core.h"
#include "aggregate_compat.h"

static void ___memset_chk(long address, int value, size_t size, size_t capacity) {
    if (size > capacity) abort();
    memset((void *)(uintptr_t)address, value, size);
}

#include "candidate.c"

_Static_assert(sizeof(long) == 8 && sizeof(int) == 4 && CHAR_MIN < 0,
               "Evaluator requires the tested Darwin data model");
_Static_assert(sizeof(calc_state_t) == 0x38 &&
               offsetof(calc_state_t, pending_op) == 0x10 &&
               offsetof(calc_state_t, fresh_entry) == 0x24 &&
               offsetof(calc_state_t, negative_zero) == 0x28 &&
               offsetof(calc_state_t, error_latched) == 0x2c &&
               offsetof(calc_state_t, error) == 0x30, "Unexpected calculator state layout");

static uint64_t seed = UINT64_C(0xB5AD4ECEDA1CE2A9);
static unsigned mismatches;
static unsigned first_mismatch;

static uint64_t bits(void) {
    uint64_t value = (seed += UINT64_C(0x9E3779B97F4A7C15));
    value = (value ^ (value >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94D049BB133111EB);
    return value ^ (value >> 31);
}

static void compare(unsigned ordinal, const calc_state_t *input) {
    calc_state_t actual, expected;
    if (input) {
        memcpy(&actual, input, sizeof(actual));
        memcpy(&expected, input, sizeof(expected));
    }
#if POINTER_STATE
    RECOVERED(input ? (void *)&actual : NULL);
#else
    RECOVERED(input ? (long)(uintptr_t)&actual : 0);
#endif
    calc_state_t *reference = input ? &expected : NULL;
#if STATE_KIND == 1
    calc_state_init(reference);
#elif STATE_KIND == 2
    calc_engine_clear(reference);
#elif STATE_KIND == 3
    calc_engine_sign_toggle(reference);
#else
#error Unknown state routine
#endif
    if (input && memcmp(&actual, &expected, sizeof(actual)) != 0 && mismatches++ == 0)
        first_mismatch = ordinal;
}

int main(void) {
    static const int64_t values[] = {
        INT64_MIN, INT64_MIN+1, -INT64_C(0x100000000), -100, -2, -1,
        0, 1, 2, 100, INT64_C(0x100000000), INT64_MAX
    };
    unsigned directed = 0;
    compare(directed++, NULL);
    calc_state_t state;
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        for (unsigned scenario = 0; scenario < 12; ++scenario) {
            calc_state_init(&state);
            state.display = values[i];
            state.accumulator = INT64_MAX;
            state.last_operand = INT64_MIN;
            state.last_op = '-';
            state.has_last = 1;
            state.pending_op = scenario & 1 ? '+' : 0;
            state.fresh_entry = !!(scenario & 2);
            state.negative_zero = values[i] == 0 && !!(scenario & 4);
            state.error_latched = scenario >= 8;
            state.error = state.error_latched ? CALC_ERR_OVERFLOW : CALC_OK;
            compare(directed++, &state);
        }
    }
    calc_state_init(&state);
    for (unsigned i = 0; i < 10000; ++i) {
        uint64_t value = bits();
        switch (value % 8) {
            case 0: calc_engine_clear(&state); break;
            case 1: calc_engine_input_op(&state, "+-*/"[(value >> 8) & 3]); break;
            case 2: calc_engine_equals(&state); break;
            case 3: calc_engine_sign_toggle(&state); break;
            default: calc_engine_input_digit(&state, (int)((value >> 8) % 10)); break;
        }
        compare(directed + i, &state);
    }
    printf("{\"directed\":%u,\"seeded\":10000,\"mismatches\":%u,\"first_mismatch\":%u}\n",
           directed, mismatches, first_mismatch);
    return 0;
}
