/* Compare a recovered state transition and its captured callees. */
#include <limits.h>
#include <string.h>

#include "calc_core.h"
#include "aggregate_compat.h"
#include "candidate.c"

_Static_assert(sizeof(calc_state_t) == 0x38 && offsetof(calc_state_t, pending_op) == 0x10 &&
               offsetof(calc_state_t, fresh_entry) == 0x24 && offsetof(calc_state_t, error) == 0x30 &&
               sizeof(long) == 8 && sizeof(int) == 4 && CHAR_MIN < 0, "Unexpected evaluator ABI");

static uint64_t seed = UINT64_C(0xCB091F6E535F358D);
static unsigned mismatches, first_mismatch;
static const char operations[] = "+-*/";

static uint64_t next_word(void) {
    seed ^= seed >> 12;
    seed ^= seed << 25;
    seed ^= seed >> 27;
    return seed * UINT64_C(0x2545F4914F6CDD1D);
}

static bool equal(const calc_state_t *a, const calc_state_t *b) {
    return a->display == b->display && a->accumulator == b->accumulator
        && a->pending_op == b->pending_op && a->last_op == b->last_op
        && a->last_operand == b->last_operand && a->has_last == b->has_last
        && a->fresh_entry == b->fresh_entry && a->negative_zero == b->negative_zero
        && a->error_latched == b->error_latched && a->error == b->error;
}

static void compare(unsigned ordinal, const calc_state_t *input, int selector) {
    calc_state_t actual, expected;
    if (input) {
        memcpy(&actual, input, sizeof(actual));
        memcpy(&expected, input, sizeof(expected));
    }
    void *state = input ? &actual : NULL;
    calc_state_t *reference = input ? &expected : NULL;
#if STATE_KIND == 1
    RECOVERED(state, selector);
    calc_engine_input_digit(reference, selector);
#elif STATE_KIND == 2
    RECOVERED(state, (char)selector);
    calc_engine_input_op(reference, (char)selector);
#elif STATE_KIND == 3
    RECOVERED(state);
    calc_engine_equals(reference);
#elif STATE_KIND == 4
    RECOVERED(state);
    calc_engine_sign_toggle(reference);
#else
#error Unknown state routine
#endif
    if (input && !equal(&actual, &expected) && mismatches++ == 0) {
        first_mismatch = ordinal;
    }
}

int main(void) {
    static const int64_t values[] = {
        INT64_MIN, INT64_MIN+1, INT64_MIN/10, -64, -1, 0,
        1, 2, 9, 10, INT64_MAX/10, INT64_MAX-1, INT64_MAX
    };
#if STATE_KIND == 1
    static const int selectors[] = {INT_MIN, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, INT_MAX};
#elif STATE_KIND == 2
    static const int selectors[] = {CHAR_MIN, -1, 0, 1, '*', '+', '-', '/', '%', '0', 'x', CHAR_MAX};
#else
    static const int selectors[] = {0};
#endif
    unsigned directed = 0;
    const size_t value_count = sizeof(values) / sizeof(values[0]);
    const size_t selector_count = sizeof(selectors) / sizeof(selectors[0]);
    calc_state_t state;
    for (size_t s = 0; s < selector_count; ++s) {
        compare(directed++, NULL, selectors[s]);
    }
    for (size_t i = 0; i < value_count; ++i) {
        for (unsigned scenario = 0; scenario < 40; ++scenario) {
            calc_state_init(&state);
            state.display = values[i];
            state.accumulator = values[(i + scenario) % value_count];
            state.pending_op = scenario % 5 ? operations[scenario % 5 - 1] : 0;
            state.fresh_entry = !!(scenario & 1);
            state.negative_zero = !state.fresh_entry && state.display == 0 && !!(scenario & 2);
            state.has_last = !!(scenario & 4);
            if (state.has_last) {
                state.last_op = operations[(scenario >> 1) & 3];
                state.last_operand = values[(i + scenario + 1) % value_count];
            }
            state.error_latched = scenario >= 32;
            state.error = state.error_latched ? CALC_ERR_OVERFLOW : CALC_OK;
            for (size_t s = 0; s < selector_count; ++s) {
                compare(directed++, &state, selectors[s]);
            }
        }
    }
    calc_state_init(&state);
    for (unsigned i = 0; i < 10000; ++i) {
        uint64_t value = next_word();
        switch (value & 7) {
            case 0: calc_engine_clear(&state); break;
            case 1: calc_engine_input_op(&state, operations[(value >> 8) & 3]); break;
            case 2: calc_engine_equals(&state); break;
            case 3: calc_engine_sign_toggle(&state); break;
            default: calc_engine_input_digit(&state, (int)((value >> 8) % 10)); break;
        }
        compare(directed + i, &state, selectors[next_word() % selector_count]);
    }
    printf("{\"directed\":%u,\"seeded\":10000,\"mismatches\":%u,\"first_mismatch\":%u}\n",
           directed, mismatches, first_mismatch);
    return 0;
}
