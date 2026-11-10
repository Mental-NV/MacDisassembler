/* Compare the return status and the whole caller-owned output buffer. */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "calc_core.h"
#include "aggregate_compat.h"

extern long gh_stack_guard __asm("___stack_chk_guard");
extern _Noreturn void gh_stack_fail(void) __asm("___stack_chk_fail");
#define ___stack_chk_fail gh_stack_fail
#include "candidate.c"

_Static_assert(sizeof(long) == 8 && CHAR_MIN < 0, "Unexpected evaluator ABI");

static uint64_t seed = UINT64_C(0xC06390F6F6F47921);
static unsigned mismatches, first_mismatch;

static uint64_t next_word(void) {
    seed ^= seed >> 12;
    seed ^= seed << 25;
    seed ^= seed >> 27;
    return seed * UINT64_C(0x2545F4914F6CDD1D);
}

static void compare(unsigned ordinal, int64_t value, size_t capacity, bool use_null) {
    unsigned char actual[64], expected[64];
    memset(actual, 0xa5, sizeof(actual));
    memset(expected, 0xa5, sizeof(expected));
    uint64_t status = RECOVERED(value, use_null ? NULL : actual, capacity);
    calc_status_t want = calc_format_int64(value, use_null ? NULL : (char *)expected, capacity);
    if ((status != (uint64_t)want || memcmp(actual, expected, sizeof(actual))) && mismatches++ == 0) {
        first_mismatch = ordinal;
    }
}

int main(void) {
    static const int64_t edges[] = {
        INT64_MIN, INT64_MIN+1, -INT64_C(10000000000), -100, -10, -9, -1, 0,
        1, 9, 10, 100, INT64_C(10000000000), INT64_MAX-1, INT64_MAX
    };
    unsigned directed = 0;
    for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        compare(directed++, edges[i], 0, true);
        compare(directed++, edges[i], 64, true);
        for (size_t capacity = 0; capacity <= 64; ++capacity) {
            compare(directed++, edges[i], capacity, false);
        }
    }
    for (unsigned i = 0; i < 10000; ++i) {
        uint64_t bits = next_word();
        int64_t value;
        memcpy(&value, &bits, sizeof(value));
        compare(directed+i, value, (size_t)(next_word() % 65), i % 23 == 0);
    }
    printf("{\"directed\":%u,\"seeded\":10000,\"mismatches\":%u,\"first_mismatch\":%u}\n",
           directed, mismatches, first_mismatch);
    return 0;
}
