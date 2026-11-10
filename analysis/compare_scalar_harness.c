/* Fixed evaluator for the two public scalar comparison functions. */
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "calc_core.h"

typedef uint32_t undefined4;
typedef unsigned int uint;
typedef unsigned long ulong;

#include "candidate.c"

_Static_assert(sizeof(long) == 8 && sizeof(int) == 4 && CHAR_MIN < 0,
               "Evaluator requires the tested Darwin scalar representation");

#if SIGNED_CASE
typedef long Input;
#define REFERENCE calc_compare_s64
static const Input directed[] = {
    INT64_MIN, INT64_MIN+1, -0x100000000L, -2, -1, 0, 1, 2,
    0x100000000L, INT64_MAX-1, INT64_MAX
};
#else
typedef unsigned long Input;
#define REFERENCE calc_compare_u64
static const Input directed[] = {
    0, 1, 2, 0x7FFFFFFFUL, 0x80000000UL, 0xFFFFFFFFUL, 0x100000000UL,
    INT64_MAX, UINT64_C(1)<<63, UINT64_MAX-1, UINT64_MAX
};
#endif

typedef __typeof__(&RECOVERED) RecoveredSignature;
_Static_assert(__builtin_types_compatible_p(RecoveredSignature, int (*)(Input, Input)) ||
               __builtin_types_compatible_p(RecoveredSignature, uint32_t (*)(Input, Input)),
               "Recovered signature does not match the declared scalar cohort");

static uint64_t seed = UINT64_C(0x57B4A6CE316D9C73);
static unsigned results[3];
static unsigned mismatches;
static uint64_t first_left, first_right;
static uint32_t first_expected, first_actual;

static Input random_input(void) {
    uint64_t value = (seed += UINT64_C(0x9E3779B97F4A7C15));
    value = (value ^ (value >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94D049BB133111EB);
    value ^= value >> 31;
    Input input;
    memcpy(&input, &value, sizeof(input));
    return input;
}

static void compare(Input left, Input right) {
    int expected = REFERENCE(left, right);
    uint32_t actual = (uint32_t)RECOVERED(left, right);
    results[expected + 1]++;
    if (actual != (uint32_t)expected && mismatches++ == 0) {
        first_left = (uint64_t)left;
        first_right = (uint64_t)right;
        first_expected = (uint32_t)expected;
        first_actual = actual;
    }
}

int main(void) {
    size_t count = sizeof(directed) / sizeof(directed[0]);
    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < count; j++) {
            compare(directed[i], directed[j]);
        }
    }
    for (unsigned i = 0; i < 10000; i++) {
        Input left = random_input();
        Input right = random_input();
        compare(left, right);
    }
    printf("{\"directed\":%zu,\"seeded\":10000,\"less\":%u,\"equal\":%u,\"greater\":%u,"
           "\"mismatches\":%u,\"first_left_bits\":\"%016" PRIx64 "\","
           "\"first_right_bits\":\"%016" PRIx64 "\",\"first_expected_bits\":%u,\"first_actual_bits\":%u}\n",
           count * count, results[0], results[1], results[2], mismatches,
           first_left, first_right, first_expected, first_actual);
    return 0;
}
