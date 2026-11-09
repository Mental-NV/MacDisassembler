/* Compare the unmodified recovered history routines in the Darwin data model. */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "calc_core.h"

typedef unsigned char undefined1;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long undefined8;

#if HISTORY_KIND == 1
static void _bzero(void *buffer, size_t size) {
    memset(buffer, 0, size);
}

static void ___bzero(long address, size_t size) {
    _bzero((void *)(uintptr_t)address, size);
}

static void ___memset_chk(long address, int value, size_t size, size_t capacity) {
    if (size > capacity) abort();
    memset((void *)(uintptr_t)address, value, size);
}
#endif

#include "candidate.c"

_Static_assert(sizeof(long) == 8 && sizeof(int) == 4 && CHAR_MIN < 0,
               "Evaluator requires the tested Darwin data model");
_Static_assert(sizeof(calc_history_entry_t) == 0x20 &&
               offsetof(calc_history_entry_t, op) == 8 &&
               offsetof(calc_history_entry_t, operand2) == 0x10 &&
               offsetof(calc_history_entry_t, result) == 0x18 &&
               offsetof(calc_history_t, count) == 0x200 &&
               sizeof(calc_history_t) == 0x208, "Unexpected history layout");

static uint64_t seed = UINT64_C(0x57B4A6CE316D9C73);
static unsigned mismatches;
static unsigned first_mismatch;

static uint64_t bits(void) {
    uint64_t value = (seed += UINT64_C(0x9E3779B97F4A7C15));
    value = (value ^ (value >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94D049BB133111EB);
    return value ^ (value >> 31);
}

static int64_t signed_bits(uint64_t value) {
    int64_t result;
    memcpy(&result, &value, sizeof(result));
    return result;
}

static void compare(unsigned ordinal, calc_history_t *actual, calc_history_t *expected,
                    size_t index, uint64_t left, unsigned char op, uint64_t right,
                    uint64_t result) {
    long address = (long)(uintptr_t)actual;
    int differs;
#if HISTORY_KIND == 1
#if POINTER_INIT
    RECOVERED(actual);
#else
    RECOVERED(address);
#endif
    calc_history_init(expected);
    differs = actual && memcmp(actual, expected, sizeof(*actual)) != 0;
#elif HISTORY_KIND == 2
    RECOVERED(address, left, op, right, result);
    calc_history_push(expected, signed_bits(left), (char)op, signed_bits(right), signed_bits(result));
    differs = actual && memcmp(actual, expected, sizeof(*actual)) != 0;
#elif HISTORY_KIND == 3
    differs = RECOVERED(address) != calc_history_len(expected)
              || (actual && memcmp(actual, expected, sizeof(*actual)) != 0);
#elif HISTORY_KIND == 4
    const calc_history_entry_t *entry = calc_history_get(expected, index);
    uintptr_t expected_address = entry ? (uintptr_t)&actual->entries[entry - expected->entries] : 0;
    differs = (uintptr_t)RECOVERED(address, index) != expected_address
              || (actual && memcmp(actual, expected, sizeof(*actual)) != 0);
#else
#error Unknown history routine
#endif
    if (differs && mismatches++ == 0) first_mismatch = ordinal;
}

int main(int argc, char **argv) {
    static const size_t counts[] = {
        0, 1, 2, 14, 15, 16, 17, 31, 32, 33, INT_MAX-1, INT_MAX,
        (size_t)INT_MAX+1, UINT32_MAX, (size_t)UINT32_MAX+1, LONG_MAX-1,
        LONG_MAX, (size_t)LONG_MAX+1, SIZE_MAX-1, SIZE_MAX
    };
    static const size_t indices[] = {
        0, 1, 2, 14, 15, 16, 17, INT_MAX, (size_t)INT_MAX+1, LONG_MAX, SIZE_MAX
    };
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "wide") != 0)) return 2;
    int wide = argc == 2;
    size_t regular_counts = 10;
    size_t count_end = wide ? sizeof(counts) / sizeof(counts[0]) : regular_counts;
    calc_history_t actual, expected;
    unsigned directed = 0;
    if (!wide) compare(directed++, NULL, NULL, 0, 0, 0, 0, 0);
    for (size_t i = wide ? regular_counts : 0; i < count_end; ++i) {
        for (size_t j = 0; j < sizeof(indices) / sizeof(indices[0]); ++j) {
            memset(&actual, 0xA5, sizeof(actual));
            actual.count = counts[i];
            memcpy(&expected, &actual, sizeof(actual));
            compare(directed++, &actual, &expected, indices[j], UINT64_C(1)<<63,
                    '-', INT64_MAX, UINT64_MAX);
        }
    }
    memset(&actual, 0x5A, sizeof(actual));
    actual.count = 0;
    memcpy(&expected, &actual, sizeof(actual));
    unsigned seeded = wide ? 0 : 10000;
    for (unsigned i = 0; i < seeded; ++i) {
#if HISTORY_KIND != 2
        /* Build a wrapped ring by running the trusted reference pushes. */
        int64_t value = signed_bits(bits());
        calc_history_push(&actual, value, '+', value, value);
        memcpy(&expected, &actual, sizeof(actual));
#endif
        size_t index = i % 3 ? (size_t)(bits() % 20) : (size_t)bits();
        uint64_t left = bits();
        unsigned char op = (unsigned char)bits();
        uint64_t right = bits();
        uint64_t result = bits();
        compare(directed + i, &actual, &expected, index, left, op, right, result);
    }
    printf("{\"directed\":%u,\"seeded\":%u,\"mismatches\":%u,\"first_mismatch\":%u}\n",
           directed, seeded, mismatches, first_mismatch);
    return 0;
}
