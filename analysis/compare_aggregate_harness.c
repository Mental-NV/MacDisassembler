/* Evaluate the visible value and status of the owned aggregate returns. */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "calc_core.h"
#include "aggregate_compat.h"
#include "candidate.c"

_Static_assert(sizeof(long) == 8 && sizeof(int) == 4 && CHAR_MIN < 0,
               "Evaluator requires the tested Darwin data model");
_Static_assert(sizeof(calc_result_t) == 16 && offsetof(calc_result_t, status) == 8
               && sizeof(calc_status_t) == 4, "Unexpected evaluator result layout");

static uint64_t seed = UINT64_C(0xA47DE13C9700B3C1);
static unsigned mismatches, undefined_results, unspecified_padding, first_mismatch;

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

static void compare(unsigned index, gh_bits got, calc_result_t expected, bool changed) {
    if ((got.known & 0x0fff) != 0x0fff) {
        ++undefined_results;
        return;
    }
    unspecified_padding += got.known != UINT16_MAX;
    uint64_t result = (uint64_t)got.bits;
    uint32_t status = (uint32_t)(got.bits >> 64);
    if ((changed || status != (uint32_t)expected.status || result != (uint64_t)expected.value)
            && mismatches++ == 0) {
        first_mismatch = index;
    }
}

#if KIND == 10
static void parse_case(unsigned ordinal, const char *input, size_t length) {
    char copy[128];
    memcpy(copy, input ? input : "", input ? sizeof(copy) : 1);
    calc_result_t expected = REFERENCE(input, length);
    gh_bits got = RECOVERED(input ? copy : NULL, length);
    compare(ordinal, got, expected, input && memcmp(input, copy, sizeof(copy)) != 0);
}
#elif KIND == 13
static void history_case(unsigned ordinal, const calc_history_t *input) {
    calc_history_t copy;
    if (input) memcpy(&copy, input, sizeof(copy));
    calc_result_t expected = REFERENCE(input);
    gh_bits got = RECOVERED(input ? (long)(uintptr_t)&copy : 0);
    compare(ordinal, got, expected, input && memcmp(input, &copy, sizeof(copy)) != 0);
}
#else
static void numeric_case(unsigned ordinal, int64_t left, int64_t right, int selector) {
#if KIND == 5 || KIND == 6 || KIND == 12
    compare(ordinal, RECOVERED(left), REFERENCE(left), false);
#elif KIND == 8 || KIND == 9
    compare(ordinal, RECOVERED((char)selector, left, right),
            REFERENCE((char)selector, left, right), false);
#elif KIND == 11
    compare(ordinal, RECOVERED(left, selector), REFERENCE(left, selector), false);
#else
    compare(ordinal, RECOVERED(left, right), REFERENCE(left, right), false);
#endif
}
#endif

int main(void) {
    static const int64_t values[] = {
        INT64_MIN, INT64_MIN+1, INT64_MIN/10, -INT64_C(0x100000000), -64, -2, -1, 0, 1,
        2, 9, 10, 31, 62, 63, 64, INT64_C(0x100000000), INT64_MAX/10, INT64_MAX-1, INT64_MAX
    };
    unsigned directed = 0;
#if KIND == 10
    char text[128];
    memset(text, '0', sizeof(text));
    parse_case(directed++, NULL, 0);
    parse_case(directed++, NULL, 17);
    parse_case(directed++, text, 0);
    parse_case(directed++, text, 64);
    parse_case(directed++, text, 65);
    for (unsigned i = 0; i < 256; ++i) {
        text[0] = (char)i;
        parse_case(directed++, text, 1);
    }
    static const char *const boundaries[] = {
        "-", "00", "-0", "9223372036854775807", "9223372036854775808",
        "-9223372036854775808", "-9223372036854775809",
        "18446744073709551615", "18446744073709551616", "00000000000000000009223372036854775807"
    };
    for (size_t i = 0; i < sizeof(boundaries)/sizeof(boundaries[0]); ++i) {
        size_t length = strlen(boundaries[i]);
        memcpy(text, boundaries[i], length);
        parse_case(directed++, text, length);
    }
    for (unsigned i = 0; i < 10000; ++i) {
        size_t length = (size_t)(bits() % 67);
        for (size_t j = 0; j < length; ++j) text[j] = '0' + (char)(bits() % 10);
        if (length && i % 2) text[0] = '-';
        if (length && i % 5 == 0) {
            size_t position = (size_t)(bits() % length);
            text[position] = (char)bits();
        }
        parse_case(directed+i, text, length);
    }
#elif KIND == 13
    calc_history_t history;
    history_case(directed++, NULL);
    for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); ++i) {
        calc_history_init(&history);
        for (unsigned j = 0; j < 33; ++j) {
            history_case(directed++, &history);
            calc_history_push(&history, 0, '+', 0, values[i]);
        }
    }
    for (unsigned i = 0; i < 10000; ++i) {
        calc_history_init(&history);
        unsigned pushes = (unsigned)(bits() % 33);
        for (unsigned j = 0; j < pushes; ++j)
            calc_history_push(&history, 0, '+', 0, signed_bits(bits()));
        history_case(directed+i, &history);
    }
#else
    size_t length = sizeof(values)/sizeof(values[0]);
#if KIND == 5 || KIND == 6 || KIND == 12
    for (size_t i = 0; i < length; ++i) numeric_case(directed++, values[i], 0, 0);
    for (int i = -64; i < 64; ++i) numeric_case(directed++, i, 0, 0);
#else
    static const int selectors[] = {-1, 0, 1, 2, 9, 10, '*', '+', '-', '/', 127, 255};
    for (size_t i = 0; i < length; ++i) {
#if KIND == 11
        for (size_t s = 0; s < sizeof(selectors)/sizeof(selectors[0]); ++s)
            numeric_case(directed++, values[i], 0, selectors[s]);
#else
        for (size_t j = 0; j < length; ++j) {
#if KIND == 8 || KIND == 9
            for (size_t s = 0; s < sizeof(selectors)/sizeof(selectors[0]); ++s)
                numeric_case(directed++, values[i], values[j], selectors[s]);
#else
            numeric_case(directed++, values[i], values[j], 0);
#endif
        }
#endif
    }
#endif
    for (unsigned i = 0; i < 10000; ++i) {
        int64_t left = signed_bits(bits());
        int64_t right = signed_bits(bits());
        int selector = (int)(bits() % 256);
        if (i % 3 == 0) left %= 1000000;
        if (i % 3 == 1) right %= 100;
#if KIND == 8 || KIND == 9
        if (i % 2) selector = "+-*/"[selector & 3];
#elif KIND == 11
        if (i % 2) selector %= 10;
#elif KIND == 7
        if (i % 2) right %= 64;
#endif
        numeric_case(directed+i, left, right, selector);
    }
#endif
    printf("{\"directed\":%u,\"seeded\":10000,\"mismatches\":%u,"
           "\"first_mismatch\":%u,\"undefined_results\":%u,\"unspecified_padding\":%u}\n",
           directed, mismatches, first_mismatch, undefined_results, unspecified_padding);
    return 0;
}
