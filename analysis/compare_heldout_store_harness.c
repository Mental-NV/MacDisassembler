#include <stddef.h>

#include "heldout_store.h"
#include "aggregate_compat.h"
#include "candidate.c"

_Static_assert(sizeof(store_result_t) == 16 && offsetof(store_result_t, flags) == 8,
               "Unexpected store result layout");

static uint64_t seed = UINT64_C(0x78A04C63335E1FA9);
static unsigned mismatches, undefined_results, unspecified_padding, first_mismatch;

static uint64_t next_word(void) {
    seed ^= seed >> 12;
    seed ^= seed << 25;
    seed ^= seed >> 27;
    return seed * UINT64_C(0x2545F4914F6CDD1D);
}

static void compare(unsigned ordinal, uint64_t fill, uint64_t value, bool missing) {
    uint64_t actual[4] = {fill, ~fill, fill ^ UINT64_C(0x10103AF5083B0714), fill >> 9};
    uint64_t expected[4];
    memcpy(expected, actual, sizeof(expected));
#if POINTER_INPUT
    void *address = missing ? NULL : actual;
#else
    uintptr_t address = missing ? 0 : (uintptr_t)actual;
#endif
    gh_bits got = RECOVERED(address, value);
#if CHECKED
    store_result_t want = heldout_checked(missing ? NULL : expected, value);
#else
    store_result_t want = heldout_packet(missing ? NULL : expected, value);
#endif
    if ((got.known & 0x0fff) != 0x0fff) {
        ++undefined_results;
        return;
    }
    unspecified_padding += got.known != UINT16_MAX;
    if (((uint64_t)got.bits != want.word || (uint32_t)(got.bits >> 64) != want.flags
            || memcmp(actual, expected, sizeof(actual))) && mismatches++ == 0) {
        first_mismatch = ordinal;
    }
}

int main(void) {
    static const uint64_t edges[] = {
        0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000,
        0xffff, 0x10000, 0x7fffffff, 0x80000000, 0xffffffff,
        0x100000000, INT64_MAX, UINT64_MAX
    };
    const size_t length = sizeof(edges) / sizeof(edges[0]);
    unsigned directed = 0;
    for (size_t i = 0; i < length; ++i) {
        for (size_t j = 0; j < length; ++j) {
            compare(directed++, edges[i], edges[j], i == 0);
        }
    }
    for (unsigned i = 0; i < 10000; ++i) {
        uint64_t fill = next_word(), value = next_word();
        compare(directed+i, fill, value, i % 43 == 0);
    }
    printf("{\"directed\":%u,\"seeded\":10000,\"mismatches\":%u,"
           "\"first_mismatch\":%u,\"undefined_results\":%u,\"unspecified_padding\":%u}\n",
           directed, mismatches, first_mismatch, undefined_results, unspecified_padding);
    return 0;
}
