#include <stddef.h>
#include <string.h>

#include "heldout_aggregate.h"
#include "aggregate_compat.h"
#include "candidate.c"

_Static_assert(sizeof(packet_t) == 16 && offsetof(packet_t, flags) == 8, "Unexpected packet layout");

#if DISPATCH
packet_t heldout_dispatch(char selector, uint64_t left, uint64_t right);
#endif

static uint64_t seed = UINT64_C(0x313A5BCF76D0914D);
static unsigned mismatches, undefined_results, unspecified_padding, first_mismatch;

static uint64_t next_word(void) {
    seed ^= seed >> 12;
    seed ^= seed << 25;
    seed ^= seed >> 27;
    return seed * UINT64_C(0x2545F4914F6CDD1D);
}

static void compare(unsigned ordinal, int selector, uint64_t left, uint64_t right) {
#if DISPATCH
    packet_t want = heldout_dispatch((char)selector, left, right);
    gh_bits got = RECOVERED((char)selector, left, right);
#elif CHECKED
    int64_t a, b;
    memcpy(&a, &left, sizeof(a));
    memcpy(&b, &right, sizeof(b));
    packet_t want = heldout_checked(a, b);
    gh_bits got = RECOVERED(a, b);
#else
    packet_t want = heldout_packet(left, right);
    gh_bits got = RECOVERED(left, right);
#endif
    if ((got.known & 0x0fff) != 0x0fff) {
        ++undefined_results;
        return;
    }
    unspecified_padding += got.known != UINT16_MAX;
    if (((uint64_t)got.bits != want.word || (uint32_t)(got.bits >> 64) != want.flags)
            && mismatches++ == 0) {
        first_mismatch = ordinal;
    }
}

int main(void) {
    static const uint64_t edges[] = {
        0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0x100000000, 0x007fffffffffffff,
        0x0080000000000000, INT64_MAX-1, INT64_MAX, (uint64_t)INT64_MIN,
        (uint64_t)INT64_MIN+1, UINT64_MAX-1, UINT64_MAX
    };
    const size_t length = sizeof(edges) / sizeof(edges[0]);
    unsigned directed = 0;
#if DISPATCH
    for (int selector = 0; selector < 256; ++selector) {
        for (size_t i = 0; i < length; ++i) {
            compare(directed++, selector, edges[i], edges[(i + selector) % length]);
        }
    }
#else
    for (size_t i = 0; i < length; ++i) {
        for (size_t j = 0; j < length; ++j) {
            compare(directed++, 0, edges[i], edges[j]);
        }
    }
#endif
    for (unsigned i = 0; i < 10000; ++i) {
        uint64_t left = next_word(), right = next_word();
#if DISPATCH
        int selector = i % 2 ? 'A' + next_word() % 6 : (uint8_t)next_word();
#else
        int selector = 0;
#endif
        compare(directed+i, selector, left, right);
    }
    printf("{\"directed\":%u,\"seeded\":10000,\"mismatches\":%u,"
           "\"first_mismatch\":%u,\"undefined_results\":%u,\"unspecified_padding\":%u}\n",
           directed, mismatches, first_mismatch, undefined_results, unspecified_padding);
    return 0;
}
