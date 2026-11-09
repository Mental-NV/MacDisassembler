/* Owned direct calls with two-register and single-register observation controls. */
#include "heldout_aggregate.h"

static __attribute__((noinline)) packet_t combine(uint64_t left, uint64_t right) {
    return (packet_t){left ^ (right | UINT64_C(0x19461)), 0x237AD119U};
}

static __attribute__((noinline)) packet_t difference(uint64_t left, uint64_t right) {
    return (packet_t){left - right, 0x72EF0014U};
}

__attribute__((noinline, disable_tail_calls))
packet_t heldout_checked(int64_t left, int64_t right) {
    switch ((uint64_t)left & 7U) {
    case 1:
        return combine((uint64_t)right + 15, (uint64_t)left);
    case 4:
        return difference((uint64_t)left, (uint64_t)right ^ 3U);
    default:
        return (packet_t){(uint64_t)left & (uint64_t)right, 0x105FC802U};
    }
}

__attribute__((noinline, disable_tail_calls))
packet_t heldout_packet(uint64_t word, uint64_t salt) {
    if (word & 2U) {
        return difference(salt, word + 5);
    }
    return combine(word, salt ^ 9U);
}

#ifdef HELDOUT_LINK_IMAGE
static volatile uint64_t observed_word;
static volatile uint32_t observed_flags;

int main(int argc, char **argv) {
    packet_t checked = heldout_checked(argc, (int64_t)(uintptr_t)argv);
    observed_word = checked.word;
    observed_flags = checked.flags;
    observed_word = heldout_packet((uint64_t)argc, (uintptr_t)argv).word;
    return 0;
}
#endif
