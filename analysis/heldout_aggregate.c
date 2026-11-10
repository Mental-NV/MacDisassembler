/* An owned evaluator fixture, separate from the calculator. */
#include "heldout_aggregate.h"

__attribute__((noinline))
packet_t heldout_packet(uint64_t word, uint64_t salt) {
    uint64_t rotated = (word << 9) | (word >> 55);
    return (packet_t){rotated ^ salt, 0xA1B2C300U | ((uint32_t)(word ^ salt) & 0xffU)};
}

__attribute__((noinline))
packet_t heldout_checked(int64_t left, int64_t right) {
    int64_t sum;
    if (__builtin_add_overflow(left, right, &sum)) {
        return (packet_t){0, 0x13570003U};
    }
    return (packet_t){(uint64_t)sum, 0x10203040U};
}

#ifdef HELDOUT_LINK_IMAGE
int main(void) {
    return 0;
}
#endif
