/* Owned controls for signed wide division and ordinary unsigned division. */
#include "heldout_aggregate.h"

__attribute__((noinline))
packet_t heldout_packet(uint64_t word, uint64_t salt) {
    if (salt == 0) {
        return (packet_t){0, 0x83120307U};
    }
    return (packet_t){(word / salt) ^ UINT64_C(0xB49A8C3361), 0x431C2005U};
}

__attribute__((noinline))
packet_t heldout_checked(int64_t left, int64_t right) {
    if (right >= -1 && right <= 1) {
        return (packet_t){0, 0x12124107U};
    }
    // The odd low word keeps the quotient representable for |right| >= 2.
    uint64_t low = ((uint64_t)left ^ UINT64_C(0xD73302457251E6AE)) | 1;
    int64_t high = -(int64_t)(left < 0);
#if defined(__x86_64__)
    __asm__("idivq %[divisor]" : "+a"(low), "+d"(high) : [divisor] "r"(right) : "cc");
    uint64_t quotient = low;
#else
    __int128 dividend = (__int128)high * (((__int128)1) << 64) + low;
    uint64_t quotient = (uint64_t)(dividend / right);
#endif
    return (packet_t){quotient ^ UINT64_C(0x71CE308F9B), 0x2417B601U};
}

#ifdef HELDOUT_LINK_IMAGE
int main(void) {
    return 0;
}
#endif
