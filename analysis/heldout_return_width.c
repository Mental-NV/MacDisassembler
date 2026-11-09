/* Owned producer and caller for aggregate return-width evaluation. */
#include "heldout_aggregate.h"

__attribute__((noinline))
packet_t heldout_packet(uint64_t word, uint64_t salt) {
    uint64_t mixed = word ^ ((salt << 7) | (salt >> 57));
    uint32_t flags = (uint32_t)((word >> 32) ^ salt) ^ 0x81032071U;
    return (packet_t){mixed, flags};
}

__attribute__((noinline))
packet_t heldout_checked(int64_t left, int64_t right) {
    packet_t incoming = heldout_packet((uint64_t)left, (uint64_t)right);
    uint64_t word = incoming.word;
    if (incoming.flags & 4U) {
        word ^= UINT64_C(0x5382A0010A052104);
    }
    return (packet_t){word ^ (uint64_t)left, incoming.flags ^ 0x11325504U};
}

#ifdef HELDOUT_LINK_IMAGE
int main(void) {
    return 0;
}
#endif
