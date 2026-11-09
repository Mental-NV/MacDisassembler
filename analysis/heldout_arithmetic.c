/* Owned variation for evaluating the fixed-width C printer. */
#include "heldout_aggregate.h"

__attribute__((noinline))
packet_t heldout_packet(uint64_t word, uint64_t salt) {
    uint32_t mixed = (uint32_t)word * 0x40000003U - (uint32_t)(salt >> 32);
    return (packet_t){(word + salt) * UINT64_C(0xA343B135AB3AE40D), mixed ^ 0x37B29353U};
}

__attribute__((noinline))
packet_t heldout_checked(int64_t left, int64_t right) {
    int64_t value;
    if ((right & 3) == 3) {
        int32_t low;
        int32_t a = (int32_t)(left >> 32);
        int32_t b = (int32_t)(right >> 32);
        if (__builtin_add_overflow(a, b, &low)) {
            return (packet_t){0, 0x50206000U};
        }
        return (packet_t){(uint64_t)(int64_t)low, 0x30184200U};
    }
    if (right & 1) {
        if (__builtin_sub_overflow(left, right, &value)) {
            return (packet_t){0, 0x215040A0U};
        }
        return (packet_t){(uint64_t)value, 0x71203004U};
    }
    if (__builtin_mul_overflow(left, right, &value)) {
        return (packet_t){0, 0x60401200U};
    }
    return (packet_t){(uint64_t)value, 0x05323155U};
}

#ifdef HELDOUT_LINK_IMAGE
int main(void) {
    return 0;
}
#endif
