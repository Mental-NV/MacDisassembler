/* An owned indirect-call fixture, independent of the calculator. */
#include <stddef.h>

#include "heldout_aggregate.h"

typedef packet_t (*operation_t)(uint64_t, uint64_t);

static __attribute__((noinline)) packet_t mix(uint64_t left, uint64_t right) {
    return (packet_t){left ^ (right << 3), (uint32_t)left ^ 0xE02AB675U};
}

static __attribute__((noinline)) packet_t combine(uint64_t left, uint64_t right) {
    return (packet_t){(left >> 5) + right, 0x86072051U};
}

static __attribute__((noinline)) packet_t fold(uint64_t left, uint64_t right) {
    return (packet_t){(left << 13) | (right >> 7), (uint32_t)right ^ 0x051D84B0U};
}

static __attribute__((noinline)) packet_t difference(uint64_t left, uint64_t right) {
    return (packet_t){right - left, 0x10F1C03DU};
}

static const struct {
    char selector;
    operation_t operation;
} operations[] = {
    {'D', mix},
    {'F', combine},
    {'A', fold},
    {'B', difference},
};

__attribute__((noinline))
packet_t heldout_dispatch(char selector, uint64_t left, uint64_t right) {
    for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i) {
        if (operations[i].selector == selector) {
            return operations[i].operation(left, right);
        }
    }
    return (packet_t){0, 0x15A5F00DU};
}

#ifdef HELDOUT_LINK_IMAGE
int main(void) {
    return 0;
}
#endif
