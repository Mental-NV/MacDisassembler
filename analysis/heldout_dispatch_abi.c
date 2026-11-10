/* An owned dispatch fixture with a caller that observes both result fields. */
#include <stddef.h>
#include "heldout_aggregate.h"

typedef packet_t (*operation_t)(uint64_t, uint64_t);

static __attribute__((noinline)) packet_t either(uint64_t left, uint64_t right) {
    return (packet_t){left | right, 0xAB4E7C00U};
}

static __attribute__((noinline)) packet_t both(uint64_t left, uint64_t right) {
    return (packet_t){left & right, 0x21A70D11U};
}

static __attribute__((noinline)) packet_t opposite(uint64_t left, uint64_t right) {
    return (packet_t){left ^ right, 0x54E10C82U};
}

static __attribute__((noinline)) packet_t inverse(uint64_t left, uint64_t right) {
    return (packet_t){~(left ^ right), 0x7806F0B3U};
}

static const struct {
    char selector;
    operation_t operation;
} operations[] = {
    {'q', opposite},
    {'o', both},
    {'r', inverse},
    {'m', either},
};

__attribute__((noinline))
packet_t heldout_dispatch(char selector, uint64_t left, uint64_t right) {
    for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i) {
        if (operations[i].selector == selector) {
            return operations[i].operation(left, right);
        }
    }
    return (packet_t){0, 0x1286CFA4U};
}

#ifdef HELDOUT_LINK_IMAGE
static volatile uint32_t observed_flags;
static volatile uint64_t observed_word;

int main(int argc, char **argv) {
    packet_t result = heldout_dispatch((char)argc, (uint64_t)argc, (uintptr_t)argv);
    observed_flags = result.flags;
    observed_word = result.word;
    return 0;
}
#endif
