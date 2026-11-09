/* Owned variation for evaluating byte-offset memory writes. */
#include "heldout_store.h"

__attribute__((noinline))
store_result_t heldout_packet(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return (store_result_t){0, 0x15401200U};
    }
    uint64_t anchor = *buffer;
    uint64_t mixed = value ^ anchor;
    __builtin_memcpy((unsigned char *)buffer + 3, &mixed, sizeof(mixed));
    return (store_result_t){mixed, (uint32_t)anchor ^ 0x60A4120FU};
}

__attribute__((noinline))
store_result_t heldout_checked(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return (store_result_t){0, 0x48205D00U};
    }
    uint64_t anchor = *buffer;
    uint32_t low = (uint32_t)(value ^ anchor);
    uint16_t high = (uint16_t)(value >> 48);
    __builtin_memcpy((unsigned char *)buffer + 5, &low, sizeof(low));
    __builtin_memcpy((unsigned char *)buffer + 13, &high, sizeof(high));
    return (store_result_t){anchor, low ^ 0x3A712C55U};
}

#ifdef HELDOUT_LINK_IMAGE
int main(void) {
    return 0;
}
#endif
