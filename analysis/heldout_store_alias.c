/* Independent owned variation for byte-range alias checks. */
#include "heldout_store.h"

__attribute__((noinline))
store_result_t heldout_packet(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return (store_result_t){0, 0x21304120U};
    }
    uint64_t before = buffer[1];
    uint64_t mixed = value ^ before;
    __builtin_memcpy((unsigned char *)buffer + 5, &mixed, sizeof(mixed));
    return (store_result_t){mixed, (uint32_t)before ^ 0x603B2005U};
}

__attribute__((noinline))
store_result_t heldout_checked(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return (store_result_t){0, 0x21400CD0U};
    }
    uint64_t before = buffer[1];
    uint64_t mixed = value ^ before;
    __builtin_memcpy((unsigned char *)buffer + 16, &mixed, sizeof(mixed));
    return (store_result_t){mixed, (uint32_t)(before >> 32) ^ 0x1A60C028U};
}

#ifdef HELDOUT_LINK_IMAGE
int main(void) {
    return 0;
}
#endif
