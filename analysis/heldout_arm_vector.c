/* Owned variation with live AArch64 byte permutations and a scalar oracle. */
#include "heldout_store.h"
#include <string.h>

static inline __attribute__((always_inline)) void permute(uint64_t *buffer, unsigned offset) {
#if defined(__aarch64__) && defined(HELDOUT_LINK_IMAGE)
    typedef unsigned char vector16 __attribute__((ext_vector_type(16)));
    vector16 input, reversed, result;
    memcpy(&input, buffer, sizeof(input));
    __asm__("rev64 %0.16b, %1.16b" : "=w"(reversed) : "w"(input));
    if (offset == 9) {
        __asm__("ext %0.16b, %1.16b, %2.16b, #9" : "=w"(result) : "w"(reversed), "w"(input));
    } else {
        __asm__("ext %0.16b, %1.16b, %2.16b, #5" : "=w"(result) : "w"(reversed), "w"(input));
    }
    memcpy(buffer, &result, sizeof(result));
#else
    unsigned char input[16], reversed[16], result[16];
    memcpy(input, buffer, sizeof(input));
    for (unsigned i = 0; i < sizeof(input); ++i) {
        unsigned half = i / 8;
        unsigned index = 7 - i % 8;
        reversed[i] = input[8 * half + index];
    }
    memcpy(result, reversed + offset, sizeof(result) - offset);
    memcpy(result + sizeof(result) - offset, input, offset);
    memcpy(buffer, result, sizeof(result));
#endif
}

__attribute__((noinline))
store_result_t heldout_packet(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return (store_result_t){0, 0x71205380U};
    }
    permute(buffer, 9);
    return (store_result_t){buffer[0] ^ value, (uint32_t)(buffer[1] >> 32) ^ 0x10130002U};
}

__attribute__((noinline))
store_result_t heldout_checked(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return (store_result_t){0, 0x10864005U};
    }
    permute(buffer, 5);
    return (store_result_t){buffer[1] ^ value, (uint32_t)buffer[0] ^ 0x81302055U};
}

#ifdef HELDOUT_LINK_IMAGE
int main(void) {
    return 0;
}
#endif
