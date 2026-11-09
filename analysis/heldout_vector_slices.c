/* Owned variation with two different vector inputs and a scalar store. */
#include "heldout_store.h"
#include <string.h>

static inline __attribute__((always_inline)) void permute(uint64_t *buffer, uint64_t value, unsigned offset) {
#if defined(HELDOUT_LINK_IMAGE) && defined(__aarch64__)
    typedef unsigned char vector16 __attribute__((ext_vector_type(16)));
    vector16 first, second, reversed, result;
    memcpy(&first, buffer, sizeof(first));
    memcpy(&second, buffer + 2, sizeof(second));
    __asm__("rev64 %0.16b, %1.16b" : "=w"(reversed) : "w"(first));
    if (offset == 3) {
        __asm__("ext %0.16b, %1.16b, %2.16b, #3" : "=w"(result) : "w"(reversed), "w"(second));
    } else {
        __asm__("ext %0.16b, %1.16b, %2.16b, #12" : "=w"(result) : "w"(reversed), "w"(second));
    }
#else
    unsigned char first[16], second[16], result[16];
    memcpy(first, buffer, sizeof(first));
    memcpy(second, buffer + 2, sizeof(second));
    for (unsigned i = 0; i < sizeof(result); ++i) {
        unsigned position = i + offset;
        result[i] = position < 16 ? first[position ^ 7U] : second[position - 16];
    }
#endif
    buffer[3] ^= value;
    memcpy(buffer, &result, sizeof(result));
}

__attribute__((noinline))
store_result_t heldout_packet(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return (store_result_t){0, 0x82112312U};
    }
    permute(buffer, value, 3);
    return (store_result_t){buffer[0] ^ value, (uint32_t)(buffer[1] >> 32) ^ 0x50102404U};
}

__attribute__((noinline))
store_result_t heldout_checked(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return (store_result_t){0, 0x49203109U};
    }
    permute(buffer, value, 12);
    return (store_result_t){buffer[1] ^ value, (uint32_t)buffer[0] ^ 0x72240015U};
}

#ifdef HELDOUT_LINK_IMAGE
int main(void) {
    return 0;
}
#endif
