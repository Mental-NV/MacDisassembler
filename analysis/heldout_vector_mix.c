/* Independent byte permutations with live vector pointer arguments. */
#include "heldout_store.h"
#include <string.h>

static inline __attribute__((always_inline)) void permute(uint64_t *buffer, unsigned offset) {
#if defined(HELDOUT_LINK_IMAGE)
    typedef unsigned char vector16 __attribute__((ext_vector_type(16)));
    vector16 input, result;
    memcpy(&input, buffer, sizeof(input));
#if defined(__aarch64__)
    vector16 reversed;
    __asm__("rev64 %0.16b, %1.16b" : "=w"(reversed) : "w"(input));
    if (offset == 2) {
        __asm__("ext %0.16b, %1.16b, %2.16b, #2" : "=w"(result) : "w"(reversed), "w"(input));
    } else {
        __asm__("ext %0.16b, %1.16b, %2.16b, #11" : "=w"(result) : "w"(reversed), "w"(input));
    }
#else
    uint64_t low = offset == 2 ? UINT64_C(0x0e0f000102030405) : UINT64_C(0x02010008090a0b0c);
    uint64_t high = offset == 2 ? UINT64_C(0x010008090a0b0c0d) : UINT64_C(0x0a09080706050403);
    vector16 mask;
    __asm__("movq %1,%0; pinsrq $1,%2,%0" : "=&x"(mask) : "r"(low), "r"(high));
    result = input;
    __asm__("pshufb %1,%0" : "+x"(result) : "x"(mask));
#endif
    memcpy(buffer, &result, sizeof(result));
#else
    unsigned char input[16], result[16];
    memcpy(input, buffer, sizeof(input));
    for (unsigned i = 0; i < sizeof(input); ++i) {
        unsigned position = i + offset;
        unsigned index = position < 16 ? position ^ 7U : position - 16;
        result[i] = input[index];
    }
    memcpy(buffer, result, sizeof(result));
#endif
}

__attribute__((noinline))
store_result_t heldout_packet(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return (store_result_t){0, 0x22137144U};
    }
    permute(buffer, 2);
    return (store_result_t){buffer[0] ^ value, (uint32_t)(buffer[1] >> 32) ^ 0x40713352U};
}

__attribute__((noinline))
store_result_t heldout_checked(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return (store_result_t){0, 0x88224701U};
    }
    permute(buffer, 11);
    return (store_result_t){buffer[1] ^ value, (uint32_t)buffer[0] ^ 0x64301837U};
}

#ifdef HELDOUT_LINK_IMAGE
int main(void) {
    return 0;
}
#endif
