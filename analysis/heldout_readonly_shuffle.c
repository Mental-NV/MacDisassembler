/* Owned fixture with an immutable shuffle mask and a writable control. */
#include "heldout_store.h"
#include <string.h>

static const unsigned char first_mask[16] __attribute__((aligned(16))) = {
    0x8f, 0x27, 0x42, 0x71, 0x14, 0x90, 0x7e, 0x03,
    0x20, 0x81, 0x65, 0x36, 0x19, 0x5a, 0x0b, 0x0c
};
static const unsigned char second_mask[16] __attribute__((aligned(16))) = {
    1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 0, 1, 2, 3, 4, 5
};
unsigned char heldout_writable_mask[16] __attribute__((aligned(16))) = {
    2, 4, 6, 8, 10, 12, 14, 0, 1, 3, 5, 7, 9, 11, 13, 15
};

static inline __attribute__((always_inline)) void shuffle(
    uint64_t *buffer, const unsigned char *selectors, uint64_t value, int reverse_extract
) {
#if defined(HELDOUT_LINK_IMAGE) && defined(__x86_64__)
    typedef unsigned char vector16 __attribute__((ext_vector_type(16)));
    vector16 input, mask;
    memcpy(&input, buffer, sizeof(input));
    __asm__ volatile("movdqa %1,%0" : "=x"(mask) : "m"(*(const vector16 *)selectors));
    if (value & 1U) {
        buffer[2] = value;
    }
    __asm__("pshufb %1,%0" : "+x"(input) : "x"(mask));
    memcpy(buffer, &input, sizeof(input));
#else
#if defined(HELDOUT_LINK_IMAGE) && defined(__aarch64__)
    if (reverse_extract) {
        typedef unsigned char vector16 __attribute__((ext_vector_type(16)));
        vector16 input, reversed, result;
        memcpy(&input, buffer, sizeof(input));
        __asm__("rev64 %0.16b, %1.16b" : "=w"(reversed) : "w"(input));
        __asm__("ext %0.16b, %1.16b, %2.16b, #6" : "=w"(result) : "w"(reversed), "w"(input));
        if (value & 1U) {
            buffer[2] = value;
        }
        memcpy(buffer, &result, sizeof(result));
        return;
    }
#endif
    unsigned char input[16], output[16];
    memcpy(input, buffer, sizeof(input));
    if (value & 1U) {
        buffer[2] = value;
    }
    for (unsigned i = 0; i < sizeof(input); ++i) {
        unsigned selector = selectors[i];
        output[i] = selector & 0x80 ? 0 : input[selector & 15];
    }
    memcpy(buffer, output, sizeof(output));
#endif
}

__attribute__((noinline))
store_result_t heldout_packet(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return (store_result_t){0, 0x75346820U};
    }
    shuffle(buffer, first_mask, value, 0);
    return (store_result_t){buffer[0] ^ value, (uint32_t)(buffer[1] >> 32) ^ 0x24150006U};
}

__attribute__((noinline))
store_result_t heldout_checked(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return (store_result_t){0, 0x48813102U};
    }
    shuffle(buffer, second_mask, value, 1);
    return (store_result_t){buffer[1] ^ value, (uint32_t)buffer[0] ^ 0x12230028U};
}

#ifdef HELDOUT_LINK_IMAGE
__attribute__((noinline))
uint64_t heldout_mutable(uint64_t *buffer, uint64_t value) {
    if (!buffer) {
        return 0;
    }
    shuffle(buffer, heldout_writable_mask, value, 0);
    return buffer[0];
}

int main(void) {
    return 0;
}
#endif
