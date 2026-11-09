/* Ghidra printed byte aggregates, with an explicit byte-definedness mask. */
#ifndef MACSCOPE_AGGREGATE_COMPAT_H
#define MACSCOPE_AGGREGATE_COMPAT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t byte;
typedef uint8_t undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined4;
typedef unsigned long undefined8;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned __int128 gh_wide;

typedef struct {
    gh_wide bits;
    uint16_t known;
} gh_bits;

static gh_bits gh_known(gh_wide value) {
    return (gh_bits){value, UINT16_MAX};
}

static gh_wide gh_mask(unsigned width) {
    return (gh_wide)-1 >> ((16-width)*8);
}

static unsigned gh_byte_mask(unsigned offset, unsigned width) {
    return ((1u << width)-1) << offset;
}

static gh_bits gh_low_bytes(gh_bits value, unsigned width) {
    return (gh_bits){value.bits & gh_mask(width), value.known & gh_byte_mask(0, width)};
}

static void gh_undef(gh_bits *value, unsigned offset, unsigned width) {
    value->known &= ~gh_byte_mask(offset, width);
}

static void gh_set(gh_bits *value, unsigned offset, unsigned width, gh_wide bits) {
    gh_wide mask = gh_mask(width) << (offset*8);
    value->bits = (value->bits & ~mask) | ((bits << (offset*8)) & mask);
    value->known |= gh_byte_mask(offset, width);
}

static void gh_copy_field(gh_bits *dest, unsigned offset, unsigned width, gh_bits source) {
    unsigned mask = gh_byte_mask(offset, width);
    gh_set(dest, offset, width, source.bits);
    dest->known = (dest->known & ~mask) | ((source.known << offset) & mask);
}

static gh_wide gh_read(gh_bits value, unsigned offset, unsigned width) {
    unsigned mask = gh_byte_mask(offset, width);
    if ((value.known & mask) != mask) {
        fputs("GHIDRA_UNDEFINED_INPUT\n", stderr);
        exit(70);
    }
    return (value.bits >> (offset*8)) & gh_mask(width);
}

static __int128 gh_signed(gh_bits value) {
    return (__int128)gh_read(value, 0, 16);
}

static __int128 gh_signed_scalar(__int128 value) {
    return value;
}

#define GH_SIGNED16(value) _Generic((value), gh_bits: gh_signed, default: gh_signed_scalar)(value)
#define SDIV16(left, right) (GH_SIGNED16(left) / GH_SIGNED16(right))

static gh_bits gh_shift(gh_bits value, unsigned bytes) {
    return (gh_bits){value.bits << (bytes*8), (uint16_t)((value.known << bytes) | ((1u<<bytes)-1))};
}

static gh_bits gh_load_vector(const void *address) {
    gh_wide value;
    memcpy(&value, address, sizeof(value));
    return gh_known(value);
}

static void gh_store_vector(void *address, gh_bits value) {
    gh_wide bits = gh_read(value, 0, 16);
    memcpy(address, &bits, sizeof(bits));
}

static void gh_copy_byte(gh_bits *dest, unsigned index, gh_bits src, unsigned source) {
    if (src.known & (1u << source)) {
        gh_set(dest, index, 1, src.bits >> (source * 8));
    }
}

static gh_bits NEON_rev64(gh_bits input, unsigned lane_bytes) {
    if (lane_bytes != 1) abort();
    gh_bits result = {0};
    for (unsigned i = 0; i < 16; ++i) {
        gh_copy_byte(&result, i, input, i ^ 7);
    }
    return result;
}

static gh_bits NEON_ext(gh_bits first, gh_bits second, unsigned offset, unsigned lane_bytes) {
    if (lane_bytes != 1 || offset >= 16) abort();
    gh_bits result = {0};
    for (unsigned i = 0; i < 16; ++i) {
        unsigned source = i + offset;
        gh_copy_byte(&result, i, source < 16 ? first : second, source & 15);
    }
    return result;
}

static gh_bits CONCAT88(uint64_t high, uint64_t low) {
    return gh_known(((gh_wide)high << 64) | low);
}

static gh_bits pshufb(gh_bits input, gh_bits controls) {
    gh_bits result = {0};
    for (unsigned i = 0; i < 16; ++i) {
        if (controls.known & (1u << i)) {
            unsigned char control = (unsigned char)(controls.bits >> (i * 8));
            if (control & 0x80) {
                gh_set(&result, i, 1, 0);
            } else {
                gh_copy_byte(&result, i, input, control & 15);
            }
        }
    }
    return result;
}

static bool SCARRY8(int64_t left, int64_t right) {
    int64_t ignored;
    return __builtin_add_overflow(left, right, &ignored);
}

static bool SBORROW8(int64_t left, int64_t right) {
    int64_t ignored;
    return __builtin_sub_overflow(left, right, &ignored);
}

static __int128 SEXT816(int64_t value) { return value; }
static gh_wide ZEXT816(uint64_t value) { return value; }
static gh_wide ZEXT412(uint32_t value) { return value; }
static uint64_t SUB168(gh_wide value, unsigned offset) { return (uint64_t)(value >> (offset*8)); }

_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "Store evaluator requires little-endian memory");

static void STORE_LE16(void *address, uint16_t value) {
    memcpy(address, &value, sizeof(value));
}

static void STORE_LE32(void *address, uint32_t value) {
    memcpy(address, &value, sizeof(value));
}

static void STORE_LE64(void *address, uint64_t value) {
    memcpy(address, &value, sizeof(value));
}

#endif
