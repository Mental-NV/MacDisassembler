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

static gh_bits gh_shift(gh_bits value, unsigned bytes) {
    return (gh_bits){value.bits << (bytes*8), (uint16_t)((value.known << bytes) | ((1u<<bytes)-1))};
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
