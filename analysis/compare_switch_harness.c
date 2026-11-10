/* Evaluates the emitted declarations and compares the 32-bit return bits. */
#include <stdint.h>
#include <stdio.h>

typedef uint32_t uint;
typedef uint32_t undefined4;
typedef uint64_t undefined8;
typedef unsigned long ulong;

#define main fixture_main
#include "heldout_switch.c"
#undef main
#include "candidate.c"

static uint32_t random_u32(void)
{
    static uint32_t state = UINT32_C(0xca4ec052);
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

static int differs(uint32_t operation, uint32_t left, uint32_t right)
{
#if DISPATCH
    return (uint32_t)CANDIDATE(operation, left, right) != REFERENCE(operation, left, right);
#else
    (void)operation;
    return (uint32_t)CANDIDATE(left, right) != REFERENCE(left, right);
#endif
}

int main(void)
{
    const uint32_t values[] = {
        0, 1, 2, 3, 127, 255, 256, UINT32_C(0x7fffffff), UINT32_C(0x80000000),
        UINT32_MAX - 1, UINT32_MAX,
    };
#if DISPATCH
    const uint32_t operations[] = {0, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, UINT32_MAX};
#else
    const uint32_t operations[] = {0};
#endif
    unsigned directed = 0;
    unsigned mismatches = 0;
    for (size_t op = 0; op < sizeof(operations) / sizeof(operations[0]); ++op) {
        for (size_t a = 0; a < sizeof(values) / sizeof(values[0]); ++a) {
            for (size_t b = 0; b < sizeof(values) / sizeof(values[0]); ++b) {
                mismatches += differs(operations[op], values[a], values[b]);
                ++directed;
            }
        }
    }
    for (unsigned i = 0; i < 10000; ++i) {
        uint32_t operation = i % 2 ? random_u32() : operations[(i / 2) % (sizeof(operations) / sizeof(operations[0]))];
        uint32_t left = random_u32();
        uint32_t right = random_u32();
        mismatches += differs(operation, left, right);
    }
    printf("{\"directed\":%u,\"seeded\":10000,\"mismatches\":%u}\n", directed, mismatches);
    return 0;
}
