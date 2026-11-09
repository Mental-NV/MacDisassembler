/* Evaluator-only variation for bounded computed-jump coverage. */
#include <stdint.h>

#define RETAIN __attribute__((noinline, used))

static RETAIN uint32_t combine_add(uint32_t a, uint32_t b) { return a + b + 0x517u; }
static RETAIN uint32_t combine_xor(uint32_t a, uint32_t b) { return (a ^ b) + 0x192u; }
static RETAIN uint32_t combine_mul(uint32_t a, uint32_t b) { return a * (b | 1u); }
static RETAIN uint32_t combine_sub(uint32_t a, uint32_t b) { return b - a; }
static RETAIN uint32_t combine_max(uint32_t a, uint32_t b) { return a > b ? a : b; }
static RETAIN uint32_t combine_rot(uint32_t a, uint32_t b) { return ((a << 7) | (a >> 25)) ^ b; }

static RETAIN uint32_t heldout_dispatch(uint32_t operation, uint32_t left, uint32_t right)
{
    switch (operation) {
    case 17: return combine_xor(left, right);
    case 18: return combine_rot(left, right);
    case 20: return combine_add(left, right);
    case 21: return combine_max(left, right);
    case 23: return combine_mul(left, right);
    case 24: return combine_sub(left, right);
    default: return 0xf4a726b1u;
    }
}

int main(int argc, char **argv)
{
    uint32_t input = (uint32_t)(uintptr_t)argv;
    return (int)(heldout_dispatch((uint32_t)argc, input, input >> 7) & 255u);
}
