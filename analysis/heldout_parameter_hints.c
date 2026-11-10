#include <stdbool.h>
#include <stdint.h>

static volatile uint32_t zero_value = 9;

__attribute__((noinline))
const uint32_t *owned_advance(const uint32_t *words, uint32_t offset) {
    return words + offset;
}

__attribute__((noinline))
uint32_t owned_stack(uint32_t a, uint32_t b, uint32_t c, uint32_t d,
                     uint32_t e, uint32_t f, uint32_t g, uint32_t h,
                     const uint32_t *words) {
    return a + b + c + d + e + f + g + h + words[0];
}

__attribute__((noinline))
uint32_t owned_zero(void) {
    return zero_value;
}

int main(int argc, char **argv) {
    (void)argv;
    uint32_t words[] = {11, 17};
    const uint32_t *word = owned_advance(words, (uint32_t)argc & 1);
    return (int)(owned_stack(1, 2, 3, 4, 5, 6, 7, 8, word) + owned_zero());
}
