#include <stdint.h>

typedef struct OwnedPair { uint64_t left; uint64_t right; } OwnedPair;
typedef struct OwnedWide { uint64_t left; uint64_t middle; uint64_t right; } OwnedWide;
typedef struct OwnedPadded { uint8_t tag; uint64_t total; } OwnedPadded;
typedef struct OwnedFloats { float first; float second; } OwnedFloats;

__attribute__((noinline)) OwnedPair owned_pair(OwnedPair input, uint64_t bias) {
    return (OwnedPair){input.right + bias, input.left ^ bias};
}

__attribute__((noinline)) OwnedWide owned_wide(uint64_t input) {
    return (OwnedWide){input, input + 17, input + 41};
}

__attribute__((noinline)) uint64_t owned_padded(const OwnedPadded *input) {
    return input->tag + input->total;
}

__attribute__((noinline)) OwnedFloats owned_floats(OwnedFloats input) {
    return (OwnedFloats){input.second + 2.0f, input.first - 1.0f};
}
