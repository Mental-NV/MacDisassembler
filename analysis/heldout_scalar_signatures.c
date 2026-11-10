/* Owned scalar-call observers and unrelated-call controls. */
#include <stdint.h>
#include <stdlib.h>

#define NOINLINE __attribute__((noinline))

#if defined(__x86_64__)
NOINLINE int heldout_tag(char value) {
    return value == 'b' || value == 'M' || value == '2';
}

NOINLINE int heldout_observer(char value) {
    if (!heldout_tag(value)) {
        return 207;
    }
    return 113;
}

NOINLINE unsigned char heldout_byte(char value) {
    return (unsigned char)value ^ 0x93U;
}

NOINLINE unsigned char heldout_control(char value) {
    return heldout_byte(value);
}
#elif defined(__arm64__)
NOINLINE int heldout_observer(char value) {
    return (unsigned char)value ^ 0xa7U;
}

NOINLINE __attribute__((no_stack_protector)) unsigned char heldout_control(char value) {
    if (value == 'z') {
        abort();
    }
    return (unsigned char)value + 11U;
}
#endif

#ifdef HELDOUT_LINK_IMAGE
static volatile int observed;

__attribute__((no_stack_protector))
int main(int argc, char **argv) {
    char value = (char)((unsigned)argc ^ (uintptr_t)argv);
    observed = heldout_observer(value);
    observed = heldout_control(value);
    return 0;
}
#endif
