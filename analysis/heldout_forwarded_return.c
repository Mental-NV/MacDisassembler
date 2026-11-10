/* Owned word-return wrappers with full-width, ignored, and byte-only observers. */
#include <stdint.h>

#define WRAPPER __attribute__((noinline, disable_tail_calls))

typedef struct {
    uint64_t word;
    uint64_t tag;
} ledger_t;

static __attribute__((noinline)) uint64_t mix(ledger_t *ledger, uint32_t delta) {
    ledger->word += (uint64_t)delta * 9U;
    ledger->tag ^= ledger->word >> 11;
    return ledger->tag + (ledger->word << 2);
}

WRAPPER uint64_t heldout_observer(ledger_t *ledger, uint32_t delta) {
    return mix(ledger, delta);
}

WRAPPER uint64_t heldout_discarded(ledger_t *ledger, uint32_t delta) {
    return mix(ledger, delta ^ 0x700012A5U);
}

WRAPPER uint64_t heldout_byte(ledger_t *ledger, uint32_t delta) {
    return mix(ledger, delta ^ 0x18034DB2U);
}

#ifdef HELDOUT_LINK_IMAGE
static volatile uint64_t observed_word;
static volatile uint8_t observed_byte;

int main(int argc, char **argv) {
    ledger_t ledger = {(uintptr_t)argv, (uint32_t)argc};
    observed_word = heldout_observer(&ledger, (uint32_t)argc);
    (void)heldout_discarded(&ledger, (uint32_t)argc);
    observed_byte = (uint8_t)heldout_byte(&ledger, (uint32_t)argc);
    return 0;
}
#endif
