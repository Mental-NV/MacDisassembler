/* Owned register-parameter call chain and indirect-only control. */
#include <stdint.h>

#define NOINLINE __attribute__((noinline))

typedef struct {
    uint64_t word;
    uint64_t tag;
} ledger_t;

static NOINLINE void stamp(ledger_t *ledger, uint32_t delta) {
    ledger->tag = (uint64_t)delta * 3 + 7;
}

static NOINLINE uint64_t fold(ledger_t *ledger, uint32_t delta) {
    stamp(ledger, delta);
    return ledger->tag ^ (ledger->word >> 3);
}

NOINLINE uint64_t heldout_observer(ledger_t *ledger, uint32_t delta) {
    ledger->word ^= (uint64_t)delta;
    return fold(ledger, delta);
}

typedef uint64_t (*transform_t)(ledger_t *, uint32_t);

NOINLINE uint64_t heldout_control(ledger_t *ledger, uint32_t delta, transform_t transform) {
    return transform(ledger, delta);
}

#ifdef HELDOUT_LINK_IMAGE
static volatile uint64_t observed;
static transform_t volatile selected = fold;

int main(int argc, char **argv) {
    ledger_t ledger = {(uintptr_t)argv, (uint32_t)argc};
    observed = heldout_observer(&ledger, (uint32_t)argc);
    observed = heldout_control(&ledger, (uint32_t)argc, selected);
    return 0;
}
#endif
