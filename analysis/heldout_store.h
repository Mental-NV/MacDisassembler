#ifndef MACSCOPE_HELDOUT_STORE_H
#define MACSCOPE_HELDOUT_STORE_H

#include <stdint.h>

typedef struct {
    uint64_t word;
    uint32_t flags;
} store_result_t;

store_result_t heldout_packet(uint64_t *buffer, uint64_t value);
store_result_t heldout_checked(uint64_t *buffer, uint64_t value);

#endif
