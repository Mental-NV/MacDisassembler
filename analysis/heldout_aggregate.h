#ifndef MACSCOPE_HELDOUT_AGGREGATE_H
#define MACSCOPE_HELDOUT_AGGREGATE_H

#include <stdint.h>

typedef struct {
    uint64_t word;
    uint32_t flags;
} packet_t;

packet_t heldout_packet(uint64_t word, uint64_t salt);
packet_t heldout_checked(int64_t left, int64_t right);

#endif
