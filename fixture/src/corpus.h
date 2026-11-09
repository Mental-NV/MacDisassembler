/*
 * corpus.h — extended analysis fixtures linked into the dedicated corpus
 * target only (not the calculator app). Exercises recursion, lookup
 * tables, and struct/array traversal for the baseline.
 */
#ifndef CORPUS_H
#define CORPUS_H

#include "calc_core.h"

typedef struct corpus_point {
    int64_t x;
    int64_t y;
} corpus_point_t;

typedef struct corpus_stats {
    int64_t sum;
    int64_t min;
    int64_t max;
    size_t count;
} corpus_stats_t;

/* Checked factorial via recursion: n > 20 -> OVERFLOW, n < 0 -> INVALID. */
calc_result_t corpus_fact_checked(int64_t n);

/* Lookup-table demo: maps small opcodes 0..7 to checked results. */
calc_result_t corpus_lut_demo(int opcode, int64_t a, int64_t b);

/* Struct/array traversal: checked stats over an array of points. */
calc_status_t corpus_stats_over_points(const corpus_point_t *pts, size_t n,
                                       corpus_stats_t *out);

/* Helper-call chain: (a+b)*(c-d) fully checked through helper calls. */
calc_result_t corpus_chain_demo(int64_t a, int64_t b, int64_t c, int64_t d);

#endif /* CORPUS_H */
