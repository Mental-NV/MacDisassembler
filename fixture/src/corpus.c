/* corpus.c — extended fixtures for the dedicated corpus target. */
#include "corpus.h"

calc_result_t corpus_fact_checked(int64_t n) {
    calc_result_t r;
    if (n < 0) {
        r.value = 0;
        r.status = CALC_ERR_INVALID;
        return r;
    }
    if (n <= 1) {
        r.value = 1;
        r.status = CALC_OK;
        return r;
    }
    if (n > 20) {
        r.value = 0;
        r.status = CALC_ERR_OVERFLOW;
        return r;
    }
    {
        calc_result_t sub = corpus_fact_checked(n - 1);
        if (sub.status != CALC_OK) {
            return sub;
        }
        return calc_mul(sub.value, n);
    }
}

calc_result_t corpus_lut_demo(int opcode, int64_t a, int64_t b) {
    calc_result_t r;
    static const int64_t kBias[8] = {0, 1, -1, 10, -10, 100, -100, 1000};
    if (opcode < 0 || opcode > 7) {
        r.value = 0;
        r.status = CALC_ERR_INVALID;
        return r;
    }
    switch (opcode) {
    case 0:
        return calc_add(a, b);
    case 1:
        return calc_sub(a, b);
    case 2:
        return calc_mul(a, b);
    case 3:
        return calc_div(a, b);
    case 4:
        return calc_pow_checked(a, b);
    case 5:
        return calc_add(a, kBias[opcode]);
    case 6:
        return calc_sub(a, kBias[opcode]);
    default: {
        calc_result_t m = calc_mul(a, b);
        if (m.status != CALC_OK) {
            return m;
        }
        return calc_add(m.value, kBias[opcode]);
    }
    }
}

calc_status_t corpus_stats_over_points(const corpus_point_t *pts, size_t n,
                                       corpus_stats_t *out) {
    size_t i;
    int64_t sum = 0;
    int64_t mn = 0;
    int64_t mx = 0;
    if (pts == NULL || out == NULL || n == 0) {
        return CALC_ERR_INVALID;
    }
    for (i = 0; i < n; i++) {
        int64_t v;
        int64_t s1;
        if (__builtin_add_overflow(pts[i].x, pts[i].y, &v)) {
            return CALC_ERR_OVERFLOW;
        }
        if (__builtin_add_overflow(sum, v, &s1)) {
            return CALC_ERR_OVERFLOW;
        }
        sum = s1;
        if (i == 0) {
            mn = v;
            mx = v;
        } else {
            if (calc_compare_s64(v, mn) < 0) {
                mn = v;
            }
            if (calc_compare_s64(v, mx) > 0) {
                mx = v;
            }
        }
    }
    out->sum = sum;
    out->min = mn;
    out->max = mx;
    out->count = n;
    return CALC_OK;
}

static calc_result_t corpus_add_helper(int64_t a, int64_t b) {
    return calc_add(a, b);
}

static calc_result_t corpus_sub_helper(int64_t a, int64_t b) {
    return calc_sub(a, b);
}

calc_result_t corpus_chain_demo(int64_t a, int64_t b, int64_t c, int64_t d) {
    calc_result_t s = corpus_add_helper(a, b);
    calc_result_t t = corpus_sub_helper(c, d);
    if (s.status != CALC_OK) {
        return s;
    }
    if (t.status != CALC_OK) {
        return t;
    }
    return calc_mul(s.value, t.value);
}
