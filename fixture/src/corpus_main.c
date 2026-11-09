/* corpus_main.c — reference-output harness for the corpus target.
 * Prints deterministic expected results for every core/corpus routine so
 * the blind Ghidra evaluation has a behavioral oracle. No analysis input;
 * this program IS the ground-truth generator (evaluator side).
 */
#include <inttypes.h>
#include <stdio.h>
#include "calc_core.h"
#include "corpus.h"

static void show(const char *name, calc_result_t r) {
    printf("%-28s value=%" PRId64 " status=%d\n", name, r.value, (int)r.status);
}

int main(void) {
    calc_state_t st;
    calc_history_t h;
    corpus_stats_t stats;
    corpus_point_t pts[4] = {{1, 2}, {3, 4}, {-5, 5}, {10, -3}};
    char buf[32];
    size_t i;

    show("add/max+1", calc_add(INT64_MAX, 1));
    show("sub/min-1", calc_sub(INT64_MIN, 1));
    show("mul/max*2", calc_mul(INT64_MAX, 2));
    show("div/-7/2", calc_div(-7, 2));
    show("div/7/-2", calc_div(7, -2));
    show("div/0", calc_div(1, 0));
    show("div/min/-1", calc_div(INT64_MIN, -1));
    show("neg/min", calc_negate(INT64_MIN));
    show("abs/min", calc_abs_checked(INT64_MIN));
    show("pow/2^62", calc_pow_checked(2, 62));
    show("pow/2^63", calc_pow_checked(2, 63));
    show("pow/neg", calc_pow_checked(2, -1));
    show("op/?", calc_apply_op('?', 1, 2));
    show("dispatch/*", calc_dispatch_table('*', 6, 7));
    show("parse/max", calc_parse_digits("9223372036854775807", 19));
    show("parse/min", calc_parse_digits("-9223372036854775808", 20));
    show("parse/overflow", calc_parse_digits("9223372036854775808", 19));
    show("parse/bad", calc_parse_digits("12a", 3));
    printf("format/min status=%d text=",
           (int)calc_format_int64(INT64_MIN, buf, sizeof(buf)));
    printf("%s\n", buf);
    show("append/overflow", calc_digit_append(INT64_MAX, 9));
    show("fact/20", corpus_fact_checked(20));
    show("fact/21", corpus_fact_checked(21));
    show("fact/-1", corpus_fact_checked(-1));
    show("lut/3", corpus_lut_demo(3, 7, 2));
    show("lut/7", corpus_lut_demo(7, 6, 7));
    show("chain", corpus_chain_demo(2, 3, 10, 4));
    printf("stats status=%d sum=%" PRId64 " min=%" PRId64 " max=%" PRId64
           " n=%zu\n",
           (int)corpus_stats_over_points(pts, 4, &stats), stats.sum, stats.min,
           stats.max, stats.count);
    printf("cmp_s=%d cmp_u=%d\n", calc_compare_s64(-1, 1),
           calc_compare_u64(1, 2));

    /* Scripted engine journeys (reference transcript). */
    calc_state_init(&st);
    calc_history_init(&h);
    /* 2 + 3 = =  -> 5, 8 */
    calc_engine_input_digit(&st, 2);
    calc_engine_input_op(&st, '+');
    calc_engine_input_digit(&st, 3);
    calc_engine_equals(&st);
    printf("journey/2+3= display=%" PRId64 "\n", st.display);
    calc_engine_equals(&st);
    printf("journey/repeat-= display=%" PRId64 "\n", st.display);
    /* 3 + * 4 = -> 12 */
    calc_engine_clear(&st);
    calc_engine_input_digit(&st, 3);
    calc_engine_input_op(&st, '+');
    calc_engine_input_op(&st, '*');
    calc_engine_input_digit(&st, 4);
    calc_engine_equals(&st);
    printf("journey/3+*4= display=%" PRId64 "\n", st.display);
    /* 1/0 latches, C recovers */
    calc_engine_clear(&st);
    calc_engine_input_digit(&st, 1);
    calc_engine_input_op(&st, '/');
    calc_engine_input_digit(&st, 0);
    calc_engine_equals(&st);
    printf("journey/1/0 latched=%d err=%d display=%" PRId64 "\n",
           st.error_latched, (int)st.error, st.display);
    calc_engine_input_digit(&st, 5);
    printf("journey/latched-ignores-digit display=%" PRId64 "\n", st.display);
    calc_engine_clear(&st);
    calc_engine_input_digit(&st, 5);
    printf("journey/after-clear display=%" PRId64 "\n", st.display);
    (void)i;
    return 0;
}
