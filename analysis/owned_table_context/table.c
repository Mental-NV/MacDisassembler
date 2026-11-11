/* Owned fixture data, not a third-party application or behavior oracle. */
#include <stdint.h>

__attribute__((visibility("hidden")))
const int64_t owned_membership_values[7] = {
    INT64_C(-17), INT64_C(0), INT64_C(4), INT64_C(9),
    INT64_C(15), INT64_C(23), INT64_C(-31)
};
_Static_assert(sizeof(owned_membership_values) == 56, "Exact owned table width");
