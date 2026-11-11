/* Compile separately from table.c, without LTO. No main or executable harness. */
#include <stdint.h>

__attribute__((visibility("hidden")))
extern const int64_t owned_membership_values[7];

__attribute__((noinline, used, visibility("default")))
int32_t owned_static_membership(int64_t value)
{
    const int64_t remainder = value % INT64_C(19);
    for (uint32_t index = 0; index < UINT32_C(7); ++index) {
        if (owned_membership_values[index] == remainder) {
            return INT32_C(1);
        }
    }
    return INT32_C(0);
}

/* Requires an ordinary readable caller-supplied array; no wrapper pins its target. */
__attribute__((noinline, used, visibility("default")))
int32_t owned_pointer_membership(int64_t value, const int64_t *values)
{
    const int64_t remainder = value % INT64_C(19);
    for (uint32_t index = 0; index < UINT32_C(7); ++index) {
        if (values[index] == remainder) {
            return INT32_C(1);
        }
    }
    return INT32_C(0);
}
