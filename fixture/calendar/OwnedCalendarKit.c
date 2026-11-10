#include <stdint.h>

// The fixture models one forward offset change away from local midnight.
__attribute__((noinline))
int64_t owned_calendar_midnight(int64_t localMidnight, int64_t transition,
                                int64_t beforeOffset, int64_t afterOffset) {
    int64_t before = localMidnight - beforeOffset;
    return before < transition ? before : localMidnight - afterOffset;
}

__attribute__((noinline))
int64_t owned_calendar_day_seconds(int64_t localMidnight, int64_t transition,
                                   int64_t beforeOffset, int64_t afterOffset) {
    int64_t start = owned_calendar_midnight(localMidnight, transition, beforeOffset, afterOffset);
    int64_t end = owned_calendar_midnight(localMidnight + 86400, transition, beforeOffset, afterOffset);
    return end - start;
}
