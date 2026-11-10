#import <Foundation/Foundation.h>
#import <objc/message.h>
#include <stdio.h>

extern int64_t owned_calendar_day_seconds(int64_t localMidnight, int64_t transition,
                                          int64_t beforeOffset, int64_t afterOffset);

@interface OwnedCalendarController : NSObject
- (int64_t)calendarDayDuration:(int64_t)localMidnight;
@end

@implementation OwnedCalendarController
- (int64_t)calendarDayDuration:(int64_t)localMidnight {
    return owned_calendar_day_seconds(localMidnight, 1772953200, -18000, -14400);
}
@end

typedef int64_t (*CalendarDispatch)(id receiver, SEL selector, int64_t localMidnight);

__attribute__((noinline))
int64_t owned_calendar_route(id receiver, int64_t localMidnight, CalendarDispatch dispatch) {
    return dispatch(receiver, @selector(calendarDayDuration:), localMidnight);
}

int main(void) {
    @autoreleasepool {
        OwnedCalendarController *controller = [OwnedCalendarController new];
        puts("OwnedCalendar.RangePreferences");
        const int64_t localMidnights[] = {1772841600, 1772928000, 1773014400};
        for (unsigned i = 0; i < sizeof localMidnights / sizeof localMidnights[0]; i++) {
            printf("%lld\n", (long long)owned_calendar_route(
                controller, localMidnights[i], (CalendarDispatch)objc_msgSend));
        }
    }
    return 0;
}
