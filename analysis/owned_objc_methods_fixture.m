// Owned source oracle. Compile-only: do not execute or instantiate this class.
@protocol OwnedValue
- (long)ownedValue;
@end
__attribute__((objc_root_class))
@interface OwnedCalendarMethods
- (_Bool)contains:(long)day lower:(long)lower upper:(long)upper;
- (long)clamp:(long)day limit:(long)limit;
- (id)select:(id)primary fallback:(id)fallback enabled:(_Bool)enabled;
- (long)forward:(id<OwnedValue>)target;
- (void)boundary;
@end
@implementation OwnedCalendarMethods
- (_Bool)contains:(long)day lower:(long)lower upper:(long)upper {
    return day >= lower && day <= upper;
}
- (long)clamp:(long)day limit:(long)limit {
    if (limit <= 0) return -1;
    if (day < 0) return 0;
    if (day >= limit) return limit - 1;
    return day;
}
- (id)select:(id)primary fallback:(id)fallback enabled:(_Bool)enabled {
    return enabled && primary ? primary : fallback;
}
- (long)forward:(id<OwnedValue>)target {
    return [target ownedValue];
}
- (void)boundary {}
@end
