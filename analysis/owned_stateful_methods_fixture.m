// Owned static-analysis oracle. Compile only; never execute or instantiate.
typedef struct {
    long day;
    unsigned long weight;
    unsigned int flags;
    unsigned int reserved;
} OwnedRecord;
typedef _Bool (*OwnedPredicate)(const OwnedRecord *);
__attribute__((objc_root_class))
@interface OwnedStatefulMethods {
    unsigned long _lastResult;
}
- (unsigned long)count:(const OwnedRecord *)records length:(unsigned long)count lower:(long)lower upper:(long)upper;
- (unsigned long)mark:(OwnedRecord *)records length:(unsigned long)count lower:(long)lower upper:(long)upper;
- (unsigned long)accepted:(const OwnedRecord *)records length:(unsigned long)count predicate:(OwnedPredicate)predicate;
- (void)boundary;
@end
@implementation OwnedStatefulMethods
- (unsigned long)count:(const OwnedRecord *)records length:(unsigned long)count lower:(long)lower upper:(long)upper {
    if (!records || count > 64) return 0;
    unsigned long total = 0;
    for (unsigned long i = 0; i < count; ++i) {
        if ((records[i].flags & 1) && records[i].day >= lower && records[i].day <= upper) ++total;
    }
    _lastResult = total;
    return total;
}
- (unsigned long)mark:(OwnedRecord *)records length:(unsigned long)count lower:(long)lower upper:(long)upper {
    if (!records || count > 64) return 0;
    unsigned long total = 0;
    for (unsigned long i = 0; i < count; ++i) {
        if ((records[i].flags & 1) && records[i].day >= lower && records[i].day <= upper) {
            records[i].flags |= 2;
            total += records[i].weight;
        }
    }
    _lastResult = total;
    return total;
}
- (unsigned long)accepted:(const OwnedRecord *)records length:(unsigned long)count predicate:(OwnedPredicate)predicate {
    if (!records || count > 64 || !predicate) return 0;
    unsigned long total = 0;
    for (unsigned long i = 0; i < count; ++i) if (predicate(&records[i])) ++total;
    _lastResult = total;
    return total;
}
- (void)boundary {}
@end
