// Owned compile-only Objective-C Darwin register-role fixture. No SDK headers.
volatile unsigned long long owned_abi_words[8];
__attribute__((objc_root_class))
@interface OwnedABI
- (void)capture:(id)object cls:(Class)cls selector:(SEL)selector text:(char *)text;
+ (void)classCapture:(id)object;
- (long long)signedWord:(long long)value;
- (unsigned long long)unsignedWord:(unsigned long long)value;
- (void *)pointer:(void *)value;
- (id)object:(id)value;
- (Class)classObject:(Class)value;
- (SEL)selector:(SEL)value;
- (char *)text:(char *)value;
#if defined(__arm64__)
- (void)armRegisters:(id)object cls:(Class)cls selector:(SEL)selector text:(char *)text signedWord:(long long)s unsignedWord:(unsigned long long)u;
#endif
@end
@implementation OwnedABI
- (void)capture:(id)object cls:(Class)cls selector:(SEL)selector text:(char *)text {
    owned_abi_words[0] = (unsigned long long)self;
    owned_abi_words[1] = (unsigned long long)_cmd;
    owned_abi_words[2] = (unsigned long long)object;
    owned_abi_words[3] = (unsigned long long)cls;
    owned_abi_words[4] = (unsigned long long)selector;
    owned_abi_words[5] = (unsigned long long)text;
}
+ (void)classCapture:(id)object {
    owned_abi_words[0] = (unsigned long long)self;
    owned_abi_words[1] = (unsigned long long)_cmd;
    owned_abi_words[2] = (unsigned long long)object;
}
- (long long)signedWord:(long long)value { return value; }
- (unsigned long long)unsignedWord:(unsigned long long)value { return value; }
- (void *)pointer:(void *)value { return value; }
- (id)object:(id)value { return value; }
- (Class)classObject:(Class)value { return value; }
- (SEL)selector:(SEL)value { return value; }
- (char *)text:(char *)value { return value; }
#if defined(__arm64__)
- (void)armRegisters:(id)object cls:(Class)cls selector:(SEL)selector text:(char *)text signedWord:(long long)s unsignedWord:(unsigned long long)u {
    owned_abi_words[0] = (unsigned long long)self;
    owned_abi_words[1] = (unsigned long long)_cmd;
    owned_abi_words[2] = (unsigned long long)object;
    owned_abi_words[3] = (unsigned long long)cls;
    owned_abi_words[4] = (unsigned long long)selector;
    owned_abi_words[5] = (unsigned long long)text;
    owned_abi_words[6] = (unsigned long long)s;
    owned_abi_words[7] = u;
}
#endif
@end
const char *owned_long_encoding = @encode(long);
const char *owned_ulong_encoding = @encode(unsigned long);
const char *owned_llong_encoding = @encode(long long);
const char *owned_ullong_encoding = @encode(unsigned long long);
const unsigned long owned_long_size = sizeof(long);
const unsigned long owned_pointer_size = sizeof(void *);
