// Owned compile-only fixture. No SDK/framework or executable is needed.
// clang -x objective-c -fblocks -S owned_objc_encoding_fixture.m -o encodings.s
@protocol OwnedProtocol
@end
__attribute__((objc_root_class))
@interface OwnedRoot
@end
@implementation OwnedRoot
@end
struct Mixed {
    id object;
    int count;
    OwnedRoot *typed;
    id<OwnedProtocol> proto;
    OwnedRoot<OwnedProtocol> *typedProto;
    void (^block)(void);
};
union MixedUnion { id object; int count; OwnedRoot *typed; };
struct Pair { id first; id second; };
@interface OwnedFixture : OwnedRoot {
    struct Mixed _mixed;
    union MixedUnion _mixedUnion;
    struct Pair _pair;
}
- (void)accept:(id)value;
- (void)foo:(int)a :(int)b;
- (void):(int)a;
- (void)café:(int)a;
@end
@implementation OwnedFixture
- (void)accept:(id)value { (void)value; }
- (void)foo:(int)a :(int)b { (void)a; (void)b; }
- (void):(int)a { (void)a; }
- (void)café:(int)a { (void)a; }
@end
const char *enc_char = @encode(signed char);
const char *enc_bool = @encode(_Bool);
const char *enc_block = @encode(void (^)(void));
const char *enc_named = @encode(OwnedRoot *);
const char *enc_protocol = @encode(id<OwnedProtocol>);
const char *enc_named_protocol = @encode(OwnedRoot<OwnedProtocol> *);
const char *enc_pointer_array = @encode(int (*)[3]);
const char *enc_array_pointer = @encode(int *[3]);
const char *enc_mixed = @encode(struct Mixed);
const char *enc_union = @encode(union MixedUnion);
const char *enc_pair = @encode(struct Pair);
