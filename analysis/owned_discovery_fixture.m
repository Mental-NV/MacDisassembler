/* Owned metadata-only fixture. Validation never executes this dylib.
 * The linker moves __objc_classlist to __DATA, after the unrelated pointers.
 * These are real relocations emitted by clang, not patched Mach-O headers. */
__attribute__((used,section("__DATA_CONST,__const")))
const void * const owned_unrelated_fixups[12032] = {
    [0 ... 12031] = &owned_unrelated_fixups
};

__attribute__((objc_root_class))
@interface OwnedDiscoveryProbe
- (int)ownedProbe;
+ (int)ownedClassProbe;
@end
@implementation OwnedDiscoveryProbe
- (int)ownedProbe { return 37; }
+ (int)ownedClassProbe { return 41; }
@end
