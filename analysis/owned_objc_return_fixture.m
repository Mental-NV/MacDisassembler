// Owned compile-only return-channel oracle. Never execute/instantiate.
@protocol OwnedReturnTarget
- (long)ownedInteger;
- (double)ownedFloat;
@end
__attribute__((objc_root_class))
@interface OwnedReturnChannels
- (long)forwardInteger:(id<OwnedReturnTarget>)target;
- (void)discardInteger:(id<OwnedReturnTarget>)target;
- (long)zeroAfterInteger:(id<OwnedReturnTarget>)target;
- (double)forwardFloat:(id<OwnedReturnTarget>)target;
- (void)boundary;
@end
@implementation OwnedReturnChannels
- (long)forwardInteger:(id<OwnedReturnTarget>)target { return [target ownedInteger]; }
- (void)discardInteger:(id<OwnedReturnTarget>)target { [target ownedInteger]; }
- (long)zeroAfterInteger:(id<OwnedReturnTarget>)target { [target ownedInteger]; return 0; }
- (double)forwardFloat:(id<OwnedReturnTarget>)target { return [target ownedFloat]; }
- (void)boundary {}
@end
