// Independently authored, project-owned static resource-first investigation fixture.
// Build each architecture separately on macOS; do not launch the executable:
//   xcrun clang -arch ARCH -mmacosx-version-min=13.0 -O1 \
//     -fno-objc-arc -fno-inline \
//     -framework AppKit -Wl,-fixup_chains ResourceFirstCalendar.m -o OUTPUT
// Compile ResourceFirstCalendarWiring.xib with xcrun ibtool --compile OUTPUT.nib INPUT.xib.
// The nib is evidence of declared connections, not a claim of runtime reachability.
#import <AppKit/AppKit.h>

@interface OwnedCalendarResourceController : NSObject {
    IBOutlet NSView *advancedRow;
    IBOutlet NSButton *advancedToggle;
    // Volatile makes the conditional write observable to the compiler, keeping
    // the compare/branch/store oracle independent of optimizer store folding.
    volatile NSInteger _configuredState;
}
- (void)awakeFromNib;
- (IBAction)changeAdvancedState:(NSButton *)sender;
@end

@implementation OwnedCalendarResourceController
- (void)awakeFromNib {
    [advancedRow setHidden:YES];
}

- (IBAction)changeAdvancedState:(NSButton *)sender {
    NSInteger requestedState = [sender state];
    if (requestedState != _configuredState) {
        _configuredState = requestedState;
    }
}
@end

// A caller-supplied target is deliberately unresolved. The selector is evidence
// of the requested operation, not proof of a unique runtime implementation.
typedef void (*OwnedCalendarResourceDispatch)(id receiver, SEL selector, id sender);

__attribute__((noinline, used))
void owned_calendar_resource_dispatch(id receiver, id sender,
                                      OwnedCalendarResourceDispatch dispatch) {
    dispatch(receiver, @selector(changeAdvancedState:), sender);
}

// Static-only fixture: no nib loading, NSApplication startup, or runtime oracle.
int main(void) {
    return 0;
}
