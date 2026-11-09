// ui_layout.m — actual AppKit production-layout regression, without showing
// or activating windows, synthesizing input, or running NSApplication's loop.
// Build: xcrun clang -O0 -g -Wall -Wextra -Werror -fobjc-arc -Ifixture/src \
//   -framework Cocoa fixture/src/calc_core.c fixture/src/CalcController.m \
//   fixture/src/CalculatorFixtureAppDelegate.m fixture/tests/ui_layout.m \
//   -o build/ui-layout-review-tests/ui_layout
#import <Cocoa/Cocoa.h>
#import "CalculatorFixtureAppDelegate.h"
#import "CalcController.h"
#include <math.h>

// Test-only declaration of the same constructor invoked by app launch.
@interface CalculatorFixtureAppDelegate (LayoutTests)
- (void)buildInterface;
@end

static int g_pass = 0, g_fail = 0;
#define CHECK(condition) do { \
    if (condition) { g_pass++; } \
    else { g_fail++; printf("FAIL line %d: %s\n", __LINE__, #condition); } \
} while (0)

static BOOL near(CGFloat a, CGFloat b) { return fabs(a - b) < 1; }

static void collectButtons(NSView *view, NSMutableArray<NSButton *> *buttons) {
    for (NSView *child in view.subviews) {
        if ([child isKindOfClass:NSButton.class]) {
            [buttons addObject:(NSButton *)child];
        } else {
            collectButtons(child, buttons);
        }
    }
}

static NSButton *buttonNamed(NSArray<NSButton *> *buttons, NSString *title) {
    for (NSButton *button in buttons) {
        if ([button.title isEqualToString:title]) return button;
    }
    return nil;
}

static void press(NSArray<NSButton *> *buttons, NSString *title) {
    NSButton *button = buttonNamed(buttons, title);
    CHECK(button != nil && button.target != nil && button.action != NULL);
    // Invoke the real NSControl target/action route without a mouse event or
    // performClick's highlight animation/event-loop work.
    CHECK([button sendAction:button.action to:button.target]);
}

static void digits(CalcController *controller, const char *text) {
    for (; *text; text++) [controller pressDigit:*text - '0'];
}

static void checkTextFits(NSTextField *field, NSString *expected) {
    CHECK([field.stringValue isEqualToString:expected]);
    CHECK(field.window != nil && !field.hiddenOrHasHiddenAncestor);
    NSCell *cell = field.cell;
    NSRect drawing = [cell drawingRectForBounds:field.bounds];
    NSRect text = [cell titleRectForBounds:field.bounds];
    NSSize size = [field.stringValue sizeWithAttributes:@{NSFontAttributeName:field.font}];
    // Unlike checking AXValue or stringValue alone, compare full glyph extent
    // with the actual production cell's available drawing and title regions.
    CHECK(ceil(size.width) <= NSWidth(drawing));
    CHECK(ceil(size.width) <= NSWidth(text));
    CHECK(ceil(size.height) <= NSHeight(drawing));
    CHECK(ceil(size.height) <= NSHeight(text));
    CHECK(NSWidth(field.bounds) >= cell.cellSize.width);
}

static NSRect inRoot(NSView *view, NSView *root) {
    return [view convertRect:view.bounds toView:root];
}

static void checkGeometry(CalculatorFixtureAppDelegate *delegate,
                          NSArray<NSButton *> *buttons) {
    NSView *root = delegate.window.contentView;
    NSTextField *display = delegate.controller.displayField;
    NSTextField *error = delegate.controller.errorField;
    NSTextView *history = delegate.controller.historyView;
    NSScrollView *scroll = history.enclosingScrollView;
    NSRect displayFrame = inRoot(display, root), errorFrame = inRoot(error, root);
    NSRect historyFrame = inRoot(scroll, root);
    CHECK(NSContainsRect(root.bounds, displayFrame));
    CHECK(NSContainsRect(root.bounds, errorFrame));
    CHECK(NSContainsRect(root.bounds, historyFrame));
    CHECK(near(NSMinX(displayFrame), 20) && near(NSMaxX(displayFrame), NSWidth(root.bounds) - 20));
    CHECK(near(NSWidth(errorFrame), NSWidth(displayFrame)));
    CHECK(near(NSWidth(historyFrame), NSWidth(displayFrame)));
    CHECK(near(NSMaxY(displayFrame), NSHeight(root.bounds) - 30));
    CHECK(NSMaxY(errorFrame) < NSMinY(displayFrame));
    CHECK(NSMaxY(historyFrame) < NSMinY(errorFrame));
    CHECK(near(NSMinY(historyFrame), 264));
    CHECK(history.textContainer.widthTracksTextView && !history.horizontallyResizable);
    CHECK(history.frame.size.width <= scroll.contentView.bounds.size.width + 1);
    CHECK(history.textContainer.containerSize.width <= history.bounds.size.width + 1);
    CHECK(buttons.count == 17);
    for (NSUInteger i = 0; i < buttons.count; i++) {
        NSButton *button = buttons[i];
        NSRect frame = inRoot(button, root);
        CHECK(NSContainsRect(root.bounds, frame) && !button.hiddenOrHasHiddenAncestor);
        CHECK(NSMaxY(frame) < NSMinY(historyFrame));
        CHECK(NSWidth(frame) >= 65 && NSHeight(frame) >= 44);
        CHECK(button.target == delegate && button.action == NSSelectorFromString(@"buttonPressed:"));
        for (NSUInteger j = i + 1; j < buttons.count; j++) {
            CHECK(!NSIntersectsRect(frame, inRoot(buttons[j], root)));
        }
    }
    CHECK(near(NSMinY(inRoot(buttonNamed(buttons, @"0"), root)), 8));
    CHECK(!delegate.window.visible);
}

static void checkValues(CalculatorFixtureAppDelegate *delegate,
                        NSArray<NSButton *> *buttons) {
    CalcController *controller = delegate.controller;
    [controller pressClear]; digits(controller, "9223372036854775807");
    checkTextFits(controller.displayField, @"9223372036854775807");
    [controller pressClear]; [controller pressNegate]; digits(controller, "9223372036854775808");
    checkTextFits(controller.displayField, @"-9223372036854775808");
    [controller pressNegate];
    checkTextFits(controller.displayField, @"-9223372036854775808");
    checkTextFits(controller.errorField, @"Error: overflow");

    press(buttons, @"C"); press(buttons, @"2"); press(buttons, @"+");
    press(buttons, @"3"); press(buttons, @"×"); press(buttons, @"4"); press(buttons, @"=");
    checkTextFits(controller.displayField, @"20");
    CHECK([controller.errorField.stringValue isEqualToString:@""]);
    NSTextView *history = controller.historyView;
    CHECK([history.string isEqualToString:@"2 + 3 = 5\n5 * 4 = 20\n"]);
    [history.layoutManager ensureLayoutForTextContainer:history.textContainer];
    NSRect used = [history.layoutManager usedRectForTextContainer:history.textContainer];
    used = NSOffsetRect(used, history.textContainerOrigin.x, history.textContainerOrigin.y);
    CHECK(NSWidth(used) > 0 && NSHeight(used) > 0);
    CHECK(NSContainsRect(history.visibleRect, used));
}

int main(void) {
    @autoreleasepool {
        NSApplication *app = NSApplication.sharedApplication;
        // An unbundled command-line process can already be prohibited, in
        // which case AppKit may report no transition. Check the actual state.
        [app setActivationPolicy:NSApplicationActivationPolicyProhibited];
        CHECK(app.activationPolicy == NSApplicationActivationPolicyProhibited);
        CalculatorFixtureAppDelegate *delegate = [[CalculatorFixtureAppDelegate alloc] init];
        app.delegate = delegate;
        [delegate buildInterface];
        NSWindow *window = delegate.window;
        CHECK(window != nil && delegate.controller != nil && !window.visible);
        CHECK([delegate applicationShouldTerminateAfterLastWindowClosed:app]);
        CHECK([window.title isEqualToString:@"CalculatorFixture"]);
        NSMenu *applicationMenu = app.mainMenu.itemArray.firstObject.submenu;
        CHECK(applicationMenu != nil && [applicationMenu.title isEqualToString:window.title]);
        NSMenuItem *quit = applicationMenu.itemArray.firstObject;
        CHECK([quit.title isEqualToString:[@"Quit " stringByAppendingString:window.title]]);
        CHECK(quit.action == @selector(terminate:) && quit.target == app);
        CHECK([quit.keyEquivalent isEqualToString:@"q"]);
        CHECK(quit.keyEquivalentModifierMask == NSEventModifierFlagCommand);
        // Inspect routing only; invoking terminate: would end this test early.
        CHECK([app targetForAction:quit.action to:quit.target from:quit] == app);

        NSMutableArray<NSButton *> *buttons = [NSMutableArray array];
        collectButtons(window.contentView, buttons);
        NSSize minimum = window.contentMinSize;
        CHECK(minimum.width >= 420 && minimum.height >= 480);
        CHECK(NSEqualSizes(window.contentView.bounds.size, minimum));
        checkGeometry(delegate, buttons);
        checkValues(delegate, buttons);

        const NSSize sizes[] = {
            {minimum.width + 280, minimum.height},
            {minimum.width, minimum.height + 220},
            {minimum.width + 280, minimum.height + 220},
            {minimum.width, minimum.height},
        };
        for (NSUInteger i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
            [window setContentSize:sizes[i]];
            [window.contentView layoutSubtreeIfNeeded];
            CHECK(NSEqualSizes(window.contentView.bounds.size, sizes[i]));
            checkGeometry(delegate, buttons);
            checkValues(delegate, buttons);
        }
        // Construction is idempotent and must not replace or present a window.
        [delegate buildInterface];
        CHECK(delegate.window == window && !window.visible);
        CHECK(!app.active);
        printf("ui_layout: pass=%d fail=%d minimum=%.0fx%.0f sizes=5\n",
               g_pass, g_fail, minimum.width, minimum.height);
        // Process exit reclaims only this invisible test window. No app.run,
        // window close, activation, external app lookup, or termination action.
        return g_fail == 0 ? 0 : 1;
    }
}
