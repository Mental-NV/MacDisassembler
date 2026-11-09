// CalculatorFixtureAppDelegate.m — programmatic AppKit UI. Every button
// routes through CalcController press* methods (the same methods the
// headless UI-journey tests drive).
#import "CalculatorFixtureAppDelegate.h"
#import "CalcController.h"
#include <math.h>

@interface CalculatorFixtureAppDelegate ()
- (void)buildInterface;
@end

@implementation CalculatorFixtureAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    [self buildInterface];
    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
}

// Separate construction from presentation so layout tests use the actual
// production controls without showing or activating a window.
- (void)buildInterface {
    if (self.window != nil) return;
    self.controller = [[CalcController alloc] init];

    NSString *applicationName = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleDisplayName"];
    if (applicationName.length == 0) {
        applicationName = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleName"];
    }
    if (applicationName.length == 0) applicationName = @"CalculatorFixture";
    NSMenu *mainMenu = [[NSMenu alloc] initWithTitle:applicationName];
    NSMenuItem *applicationItem = [[NSMenuItem alloc] initWithTitle:applicationName
                                                           action:NULL keyEquivalent:@""];
    NSMenu *applicationMenu = [[NSMenu alloc] initWithTitle:applicationName];
    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:[@"Quit " stringByAppendingString:applicationName]
                                                   action:@selector(terminate:)
                                            keyEquivalent:@"q"];
    quitItem.keyEquivalentModifierMask = NSEventModifierFlagCommand;
    quitItem.target = NSApp;
    [applicationMenu addItem:quitItem];
    applicationItem.submenu = applicationMenu;
    [mainMenu addItem:applicationItem];
    NSApp.mainMenu = mainMenu;

    const CGFloat margin = 20, minimumHeight = 480;
    NSFont *displayFont = [NSFont monospacedDigitSystemFontOfSize:28
                                                        weight:NSFontWeightRegular];
    NSDictionary *attributes = @{NSFontAttributeName: displayFont};
    CGFloat maximumTextWidth = MAX([@"9223372036854775807" sizeWithAttributes:attributes].width,
                                  [@"-9223372036854775808" sizeWithAttributes:attributes].width);
    // Leave room for the field's cell inset plus breathing room at both ends.
    CGFloat minimumWidth = MAX(420, ceil(maximumTextWidth) + 2 * margin + 16);
    CGFloat innerWidth = minimumWidth - 2 * margin;
    NSRect frame = NSMakeRect(0, 0, minimumWidth, minimumHeight);
    NSWindowStyleMask style = NSWindowStyleMaskTitled |
        NSWindowStyleMaskClosable | NSWindowStyleMaskResizable;
    self.window = [[NSWindow alloc] initWithContentRect:frame
                                              styleMask:style
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    self.window.title = applicationName;
    self.window.contentMinSize = NSMakeSize(minimumWidth, minimumHeight);
    NSView *root = self.window.contentView;

    NSTextField *display = [[NSTextField alloc] initWithFrame:NSMakeRect(margin, 410, innerWidth, 40)];
    display.editable = NO;
    display.selectable = NO;
    display.alignment = NSTextAlignmentRight;
    display.font = displayFont;
    display.usesSingleLineMode = YES;
    display.lineBreakMode = NSLineBreakByClipping;
    display.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
    display.stringValue = @"0";
    [root addSubview:display];

    NSTextField *error = [[NSTextField alloc] initWithFrame:NSMakeRect(margin, 384, innerWidth, 22)];
    error.editable = NO;
    error.selectable = NO;
    error.bordered = NO;
    error.drawsBackground = NO;
    error.textColor = NSColor.systemRedColor;
    error.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
    error.stringValue = @"";
    [root addSubview:error];

    NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(margin, 264, innerWidth, 112)];
    scroll.hasVerticalScroller = YES;
    // The top labels stay top-aligned and the buttons stay bottom-aligned.
    // Only history absorbs extra height, so the controls cannot overlap.
    scroll.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    NSTextView *history = [[NSTextView alloc] initWithFrame:scroll.contentView.bounds];
    history.editable = NO;
    history.font = [NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular];
    history.verticallyResizable = YES;
    history.horizontallyResizable = NO;
    history.autoresizingMask = NSViewWidthSizable;
    history.textContainer.containerSize = NSMakeSize(innerWidth, CGFLOAT_MAX);
    history.textContainer.widthTracksTextView = YES;
    scroll.documentView = history;
    [root addSubview:scroll];

    self.controller.displayField = display;
    self.controller.errorField = error;
    self.controller.historyView = history;

    NSArray<NSString *> *labels = @[
        @"C", @"±", @"÷", @"×",
        @"7", @"8", @"9", @"−",
        @"4", @"5", @"6", @"+",
        @"1", @"2", @"3", @"=",
        @"0",
    ];
    NSView *buttons = [[NSView alloc] initWithFrame:NSMakeRect(margin, 8, innerWidth, 244)];
    buttons.autoresizingMask = NSViewWidthSizable;
    [root addSubview:buttons];
    const CGFloat bh = 44, gap = 6;
    const CGFloat bw = (innerWidth - 3 * gap) / 4;
    const CGFloat x0 = 0, yTop = 200;
    for (NSUInteger i = 0; i < labels.count; i++) {
        NSUInteger row = i / 4, col = i % 4;
        // Last row holds only "0" spanning the width.
        CGFloat x = x0 + col * (bw + gap);
        CGFloat y = yTop - row * (bh + gap);
        CGFloat w = bw;
        if (i == labels.count - 1) {
            x = x0;
            w = 4 * bw + 3 * gap;
        }
        NSButton *b = [[NSButton alloc] initWithFrame:NSMakeRect(x, y, w, bh)];
        b.title = labels[i];
        b.bezelStyle = NSBezelStyleRounded;
        b.target = self;
        b.action = @selector(buttonPressed:);
        // Proportionally resize the horizontal grid, retaining row positions.
        b.autoresizingMask = NSViewMinXMargin | NSViewWidthSizable | NSViewMaxXMargin;
        [buttons addSubview:b];
    }
}

- (void)buttonPressed:(NSButton *)sender {
    NSString *t = sender.title;
    CalcController *c = self.controller;
    if (t.length == 1) {
        unichar ch = [t characterAtIndex:0];
        if (ch >= '0' && ch <= '9') {
            [c pressDigit:(int)(ch - '0')];
            return;
        }
    }
    if ([t isEqualToString:@"+"]) { [c pressOperator:'+']; return; }
    if ([t isEqualToString:@"−"] || [t isEqualToString:@"-"]) { [c pressOperator:'-']; return; }
    if ([t isEqualToString:@"×"] || [t isEqualToString:@"*"]) { [c pressOperator:'*']; return; }
    if ([t isEqualToString:@"÷"] || [t isEqualToString:@"/"]) { [c pressOperator:'/']; return; }
    if ([t isEqualToString:@"="]) { [c pressEquals]; return; }
    if ([t isEqualToString:@"C"]) { [c pressClear]; return; }
    if ([t isEqualToString:@"±"]) { [c pressNegate]; return; }
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    (void)sender;
    return YES;
}

@end
