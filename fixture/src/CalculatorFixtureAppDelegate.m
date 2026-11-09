// CalculatorFixtureAppDelegate.m — programmatic AppKit UI. Every button
// routes through CalcController press* methods (the same methods the
// headless UI-journey tests drive).
#import "CalculatorFixtureAppDelegate.h"
#import "CalcController.h"

@implementation CalculatorFixtureAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    self.controller = [[CalcController alloc] init];

    NSRect frame = NSMakeRect(0, 0, 320, 480);
    NSWindowStyleMask style = NSWindowStyleMaskTitled |
        NSWindowStyleMaskClosable | NSWindowStyleMaskResizable;
    self.window = [[NSWindow alloc] initWithContentRect:frame
                                              styleMask:style
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    self.window.title = @"CalculatorFixture";
    NSView *root = self.window.contentView;

    NSTextField *display = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 410, 280, 40)];
    display.editable = NO;
    display.selectable = NO;
    display.alignment = NSTextAlignmentRight;
    display.font = [NSFont monospacedDigitSystemFontOfSize:28 weight:NSFontWeightRegular];
    display.stringValue = @"0";
    [root addSubview:display];

    NSTextField *error = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 384, 280, 22)];
    error.editable = NO;
    error.selectable = NO;
    error.bordered = NO;
    error.drawsBackground = NO;
    error.textColor = NSColor.systemRedColor;
    error.stringValue = @"";
    [root addSubview:error];

    NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(20, 264, 280, 112)];
    scroll.hasVerticalScroller = YES;
    NSTextView *history = [[NSTextView alloc] initWithFrame:scroll.contentView.bounds];
    history.editable = NO;
    history.font = [NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular];
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
    const CGFloat bw = 65, bh = 44, gap = 6;
    const CGFloat x0 = 20, yTop = 208;
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
        [root addSubview:b];
    }

    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
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
