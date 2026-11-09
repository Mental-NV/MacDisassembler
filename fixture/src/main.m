// main.m — CalculatorFixture application entry point.
#import <Cocoa/Cocoa.h>
#import "CalculatorFixtureAppDelegate.h"

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSApplication *app = NSApplication.sharedApplication;
        CalculatorFixtureAppDelegate *delegate =
            [[CalculatorFixtureAppDelegate alloc] init];
        app.delegate = delegate;
        [app run];
    }
    return 0;
}
