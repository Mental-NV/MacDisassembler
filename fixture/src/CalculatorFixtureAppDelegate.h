// CalculatorFixtureAppDelegate.h — minimal AppKit delegate: builds the
// window, display, error label, history view, and button grid in code.
#import <Cocoa/Cocoa.h>

@class CalcController;

@interface CalculatorFixtureAppDelegate : NSObject <NSApplicationDelegate>
@property (nonatomic, strong, nullable) NSWindow *window;
@property (nonatomic, strong, nullable) CalcController *controller;
@end
