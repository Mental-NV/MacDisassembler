// CalcController.h — bridges AppKit widgets to the pure C engine.
// All button callbacks funnel through the press* methods below, which are
// also the UI test hooks: tests drive these instead of synthesizing clicks.
#import <Cocoa/Cocoa.h>
#include "calc_core.h"

@interface CalcController : NSObject

// Production state. UI widgets observe via -refreshViews.
@property (nonatomic, readonly) calc_state_t state;
@property (nonatomic, readonly) calc_history_t history;

// Widgets. Wired by the app delegate; nil in headless tests.
@property (nonatomic, weak, nullable) NSTextField *displayField;
@property (nonatomic, weak, nullable) NSTextField *errorField;
@property (nonatomic, weak, nullable) NSTextView *historyView;

// Production button pathways (also UI test hooks).
- (void)pressDigit:(int)digit;
- (void)pressOperator:(char)op;
- (void)pressEquals;
- (void)pressClear;
- (void)pressNegate;

// Read-only presentation derived from state (used by UI and tests).
- (NSString * _Nonnull)displayString;
- (NSString * _Nonnull)errorString;
- (NSString * _Nonnull)historyString;

@end
