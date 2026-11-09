// ui_journeys.m — 20 scripted UI journeys through the production
// CalcController press* pathways (the same methods AppKit buttons call).
// Headless: no windows are created. Exit 0 on success, 1 on failure.
//
// Build: clang -O0 -g -Wall -framework Cocoa -I../src \
//        ../src/calc_core.c ../src/CalcController.m ui_journeys.m \
//        -o ui_journeys
#import <Cocoa/Cocoa.h>
#import "CalcController.h"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK_STR(got, want) do { \
    NSString *_g = (got); \
    if ([_g isEqualToString:(want)]) { g_pass++; } \
    else { g_fail++; printf("FAIL line %d: got '%s' want '%s'\n", \
        __LINE__, [_g UTF8String], [(want) UTF8String]); } \
} while (0)

static CalcController *fresh(void) {
    return [[CalcController alloc] init];
}

static void enterDigits(CalcController *c, const char *digits) {
    for (; *digits; digits++) {
        [c pressDigit:(int)(*digits - '0')];
    }
}

int main(int argc, const char *argv[]) {
    (void)argc; (void)argv;
    @autoreleasepool {
        // 1: simple add.
        CalcController *c = fresh();
        enterDigits(c, "12"); [c pressOperator:'+']; enterDigits(c, "34");
        [c pressEquals]; CHECK_STR([c displayString], @"46");
        // 2: subtract negative result.
        c = fresh();
        enterDigits(c, "5"); [c pressOperator:'-']; enterDigits(c, "9");
        [c pressEquals]; CHECK_STR([c displayString], @"-4");
        // 3: multiply.
        c = fresh();
        enterDigits(c, "6"); [c pressOperator:'*']; enterDigits(c, "7");
        [c pressEquals]; CHECK_STR([c displayString], @"42");
        // 4: truncating division, negatives.
        c = fresh();
        enterDigits(c, "7"); [c pressNegate]; [c pressOperator:'/'];
        enterDigits(c, "2"); [c pressEquals];
        CHECK_STR([c displayString], @"-3");
        // 5: divide by zero latches, digit ignored, C recovers.
        c = fresh();
        enterDigits(c, "1"); [c pressOperator:'/']; enterDigits(c, "0");
        [c pressEquals];
        CHECK_STR([c displayString], @"0");
        CHECK_STR([c errorString], @"Error: division by zero");
        [c pressDigit:9];
        CHECK_STR([c displayString], @"0");
        [c pressClear];
        CHECK_STR([c errorString], @"");
        [c pressDigit:9];
        CHECK_STR([c displayString], @"9");
        // 6: repeated equals.
        c = fresh();
        enterDigits(c, "2"); [c pressOperator:'+']; enterDigits(c, "3");
        [c pressEquals]; [c pressEquals]; [c pressEquals];
        CHECK_STR([c displayString], @"11");
        // 7: consecutive operators, last wins.
        c = fresh();
        enterDigits(c, "3"); [c pressOperator:'+']; [c pressOperator:'*'];
        enterDigits(c, "4"); [c pressEquals];
        CHECK_STR([c displayString], @"12");
        // 8: chained pending compute, no precedence.
        c = fresh();
        enterDigits(c, "2"); [c pressOperator:'+']; enterDigits(c, "3");
        [c pressOperator:'*']; enterDigits(c, "4"); [c pressEquals];
        CHECK_STR([c displayString], @"20");
        // 9: sign toggle.
        c = fresh();
        enterDigits(c, "8"); [c pressNegate];
        CHECK_STR([c displayString], @"-8");
        [c pressNegate];
        CHECK_STR([c displayString], @"8");
        // 10: overflow latches.
        c = fresh();
        enterDigits(c, "9223372036854775807"); [c pressOperator:'+'];
        enterDigits(c, "1"); [c pressEquals];
        CHECK_STR([c errorString], @"Error: overflow");
        // 11: clear resets repeat history.
        c = fresh();
        enterDigits(c, "2"); [c pressOperator:'+']; enterDigits(c, "3");
        [c pressEquals]; [c pressClear]; [c pressEquals];
        CHECK_STR([c displayString], @"0");
        // 12: equals with no pending is a no-op.
        c = fresh();
        enterDigits(c, "9"); [c pressEquals];
        CHECK_STR([c displayString], @"9");
        // 13: history records completed computation.
        c = fresh();
        enterDigits(c, "2"); [c pressOperator:'+']; enterDigits(c, "3");
        [c pressEquals];
        CHECK_STR([c historyString], @"2 + 3 = 5\n");
        // 14: failed computation leaves no history.
        c = fresh();
        enterDigits(c, "1"); [c pressOperator:'/']; enterDigits(c, "0");
        [c pressEquals];
        CHECK_STR([c historyString], @"");
        // 15: multi-step journey with sign change mid-entry.
        c = fresh();
        enterDigits(c, "10"); [c pressNegate]; [c pressOperator:'*'];
        enterDigits(c, "3"); [c pressEquals];
        CHECK_STR([c displayString], @"-30");
        // 16: zero handling.
        c = fresh();
        [c pressDigit:0]; [c pressDigit:0]; [c pressDigit:5];
        CHECK_STR([c displayString], @"5");
        // 17: large multiply then repeat.
        c = fresh();
        enterDigits(c, "1000000"); [c pressOperator:'*'];
        enterDigits(c, "1000000"); [c pressEquals]; [c pressEquals];
        CHECK_STR([c displayString], @"1000000000000000000");
        // 18: error blocks operator, clear unblocks.
        c = fresh();
        enterDigits(c, "1"); [c pressOperator:'/']; enterDigits(c, "0");
        [c pressEquals]; [c pressOperator:'+'];
        CHECK_STR([c errorString], @"Error: division by zero");
        [c pressClear];
        enterDigits(c, "4"); [c pressOperator:'+']; enterDigits(c, "4");
        [c pressEquals];
        CHECK_STR([c displayString], @"8");
        // 19: subtraction chain to negative with repeat.
        c = fresh();
        enterDigits(c, "3"); [c pressOperator:'-']; enterDigits(c, "5");
        [c pressEquals]; [c pressEquals];
        CHECK_STR([c displayString], @"-7");
        // 20: fresh entry after equals starts a new number.
        c = fresh();
        enterDigits(c, "2"); [c pressOperator:'+']; enterDigits(c, "2");
        [c pressEquals]; [c pressDigit:7];
        CHECK_STR([c displayString], @"7");
        printf("ui_journeys: pass=%d fail=%d\n", g_pass, g_fail);
        return g_fail == 0 ? 0 : 1;
    }
}
