// ui_journeys.m — scripted controller journeys through the production
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
        CHECK_STR([c historyString], @"2 + 3 = 5\n5 + 3 = 8\n8 + 3 = 11\n");
        // 7: consecutive operators, last wins.
        c = fresh();
        enterDigits(c, "3"); [c pressOperator:'+']; [c pressOperator:'*'];
        CHECK_STR([c historyString], @"");
        enterDigits(c, "4"); [c pressEquals];
        CHECK_STR([c displayString], @"12");
        CHECK_STR([c historyString], @"3 * 4 = 12\n");
        // 8: chained pending compute, no precedence.
        c = fresh();
        enterDigits(c, "2"); [c pressOperator:'+']; enterDigits(c, "3");
        [c pressOperator:'*'];
        CHECK_STR([c historyString], @"2 + 3 = 5\n");
        enterDigits(c, "4"); [c pressEquals];
        CHECK_STR([c displayString], @"20");
        CHECK_STR([c historyString], @"2 + 3 = 5\n5 * 4 = 20\n");
        [c pressEquals];
        CHECK_STR([c historyString], @"2 + 3 = 5\n5 * 4 = 20\n20 * 4 = 80\n");
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
        CHECK_STR([c historyString], @"");
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

        // 21: failed chain, ignored presses, and clear never add history.
        c = fresh();
        enterDigits(c, "1"); [c pressOperator:'/']; enterDigits(c, "0");
        [c pressOperator:'+'];
        CHECK_STR([c errorString], @"Error: division by zero");
        CHECK_STR([c historyString], @"");
        [c pressOperator:'*']; [c pressEquals]; [c pressDigit:9]; [c pressNegate];
        CHECK_STR([c displayString], @"0");
        CHECK_STR([c historyString], @"");
        [c pressClear];
        CHECK_STR([c errorString], @"");
        CHECK_STR([c historyString], @"");

        // 22: a failed later chain preserves only earlier successful work.
        c = fresh();
        enterDigits(c, "2"); [c pressOperator:'+']; enterDigits(c, "3");
        [c pressOperator:'/']; enterDigits(c, "0"); [c pressOperator:'*'];
        CHECK_STR([c errorString], @"Error: division by zero");
        CHECK_STR([c historyString], @"2 + 3 = 5\n");
        [c pressEquals];
        CHECK_STR([c historyString], @"2 + 3 = 5\n");
        [c pressClear]; CHECK_STR([c historyString], @"");

        // 23: overflow during a chained operator also adds nothing.
        c = fresh();
        enterDigits(c, "9223372036854775807"); [c pressOperator:'+'];
        enterDigits(c, "1"); [c pressOperator:'*'];
        CHECK_STR([c displayString], @"1");
        CHECK_STR([c errorString], @"Error: overflow");
        CHECK_STR([c historyString], @"");

        // 24: invalid new operator cannot commit an otherwise valid chain.
        c = fresh();
        enterDigits(c, "2"); [c pressOperator:'+']; enterDigits(c, "3");
        [c pressOperator:'?'];
        CHECK_STR([c displayString], @"3");
        CHECK_STR([c errorString], @"Error: invalid input");
        CHECK_STR([c historyString], @"");

        // 25: consecutive operators after a completed chain do not duplicate it.
        c = fresh();
        enterDigits(c, "2"); [c pressOperator:'+']; enterDigits(c, "3");
        [c pressOperator:'*']; [c pressOperator:'-']; [c pressOperator:'/'];
        CHECK_STR([c historyString], @"2 + 3 = 5\n");
        enterDigits(c, "4"); [c pressEquals];
        CHECK_STR([c historyString], @"2 + 3 = 5\n5 / 4 = 1\n");

        // 26: sign-before-digits preserves negative zero and magnitude.
        c = fresh(); [c pressNegate];
        CHECK_STR([c displayString], @"-0");
        enterDigits(c, "00"); CHECK_STR([c displayString], @"-0");
        enterDigits(c, "12"); CHECK_STR([c displayString], @"-12");
        CHECK_STR([c historyString], @"");
        [c pressClear]; CHECK_STR([c displayString], @"0");
        enterDigits(c, "8"); [c pressNegate]; enterDigits(c, "2");
        CHECK_STR([c displayString], @"-82");

        // 27: signed RHS leaves LHS intact and records negative operand.
        c = fresh();
        enterDigits(c, "3"); [c pressOperator:'+']; [c pressNegate];
        CHECK_STR([c displayString], @"-0");
        enterDigits(c, "4"); [c pressEquals];
        CHECK_STR([c displayString], @"-1");
        CHECK_STR([c historyString], @"3 + -4 = -1\n");

        // 28: toggling the pending entry sign twice restores positive digits.
        c = fresh();
        enterDigits(c, "3"); [c pressOperator:'+']; [c pressNegate]; [c pressNegate];
        CHECK_STR([c displayString], @"0");
        enterDigits(c, "4"); [c pressEquals];
        CHECK_STR([c displayString], @"7");
        CHECK_STR([c historyString], @"3 + 4 = 7\n");

        // 29: a sign-only RHS is an entered zero, so an operator computes it.
        c = fresh();
        enterDigits(c, "3"); [c pressOperator:'+']; [c pressNegate];
        [c pressOperator:'*']; enterDigits(c, "4"); [c pressEquals];
        CHECK_STR([c displayString], @"12");
        CHECK_STR([c historyString], @"3 + 0 = 3\n3 * 4 = 12\n");

        // 30: signed zero is normalized by a completed binary computation.
        c = fresh();
        enterDigits(c, "0"); [c pressOperator:'+']; [c pressNegate]; [c pressEquals];
        CHECK_STR([c displayString], @"0");
        CHECK_STR([c historyString], @"0 + 0 = 0\n");
        [c pressDigit:4]; CHECK_STR([c displayString], @"4");

        // 31: INT64_MIN can be entered directly; negating it latches overflow.
        c = fresh(); [c pressNegate]; enterDigits(c, "9223372036854775808");
        CHECK_STR([c displayString], @"-9223372036854775808");
        CHECK_STR([c errorString], @"");
        [c pressNegate];
        CHECK_STR([c errorString], @"Error: overflow");
        CHECK_STR([c displayString], @"-9223372036854775808");
        CHECK_STR([c historyString], @"");

        // 32: signed RHS on INT64_MIN does not negate the LHS.
        c = fresh(); [c pressNegate]; enterDigits(c, "9223372036854775808");
        [c pressOperator:'/']; [c pressNegate];
        CHECK_STR([c displayString], @"-0");
        CHECK_STR([c errorString], @"");
        enterDigits(c, "1"); [c pressEquals];
        CHECK_STR([c displayString], @"-1");
        CHECK_STR([c errorString], @"Error: overflow");
        CHECK_STR([c historyString], @"");

        // 33: sign after equals edits the result and subsequent digits append.
        c = fresh();
        enterDigits(c, "2"); [c pressOperator:'+']; enterDigits(c, "3");
        [c pressEquals]; [c pressNegate]; [c pressDigit:4];
        CHECK_STR([c displayString], @"-54");
        CHECK_STR([c historyString], @"2 + 3 = 5\n");

        // 34: negative boundary overflow preserves the previous entered prefix.
        c = fresh(); [c pressNegate]; enterDigits(c, "9223372036854775809");
        CHECK_STR([c displayString], @"-922337203685477580");
        CHECK_STR([c errorString], @"Error: overflow");
        CHECK_STR([c historyString], @"");
        printf("ui_journeys: pass=%d fail=%d\n", g_pass, g_fail);
        return g_fail == 0 ? 0 : 1;
    }
}
