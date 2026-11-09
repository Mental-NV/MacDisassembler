// CalcController.m — AppKit bridge over calc_core. No arithmetic here:
// every press* method delegates to the C engine, then refreshes widgets.
#import "CalcController.h"

@implementation CalcController {
    calc_state_t _state;
    calc_history_t _history;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        calc_state_init(&_state);
        calc_history_init(&_history);
    }
    return self;
}

- (calc_state_t)state {
    return _state;
}

- (calc_history_t)history {
    return _history;
}

- (void)pressDigit:(int)digit {
    calc_engine_input_digit(&_state, digit);
    [self refreshViews];
}

- (void)pressOperator:(char)op {
    // Only a pending operation with an entered RHS can complete here.
    // Snapshot before the engine replaces it with the newly pressed op.
    calc_state_t before = _state;
    calc_engine_input_op(&_state, op);
    if (!before.error_latched && before.pending_op != 0 &&
        !before.fresh_entry && !_state.error_latched) {
        calc_history_push(&_history, before.accumulator, before.pending_op,
                          before.display, _state.display);
    }
    [self refreshViews];
}

- (void)pressEquals {
    // Snapshot operands so completed computations reach history.
    int64_t lhs = _state.accumulator;
    char pop = _state.pending_op;
    int64_t rhs = _state.display;
    int hadPending = (pop != 0);
    int64_t oldDisplay = _state.display;
    calc_engine_equals(&_state);
    if (hadPending && !_state.error_latched) {
        calc_history_push(&_history, lhs, pop, rhs, _state.display);
    } else if (!hadPending && _state.has_last && !_state.error_latched) {
        // Repeated equals: record the repetition (last_op/last_operand).
        calc_history_push(&_history, oldDisplay, _state.last_op,
                          _state.last_operand, _state.display);
    }
    [self refreshViews];
}

- (void)pressClear {
    calc_engine_clear(&_state);
    calc_history_init(&_history);
    [self refreshViews];
}

- (void)pressNegate {
    calc_engine_sign_toggle(&_state);
    [self refreshViews];
}

- (NSString *)displayString {
    char buf[32];
    if (_state.display == 0 && _state.negative_zero) {
        return @"-0";
    }
    if (calc_format_int64(_state.display, buf, sizeof(buf)) != CALC_OK) {
        return @"?";
    }
    return [NSString stringWithUTF8String:buf];
}

- (NSString *)errorString {
    if (!_state.error_latched) {
        return @"";
    }
    switch (_state.error) {
        case CALC_ERR_OVERFLOW: return @"Error: overflow";
        case CALC_ERR_DIV_ZERO: return @"Error: division by zero";
        case CALC_ERR_INVALID: return @"Error: invalid input";
        default: return @"Error";
    }
}

- (NSString *)historyString {
    NSMutableString *s = [NSMutableString string];
    size_t len = calc_history_len(&_history);
    for (size_t i = 0; i < len; i++) {
        const calc_history_entry_t *e = calc_history_get(&_history, i);
        char lbuf[32], rbuf[32], vbuf[32];
        calc_format_int64(e->operand1, lbuf, sizeof(lbuf));
        calc_format_int64(e->operand2, rbuf, sizeof(rbuf));
        calc_format_int64(e->result, vbuf, sizeof(vbuf));
        [s appendFormat:@"%s %c %s = %s\n", lbuf, e->op, rbuf, vbuf];
    }
    return s;
}

- (void)refreshViews {
    NSString *d = [self displayString];
    NSString *e = [self errorString];
    NSString *h = [self historyString];
    // Widgets are nil in headless tests; production path is identical.
    self.displayField.stringValue = d;
    self.errorField.stringValue = e;
    self.historyView.string = h;
}

@end
