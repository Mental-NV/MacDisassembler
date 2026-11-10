extern "C" __attribute__((noinline)) int owned_throw(int input) {
    if (input > 0)
        throw input;
    return input - 1;
}

extern "C" __attribute__((noinline)) int owned_guard(int input) {
    try {
        return owned_throw(input);
    } catch (int value) {
        return value + 2;
    }
}

int main(int argc, char **argv) {
    (void)argv;
    return owned_guard(argc);
}
