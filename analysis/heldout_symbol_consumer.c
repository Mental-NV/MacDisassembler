#include <stdio.h>
extern _Thread_local int owned_tls;
extern int owned_global;

__attribute__((noinline)) int owned_report(int count) {
    return puts(count ? "owned evidence" : "owned empty") + owned_global + owned_tls;
}

int main(int argc, char **argv) {
    (void)argv;
    return owned_report(argc);
}
