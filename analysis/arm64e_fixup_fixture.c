/* Owned metadata fixture. The validation reads the linked file as data. */
#include <ptrauth.h>
#include <stdio.h>

typedef int (*callback)(const char *);
static int owned_callback(const char *value) { return value != 0; }
__attribute__((used)) callback const local_default = owned_callback;
__attribute__((used)) callback const external_default = puts;
#if __has_feature(ptrauth_calls)
__attribute__((used)) callback __ptrauth(ptrauth_key_function_pointer, 1, 0x1357)
    const local_diverse = owned_callback;
__attribute__((used)) callback __ptrauth(ptrauth_key_process_independent_data, 1, 0x2468)
    const external_diverse = puts;
#endif
static const char label[] = "owned arm64e metadata fixture";
__attribute__((used)) const char * const local_data = label;
__attribute__((used)) FILE ** const external_data = &stdout + 1;
int main(void) { return 0; }
