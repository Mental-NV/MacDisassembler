// Owned static-only unsupported-context fixture. Never execute.
.text
.p2align 2
.globl _owned_hidden_caller
_owned_hidden_caller:
    stp x20, x30, [sp, #-16]!
    mov x20, x0
    bl _owned_hidden_callee
    ldp x20, x30, [sp], #16
    ret

.globl _owned_hidden_callee
_owned_hidden_callee:
    ldr x0, [x20]
    ret

.globl _owned_hidden_sentinel
_owned_hidden_sentinel:
    ret
