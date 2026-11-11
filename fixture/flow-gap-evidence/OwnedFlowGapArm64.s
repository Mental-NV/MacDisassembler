// Project-owned static-only fixture. Never execute this library.
.text
.p2align 2
.globl _owned_handler
_owned_handler:
    ldr w2, [x0]
    cmp w2, w1
    b.eq Lhandler_done
    str w1, [x0]
Lhandler_done:
    ret

.globl _owned_linkage
_owned_linkage:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    bl _owned_handler
    ldp x29, x30, [sp], #16
    adrp x16, _puts@GOTPAGE
    ldr x16, [x16, _puts@GOTPAGEOFF]
    br x16

.globl _owned_wrapper_named
_owned_wrapper_named:
    br x0

.globl _owned_internal
_owned_internal:
    cbz x0, Linternal_return
    b Linternal_outside
Linternal_return:
    ret
.globl _owned_boundary
_owned_boundary:
    ret
Linternal_outside:
    mov w0, #42
    b Linternal_return
.globl _owned_end
_owned_end:
    ret
