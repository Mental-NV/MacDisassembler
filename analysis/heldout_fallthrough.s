// Owned arm64 boundary fixture. The frame setup is inside each guarded routine.
.text
.p2align 2
.globl _heldout_guarded_call
_heldout_guarded_call:
    cmp w0, #5
    b.hi Lguarded_default
    tbz w0, #0, Lguarded_default
Lguarded_frame:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    blr x1
    add x0, x0, #29
    ldp x29, x30, [sp], #16
    ret
Lguarded_default:
    mov x0, #43
    ret

.globl _heldout_shared_body
_heldout_shared_body:
    cmp w0, #7
    b.hi Lshared_default
    tbz w0, #1, Lshared_default
Lshared_frame:
    stp x29, x30, [sp, #-16]!
Lshared_setup:
    mov x29, sp
    blr x1
    add x0, x0, #31
    ldp x29, x30, [sp], #16
    ret
Lshared_default:
    mov x0, #47
    ret

.globl _heldout_external_entry
_heldout_external_entry:
    b Lshared_setup

.globl _heldout_confirmed_wrapper
_heldout_confirmed_wrapper:
    cbz x0, Lwrapper_default
    b _heldout_confirmed_callee
Lwrapper_default:
    mov x0, #53
    ret

.globl _heldout_confirmed_callee
_heldout_confirmed_callee:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    blr x1
    ldp x29, x30, [sp], #16
    ret

.globl _main
_main:
    mov w0, #0
    ret

.subsections_via_symbols
