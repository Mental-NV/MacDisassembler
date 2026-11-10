// Project-owned ARM64 input. Build and statically inspect; never execute it.
.text
.p2align 2
.globl _owned_tail_local
_owned_tail_local:
    b _owned_target
.globl _owned_target
_owned_target:
    mov w0, #42
    ret
.globl _owned_tail_import
_owned_tail_import:
    b _puts
.globl _owned_trap
_owned_trap:
    cbz x0, Ltrap
    ret
Ltrap:
    brk #1
.globl _owned_indirect
_owned_indirect:
    br x0
.globl _owned_end
_owned_end:
    ret

// Non-linker exits: the decompiler may optimize the outside operations away.
.globl _owned_escape_constant
_owned_escape_constant:
    mov x1, #1
    cbz x1, Lconstant_return
    b Lconstant_outside
Lconstant_return:
    ret
.globl _owned_constant_boundary
_owned_constant_boundary:
    ret
Lconstant_outside:
    mov w0, #42
    b Lconstant_return

.globl _owned_escape_same
_owned_escape_same:
    cbz x0, Lsame_return
    b Lsame_outside
Lsame_return:
    mov w0, #7
    ret
.globl _owned_same_boundary
_owned_same_boundary:
    ret
Lsame_outside:
    mov w0, #7
    b Lsame_return

.globl _owned_escape_overwritten
_owned_escape_overwritten:
    cbz x0, Loverwritten_return
    b Loverwritten_outside
Loverwritten_return:
    mov w0, #7
    ret
.globl _owned_overwritten_boundary
_owned_overwritten_boundary:
    ret
Loverwritten_outside:
    mov w0, #42
    b Loverwritten_return

.globl _owned_escape_unused
_owned_escape_unused:
    cbz x0, Lunused_return
    b Lunused_outside
Lunused_return:
    mov w0, #7
    ret
.globl _owned_unused_boundary
_owned_unused_boundary:
    ret
Lunused_outside:
    mov x9, #42
    b Lunused_return

.globl _owned_escape_conditional
_owned_escape_conditional:
    cbz x0, Lconditional_outside
    mov w0, #7
    ret
.globl _owned_conditional_boundary
_owned_conditional_boundary:
    ret
Lconditional_outside:
    mov w0, #42
    ret

.globl _owned_escape_fallthrough
_owned_escape_fallthrough:
    nop
.globl _owned_fallthrough_boundary
_owned_fallthrough_boundary:
    ret
.globl _owned_final_boundary
_owned_final_boundary:
    ret
