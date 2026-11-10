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
