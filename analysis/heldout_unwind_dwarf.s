.text
.globl _owned_dwarf
.p2align 2
_owned_dwarf:
    .cfi_startproc
    .cfi_escape 0x0f, 0x02, 0x77, 0x08
    xor %eax, %eax
    retq
    .cfi_endproc
