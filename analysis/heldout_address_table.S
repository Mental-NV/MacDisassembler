.text
.p2align 2
.globl _main
_main:
#if defined(__arm64__)
    adrp x0, _owned_table@PAGE
    add x0, x0, _owned_table@PAGEOFF
    ret
#else
    leaq _owned_table(%rip), %rax
    retq
#endif

.globl _owned_unknown
.p2align 2
_owned_unknown:
#if defined(__arm64__)
    br x0
#else
    jmpq *%rdi
#endif

.globl _owned_a, _owned_b, _owned_c
.p2align 2
_owned_a:
#if defined(__arm64__)
    mov w0, #1
    ret
#else
    movl $1, %eax
    retq
#endif
.p2align 2
_owned_b:
#if defined(__arm64__)
    mov w0, #2
    ret
#else
    movl $2, %eax
    retq
#endif
.p2align 2
_owned_c:
#if defined(__arm64__)
    mov w0, #3
    ret
#else
    movl $3, %eax
    retq
#endif

.section __DATA,__owned_ptrs
.p2align 2
.byte 0xff
.globl _owned_table
_owned_table:
    .quad _owned_a, _owned_b, _owned_c
    .byte 0xff
.p2align 2
.byte 0xff
.globl _owned_control
_owned_control:
    .quad _owned_a, _owned_b, _owned_c
    .byte 0xff
