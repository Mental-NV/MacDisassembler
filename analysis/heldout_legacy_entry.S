.text
.globl _owned_start
.p2align 2
_owned_start:
#if defined(__arm64__)
    mov w0, #7
    ret
#else
    movl $7, %eax
    retq
#endif
