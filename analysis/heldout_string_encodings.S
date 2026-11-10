.text
.globl _main
.p2align 2
_main:
#if defined(__arm64__)
    adrp x1, _owned_ascii@PAGE
    add x1, x1, _owned_ascii@PAGEOFF
    adrp x2, _owned_utf8@PAGE
    add x2, x2, _owned_utf8@PAGEOFF
    adrp x3, _owned_wide@PAGE
    add x3, x3, _owned_wide@PAGEOFF
    ldrb w0, [x1]
    ldrb w4, [x2]
    ldrh w5, [x3]
    add w0, w0, w4
    add w0, w0, w5
    ret
#else
    leaq _owned_ascii(%rip), %rcx
    leaq _owned_utf8(%rip), %rdx
    leaq _owned_wide(%rip), %rsi
    xorl %eax, %eax
    retq
#endif

.section __TEXT,__cstring,cstring_literals
.globl _owned_ascii
_owned_ascii:
    .asciz "Owned ASCII evidence"
.globl _owned_utf8
_owned_utf8:
    .asciz "Owned caf\303\251 UTF-8"
.globl _owned_other
_owned_other:
    .asciz "Owned extra ASCII evidence"
.globl _owned_redacted
_owned_redacted:
    .asciz "/Users/localfixture/Owned string"
.globl _owned_invalid
_owned_invalid:
    .asciz "Owned invalid \377 bytes"

.section __TEXT,__ustring
.p2align 1
.globl _owned_wide
_owned_wide:
    .short 0x4f, 0x77, 0x6e, 0x65, 0x64, 0x20, 0x57, 0x69, 0x64, 0x65, 0x20, 0x57, 0x6f, 0x72, 0x64, 0
