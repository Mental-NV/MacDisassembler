// Project-owned static-only fixture. Never execute this library.
.text
.globl _owned_handler
_owned_handler:
    cmpl %esi, (%rdi)
    je Lhandler_done
    movl %esi, (%rdi)
Lhandler_done:
    retq

.globl _owned_linkage
_owned_linkage:
    pushq %rbp
    movq %rsp, %rbp
    callq _owned_handler
    popq %rbp
    jmpq *_puts@GOTPCREL(%rip)

.globl _owned_wrapper_named
_owned_wrapper_named:
    jmpq *%rax

.globl _owned_internal
_owned_internal:
    testq %rdi, %rdi
    je Linternal_return
    jmp Linternal_outside
Linternal_return:
    retq
.globl _owned_boundary
_owned_boundary:
    retq
Linternal_outside:
    movl $42, %eax
    jmp Linternal_return
.globl _owned_end
_owned_end:
    retq
