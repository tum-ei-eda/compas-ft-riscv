/* Minimal Linux user-mode entry point for freestanding RISC-V tests. */
    .text
    .globl _start
    .type _start, @function
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    call main
    li a7, 93
    ecall
    .size _start, .-_start
