typedef unsigned long word;

__attribute__((noinline)) word ordinary_helper(word value)
{
#if defined(__riscv)
    /* An ordinary ABI callee may use the caller-clobbered RTS register. */
    __asm__ volatile ("li t0, 31\n\tli t1, 47" : : : "t0", "t1");
#endif
    return 3*value + 5;
}
