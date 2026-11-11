/* Compiler barriers are transparent to EDDI; opaque assembly is diagnosed. */
#define NOINLINE __attribute__((noinline))
typedef unsigned long word;

volatile word asm_inputs[] = {2, 7, 13};
volatile word asm_mask = 11;

NOINLINE word asm_barrier(word value)
{
    word first = 3*value + 1;
    __asm__ volatile ("" : : : "memory");
    word mask = asm_mask;
    __asm__ volatile ("");
    return (first ^ mask) + value;
}

#if defined(ASM_REGISTER)
NOINLINE word asm_opaque(word value)
{
#if defined(__riscv)
    word result;
    __asm__ volatile ("addi %0, %1, 1" : "=r" (result) : "r" (value));
    return result;
#else
    return value + 1;
#endif
}
#elif defined(ASM_EMPTY_OPERAND)
NOINLINE word asm_opaque(word value)
{
    __asm__ volatile ("" : "+r" (value));
    return value;
}
#endif

int main(void)
{
    /* Independent literals: ((3*x + 1) ^ 11) + x for x = 2, 7, 13. */
    const word expected[] = {14, 36, 48};
    unsigned int index;
    for (index = 0; index != 3; ++index) {
        word result = asm_barrier(asm_inputs[index]);
#if defined(ASM_REGISTER)
        if (asm_opaque(result) != expected[index] + 1)
            return 17;
#elif defined(ASM_EMPTY_OPERAND)
        if (asm_opaque(result) != expected[index])
            return 17;
#else
        if (result != expected[index])
            return 17;
#endif
    }
    return 42;
}
