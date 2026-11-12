typedef unsigned long word;
volatile word helper_call_inputs[] = {2, 7, 19};
word ordinary_helper(word value);

#if TEST_CASE == 1
#define PROTECTED helper_repeated_calls
__attribute__((noinline)) word PROTECTED(word value)
{
#if defined(__riscv)
    __asm__ volatile ("" : : : "s1", "s2", "s3");
#endif
    word live = (value ^ 0x35UL) + 11;
    word first = ordinary_helper(value + 1);
    word second = ordinary_helper(value + 3);
    return first + 2*second + live;
}
#elif TEST_CASE == 2
#define PROTECTED helper_return_paths
__attribute__((noinline)) word PROTECTED(word value)
{
#if defined(__riscv)
    __asm__ volatile ("" : : : "s0", "s1", "s2");
#endif
    if (value == 2)
        return ordinary_helper(value) + 7;
    if (value < 10)
        return 2*ordinary_helper(value + 1);
    return ordinary_helper(value - 1) - 3;
}
#elif TEST_CASE == 3
#define PROTECTED helper_cold_branch
__attribute__((noinline)) word PROTECTED(word value)
{
    /* Shrink wrapping could otherwise put the save helper in this cold arm. */
    if (__builtin_expect((value & 1UL) == 0, 1))
        return value + 17;
#if defined(__riscv)
    __asm__ volatile ("" : : : "s0", "s1", "s2");
#endif
    return ordinary_helper(value + 1) + 13;
}
#else
#error "Select a save/restore call scenario with TEST_CASE"
#endif

int main(void)
{
#if TEST_CASE == 1
    /* 9*x + 47 + (x ^ 53), evaluated independently. */
    const word expected[] = {120UL, 160UL, 256UL};
#elif TEST_CASE == 2
    const word expected[] = {18UL, 58UL, 56UL};
#else
    const word expected[] = {19UL, 42UL, 78UL};
#endif
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int index;
        for (index = 0; index != 3; ++index) {
            if (PROTECTED(helper_call_inputs[index]) != expected[index])
                return 17;
        }
    }
    return 42;
}
