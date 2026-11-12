/* Force callee-saved spills in a function with no source-level call. */
typedef unsigned long word;
volatile word helper_leaf_inputs[] = {2, 7, 19};

__attribute__((noinline)) word helper_only_leaf(word value)
{
#if defined(__riscv)
    __asm__ volatile ("" : : : "s0", "s1", "s2");
#endif
    return 5*value + 7;
}

int main(void)
{
    const word expected[] = {17UL, 42UL, 102UL};
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int index;
        for (index = 0; index != 3; ++index) {
            if (helper_only_leaf(helper_leaf_inputs[index]) != expected[index])
                return 17;
        }
    }
    return 42;
}
