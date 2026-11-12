/* Sibling-call candidates with four outgoing stack arguments and an observer. */
#ifndef TAIL_WIDE
#define TAIL_WIDE 0
#endif

#define NOINLINE __attribute__((noinline))
typedef unsigned long word;
typedef unsigned long long wide;
#if TAIL_WIDE
typedef wide result_type;
#else
typedef word result_type;
#endif

volatile word tail_stack_inputs[] = {2, 7, 12, 9};
volatile word tail_stack_canary = 0x13579bUL;

NOINLINE result_type abi_tail_stack_leaf(word a, word b, word c, word d,
                                        word e, word f, word g, word h,
                                        word i, word j, word k, word l)
{
    volatile result_type local[4];
    word weighted = a + 2*b + 3*c + 4*d + 5*e + 6*f +
                    7*g + 8*h + 9*i + 10*j + 11*k + 12*l;
    for (word index = 0; index != 4; ++index) {
#if TAIL_WIDE
        local[index] = (wide)weighted * 0x10000000bULL + 0x200000005ULL
                       + (wide)index * 0x300000007ULL;
#else
        local[index] = weighted + 5 + 7*index;
#endif
    }
#if TAIL_WIDE
    return local[a & 3] ^ ((wide)weighted << 37);
#else
    return local[a & 3];
#endif
}

NOINLINE result_type abi_tail_stack_wrapper(word a, word b, word c, word d,
                                           word e, word f, word g, word h,
                                           word i, word j, word k, word l)
{
    volatile word scratch[9];
    for (word index = 0; index != 9; ++index)
        scratch[index] = a + 2*index;
    /* LLVM13/16 keep this as a call despite equal incoming/outgoing areas. */
    return abi_tail_stack_leaf(scratch[a & 7], b, c, d, e, f, g, h, i, j, k, l);
}

NOINLINE result_type abi_tail_stack_observer(word value)
{
    word canary = tail_stack_canary;
    result_type result = abi_tail_stack_wrapper(
        value, value+1, value+2, value+3, value+4, value+5,
        value+6, value+7, value+8, value+9, value+10, value+11);
#if TAIL_WIDE
    return result ^ (((wide)canary << 32) | 0x89abcdefULL);
#else
    return result ^ canary;
#endif
}

int main(void)
{
#if TAIL_WIDE
    static const result_type expected[] = {
        0x00130eff89abd268ULL, 0x0013de6a89abfd5fULL,
        0x0013eff589ab8cc6ULL, 0x0013cd1c89abfb01ULL
    };
#else
    static const result_type expected[] = {
        0x135574UL, 0x1353e3UL, 0x13526aUL, 0x13528dUL
    };
#endif
    for (word repeat = 0; repeat != 2; ++repeat)
        for (word index = 0; index != 4; ++index)
            if (abi_tail_stack_observer(tail_stack_inputs[index]) != expected[index])
                return 17;
    return 42;
}
