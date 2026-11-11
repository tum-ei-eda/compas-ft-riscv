/* Ordinary callers tail-call an EDDI leaf; expected values are literal oracles. */
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

volatile word tail_inputs[] = {2, 7, 12, 9};
volatile word tail_canary = 0x13579bUL;

NOINLINE result_type abi_tail_leaf(word value)
{
    volatile result_type local[4];
    for (word i = 0; i < 4; ++i) {
#if TAIL_WIDE
        local[i] = (wide)value * 0x10000000bULL + 0x200000005ULL
                 + (wide)i * 0x300000007ULL;
#else
        local[i] = value * 3 + 5 + i * 7;
#endif
    }
#if TAIL_WIDE
    return local[value & 3] ^ ((wide)value << 37);
#else
    return local[value & 3];
#endif
}

NOINLINE result_type abi_tail_wrapper(word value)
{
    volatile word scratch[9];
    for (word i = 0; i < 9; ++i)
        scratch[i] = value + 2 * i;
    /* Keep this call eligible for sibling-call optimization in the input IR. */
    return abi_tail_leaf(scratch[value & 7]);
}

NOINLINE result_type abi_tail_observer(word value)
{
    /* This ordinary caller keeps a runtime value live across the wrapper. */
    word canary = tail_canary;
    result_type result = abi_tail_wrapper(value);
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
        0x0013575589abcdbaULL, 0x0013552189abcd1cULL,
        0x0013550d89abcd0eULL, 0x001356ed89abcd7cULL
    };
#else
    static const result_type expected[] = {
        0x1357beUL, 0x1357d0UL, 0x1357daUL, 0x1357a0UL
    };
#endif
    for (word repeat = 0; repeat < 2; ++repeat)
        for (word i = 0; i < 4; ++i)
            if (abi_tail_observer(tail_inputs[i]) != expected[i])
                return 17;
    return 42;
}
