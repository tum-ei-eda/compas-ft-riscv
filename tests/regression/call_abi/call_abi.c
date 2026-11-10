/* Fault-free RISC-V call ABI checks. The independent oracle is in main(). */
#ifndef TEST_CASE
#error "Select a call ABI scenario with TEST_CASE"
#endif

#define NOINLINE __attribute__((noinline))
typedef unsigned long word;
typedef unsigned long long wide;

#if TEST_CASE >= 1 && TEST_CASE <= 3
NOINLINE word abi_leaf(word value)
{
    return value * 3 + 5;
}
#endif

#if TEST_CASE == 1
volatile word abi_inputs[] = {2, 11};

NOINLINE word abi_caller(word value)
{
    word live = value ^ 0x1357UL;
    word result = abi_leaf(value + 2);
    return (result ^ live) + 7;
}

int main(void)
{
    /* Independently evaluated: ((3 * (x + 2) + 5) ^ (x ^ 0x1357)) + 7. */
    return abi_caller(abi_inputs[0]) == 0x134bUL &&
           abi_caller(abi_inputs[1]) == 0x1377UL ? 42 : 17;
}

#elif TEST_CASE == 2
volatile word abi_inputs[] = {1, 4, 7, 13};

NOINLINE word abi_nested_middle(word value)
{
    word first = abi_leaf(value + 1);
    word second = abi_leaf(value + 2);
    return first + second + value;
}

NOINLINE word abi_nested_top(word value)
{
    word sentinel = value ^ 0xa55aUL;
    word first = abi_nested_middle(value);
    word second = abi_nested_middle(value + 3);
    return sentinel + first + second;
}

int main(void)
{
    /* Each nested pair contributes 14*x + 59, independently of the sentinel. */
    const word expected[] = {0xa5a4UL, 0xa5d1UL, 0xa5faUL, 0xa648UL};
    unsigned int index;
    for (index = 0; index != 4; ++index) {
        if (abi_nested_top(abi_inputs[index]) != expected[index])
            return 17;
    }
    return 42;
}

#elif TEST_CASE == 3
volatile word abi_inputs[] = {3, 17};

NOINLINE word abi_indirect_other(word value)
{
    return value + 17;
}

word (*volatile abi_indirect_target)(word) = abi_leaf;

NOINLINE word abi_indirect(word value)
{
    word first = abi_indirect_target(value);
    abi_indirect_target = abi_indirect_other;
    word second = abi_indirect_target(value + 1);
    abi_indirect_target = abi_leaf;
    return first ^ (second << 1) ^ (value + 0x1234UL);
}

int main(void)
{
    /* Both target choices execute on both calls; the pointer stays volatile. */
    return abi_indirect(abi_inputs[0]) == 0x1213UL &&
           abi_indirect(abi_inputs[1]) == 0x123bUL ? 42 : 17;
}

#elif TEST_CASE == 4
volatile word abi_inputs[] = {1, 7};

NOINLINE word abi_ten_args(word a, word b, word c, word d, word e,
                          word f, word g, word h, word i, word j)
{
    return a + 2*b + 3*c + 4*d + 5*e + 6*f + 7*g + 8*h + 9*i + 10*j;
}

NOINLINE word abi_stack_arguments(word value)
{
    word sentinel = value ^ 0x55UL;
    word result = abi_ten_args(value, value + 1, value + 2, value + 3,
                              value + 4, value + 5, value + 6, value + 7,
                              value + 8, value + 9);
    return result + sentinel;
}

int main(void)
{
    /* sum(k * (x + k - 1), k=1..10) = 55*x + 330. */
    return abi_stack_arguments(abi_inputs[0]) == 469UL &&
           abi_stack_arguments(abi_inputs[1]) == 797UL ? 42 : 17;
}

#elif TEST_CASE == 5
volatile wide abi_wide_inputs[] = {0xfedcba9876543210ULL, 0x81234567abcdef09ULL};

NOINLINE wide abi_wide_leaf(wide value)
{
    return (value ^ 0x13579bdf2468ace0ULL) + 0x0102030405060708ULL;
}

NOINLINE wide abi_wide_caller(wide value)
{
    wide sentinel = value ^ 0x02468ace13579bdfULL;
    wide result = abi_wide_leaf(value);
    return (result ^ sentinel) + (sentinel >> 32);
}

int main(void)
{
    /* Full 64-bit argument, return and live value; RV32 uses register pairs. */
    return abi_wide_caller(abi_wide_inputs[0]) == 0x1217141e2edb3c8dULL &&
           abi_wide_caller(abi_wide_inputs[1]) == 0x10132e15af970dd0ULL ? 42 : 17;
}

#elif TEST_CASE == 6
volatile word abi_inputs[] = {3, 21};

/* Intentionally unprotected: inspect SP without asking COMPAS to duplicate asm. */
NOINLINE word abi_stack_pointer(void)
{
#if defined(__riscv)
    word pointer;
    __asm__ volatile ("mv %0, sp" : "=r" (pointer) : : "memory");
    return pointer;
#else
    /* Host smoke builds check the arithmetic; the RISC-V runs check real SP. */
    return 0;
#endif
}

NOINLINE word abi_stack_callee(word first, word second)
{
    volatile word spill[12];
    spill[0] = first;
    spill[11] = second;
    if ((abi_stack_pointer() & 15UL) != 0)
        return 0;
    return spill[0] + spill[11] + 9;
}

NOINLINE word abi_stack_caller(word value)
{
    volatile word spill[12];
    spill[0] = value ^ 0x1234UL;
    spill[11] = value + 7;
    word before = abi_stack_pointer();
    word result = abi_stack_callee(value, spill[11]);
    word after = abi_stack_pointer();
    if ((before & 15UL) != 0 || before != after)
        return 0;
    return result + spill[0] + spill[11];
}

int main(void)
{
    /* The two nonzero sums also require aligned callees and restored SP. */
    return abi_stack_caller(abi_inputs[0]) == 0x1257UL &&
           abi_stack_caller(abi_inputs[1]) == 0x1277UL ? 42 : 17;
}

#elif TEST_CASE == 12
volatile word abi_inputs[] = {1, 4, 13, 29};

NOINLINE word abi_frame_leaf(word value)
{
    volatile word spill[3];
    spill[0] = value + 3;
    spill[1] = value ^ 0x35UL;
    spill[2] = value + 11;
    return 3*spill[0] + spill[1] + 2*spill[2];
}

NOINLINE word abi_frame_middle(word value)
{
    volatile word spill[5];
    spill[0] = value ^ 0x123UL;
    spill[1] = value + 9;
    spill[2] = value + 13;
    spill[3] = value ^ 0x27UL;
    spill[4] = value + 17;
    word first = abi_frame_leaf(value + 1);
    word second = abi_frame_leaf(value + 4);
    /* Access FP-relative locals after both calls. */
    return first + 2*second + spill[0] + spill[1] + 2*spill[2] +
           3*spill[3] + spill[4];
}

NOINLINE word abi_frame_top(word value)
{
    volatile word spill[7];
    spill[0] = value + 0x27UL;
    spill[1] = value ^ 0x456UL;
    spill[2] = value + 23;
    spill[3] = value ^ 0x67UL;
    spill[4] = value + 31;
    spill[5] = value ^ 0x89UL;
    spill[6] = value + 43;
    word first = abi_frame_middle(value + 2);
    word second = abi_frame_middle(value + 5);
    return first + 3*second + spill[0] + spill[1] + 2*spill[2] +
           3*spill[3] + 4*spill[4] + 5*spill[5] + 6*spill[6];
}

int main(void)
{
    /* Nested weighted sums, evaluated independently for each volatile input. */
    const word expected[] = {5985UL, 6415UL, 7049UL, 7881UL};
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int index;
        for (index = 0; index != 4; ++index) {
            if (abi_frame_top(abi_inputs[index]) != expected[index])
                return 17;
        }
    }
    return 42;
}

#else
#error "Unknown call ABI TEST_CASE"
#endif
