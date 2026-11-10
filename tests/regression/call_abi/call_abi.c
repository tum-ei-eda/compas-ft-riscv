/* Fault-free RISC-V call ABI checks. The independent oracle is in main(). */
#ifndef TEST_CASE
#error "Select a call ABI scenario with TEST_CASE"
#endif

#define NOINLINE __attribute__((noinline))
typedef unsigned long word;
typedef unsigned long long wide;

#if TEST_CASE == 4 || (TEST_CASE >= 7 && TEST_CASE <= 9)
NOINLINE word abi_ten_args(word a, word b, word c, word d, word e,
                          word f, word g, word h, word i, word j)
{
    return a + 2*b + 3*c + 4*d + 5*e + 6*f + 7*g + 8*h + 9*i + 10*j;
}
#endif

#if (TEST_CASE >= 1 && TEST_CASE <= 3) || TEST_CASE == 10
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

#elif TEST_CASE == 7
volatile word abi_inputs[] = {2, 11, 19};
word (*volatile abi_ten_arg_target)(word, word, word, word, word,
                                  word, word, word, word, word) = abi_ten_args;

NOINLINE word abi_indirect_stack_arguments(word value)
{
    word first = abi_ten_arg_target(value, value + 1, value + 2, value + 3,
                                   value + 4, value + 5, value + 6, value + 7,
                                   value + 8, value + 9);
    word second = abi_ten_arg_target(value + 3, value + 4, value + 5, value + 6,
                                    value + 7, value + 8, value + 9, value + 10,
                                    value + 11, value + 12);
    return first + 2*second + (value ^ 0x3cUL);
}

int main(void)
{
    /* Each pair contributes 165*x + 1320, plus the independent live sentinel. */
    const word expected[] = {1712UL, 3190UL, 4502UL};
    unsigned int index;
    for (index = 0; index != 3; ++index) {
        if (abi_indirect_stack_arguments(abi_inputs[index]) != expected[index])
            return 17;
    }
    return 42;
}

#elif TEST_CASE == 8
volatile word abi_inputs[] = {1, 7, 13};

NOINLINE word abi_ten_arg_middle(word a, word b, word c, word d, word e,
                                word f, word g, word h, word i, word j)
{
    word result = abi_ten_args(j, i, h, g, f, e, d, c, b, a);
    /* Both incoming stack arguments must survive the outgoing ten-arg call. */
    return result + 3*i + 7*j;
}

NOINLINE word abi_nested_stack_arguments(word value)
{
    word first = abi_ten_arg_middle(value, value + 1, value + 2, value + 3,
                                   value + 4, value + 5, value + 6, value + 7,
                                   value + 8, value + 9);
    word second = abi_ten_arg_middle(value + 2, value + 3, value + 4, value + 5,
                                    value + 6, value + 7, value + 8, value + 9,
                                    value + 10, value + 11);
    return first + 2*second + (value ^ 0x6bUL);
}

int main(void)
{
    /* Each middle call returns 65*x + 252; the pair gives 195*x + 1016. */
    const word expected[] = {1317UL, 2489UL, 3653UL};
    unsigned int index;
    for (index = 0; index != 3; ++index) {
        if (abi_nested_stack_arguments(abi_inputs[index]) != expected[index])
            return 17;
    }
    return 42;
}

#elif TEST_CASE == 9
volatile word abi_inputs[] = {1, 7, 13};

NOINLINE word abi_dynamic_stack_arguments(word value)
{
    /* A large fixed frame and VLA require frame-index expansion and stable FP. */
    volatile word spill[1024];
    word fixed_index = (value & 511UL) + 1;
    word count = (value & 7UL) + 11;
    volatile word dynamic[count];
    spill[0] = value ^ 0x1234UL;
    spill[1023] = value + 0x4321UL;
    /* Runtime indexing prevents splitting the fixed array into small slots. */
    spill[fixed_index] = value + 0x77UL;
    dynamic[0] = value + 17;
    dynamic[count - 1] = value ^ 0x5aUL;
    word first = abi_ten_args(value, value + 1, value + 2, value + 3,
                             value + 4, value + 5, value + 6, value + 7,
                             value + 8, value + 9);
    word second = abi_ten_args(dynamic[0], dynamic[count - 1], value + 2,
                              value + 3, value + 4, value + 5, value + 6,
                              value + 7, value + 8, value + 9);
    return first + second + spill[0] + spill[1023] + spill[fixed_index] +
           dynamic[0] + dynamic[count - 1];
}

int main(void)
{
    /* 111*x + 17996 + (x ^ 0x1234) + 3*(x ^ 0x5a), evaluated independently. */
    const word expected[] = {23041UL, 23711UL, 24365UL};
    unsigned int index;
    for (index = 0; index != 3; ++index) {
        if (abi_dynamic_stack_arguments(abi_inputs[index]) != expected[index])
            return 17;
    }
    return 42;
}

#elif TEST_CASE == 10
volatile word abi_inputs[] = {3, 17, 29};

NOINLINE word abi_realigned_live_values(word value)
{
    volatile word spill[32] __attribute__((aligned(64)));
    word index = value & 15UL;
    spill[index] = value + 0x11UL;
    spill[index + 16] = value ^ 0x123UL;
    /* Separate volatile loads keep enough independent values to force spills. */
    word a = spill[index] + 1;
    word b = spill[index + 16] + 2;
    word c = spill[index] + 3;
    word d = spill[index + 16] + 4;
    word e = spill[index] + 5;
    word f = spill[index + 16] + 6;
    word g = spill[index] + 7;
    word h = spill[index + 16] + 8;
    word i = spill[index] + 9;
    word j = spill[index + 16] + 10;
    word k = spill[index] + 11;
    word l = spill[index + 16] + 12;
    /* Register arguments isolate realigned spill slots from outgoing stack args. */
    word first = abi_leaf(value + 1);
    word second = abi_leaf(value + 2);
    return (a ^ first) + 2*(b ^ second) + 3*(c ^ first) + 4*(d ^ second) +
           5*(e ^ first) + 6*(f ^ second) + 7*(g ^ first) + 8*(h ^ second) +
           9*(i ^ first) + 10*(j ^ second) + 11*(k ^ first) + 12*(l ^ second) +
           spill[index] + spill[index + 16];
}

int main(void)
{
    /* Weighted XORs of x+17+odd or (x^291)+even with 3*x+8 or 3*x+11. */
    const word expected[] = {13826UL, 11998UL, 16510UL};
    unsigned int index;
    for (index = 0; index != 3; ++index) {
        if (abi_realigned_live_values(abi_inputs[index]) != expected[index])
            return 17;
    }
    return 42;
}

#elif TEST_CASE == 11
volatile word abi_inputs[] = {1, 4, 7, 12};
volatile word abi_signature_choices[] = {0, 1, 1, 0};
volatile word abi_signature_calls;

/* Unprotected callees may overwrite both caller-saved signature registers. */
NOINLINE word abi_signature_clobber(word value)
{
#if defined(__riscv)
    __asm__ volatile ("li t0, 123\n\tli t4, 456" : : : "t0", "t4", "memory");
#endif
    abi_signature_calls += 1;
    return 5*value + 7;
}

NOINLINE word abi_signature_join_calls(word value, word choice)
{
    word first = abi_signature_clobber(value + 1);
    word result;
    if ((choice & 1UL) != 0) {
        result = abi_signature_clobber(first + 3);
        result += value ^ 0x15UL;
    } else {
        result = abi_signature_clobber(first ^ 0x35UL);
        result ^= value + 0x27UL;
    }
    /* Both predecessors reach this join after a signature-clobbering call. */
    volatile word joined = result;
    word last = abi_signature_clobber(joined + 11);
    return last + joined + value;
}

int main(void)
{
    /* Independent literals include both branch expressions and all three calls. */
    const word expected[] = {945UL, 1260UL, 1719UL, 3596UL};
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int index;
        for (index = 0; index != 4; ++index) {
            if (abi_signature_join_calls(abi_inputs[index],
                                         abi_signature_choices[index]) !=
                expected[index])
                return 17;
        }
    }
    return abi_signature_calls == 24UL ? 42 : 17;
}

#else
#error "Unknown call ABI TEST_CASE"
#endif
