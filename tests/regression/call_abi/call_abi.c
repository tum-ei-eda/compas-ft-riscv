/* Fault-free RISC-V call ABI checks. The independent oracle is in main(). */
#ifndef TEST_CASE
#error "Select a call ABI scenario with TEST_CASE"
#endif

#define NOINLINE __attribute__((noinline))
typedef unsigned long word;
typedef unsigned long long wide;

#if TEST_CASE == 4 || (TEST_CASE >= 7 && TEST_CASE <= 9) || \
    TEST_CASE == 14 || TEST_CASE == 15 || TEST_CASE == 19
NOINLINE word abi_ten_args(word a, word b, word c, word d, word e,
                          word f, word g, word h, word i, word j)
{
    return a + 2*b + 3*c + 4*d + 5*e + 6*f + 7*g + 8*h + 9*i + 10*j;
}
#endif

#if (TEST_CASE >= 1 && TEST_CASE <= 3) || TEST_CASE == 10 || TEST_CASE == 13
NOINLINE word abi_leaf(word value)
{
    return value * 3 + 5;
}
#endif

#if TEST_CASE == 6 || TEST_CASE == 13 || TEST_CASE == 19
/* Intentionally unprotected: inspect SP without duplicating inline assembly. */
NOINLINE word abi_stack_pointer(void)
{
#if defined(__riscv)
    word pointer;
    __asm__ volatile ("mv %0, sp" : "=r" (pointer) : : "memory");
    return pointer;
#else
    /* Host builds check the arithmetic; RISC-V runs check the actual SP. */
    return 0;
#endif
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

#elif TEST_CASE == 20
volatile word abi_inputs[] = {2, 7, 10, 19};
volatile word abi_selective_trace;

/* Compiled separately: this module has no definition of the DMR-only leaf. */
word abi_selective_leaf(word value);

NOINLINE word abi_selective_caller(word value)
{
    word live = value ^ 0x2468UL;
    word first = abi_selective_leaf(value + 1);
    word second;
    if ((value & 1UL) != 0) {
        abi_selective_trace += value;
        second = abi_selective_leaf(value + 7);
    } else {
        second = abi_selective_leaf(value + 11);
        abi_selective_trace ^= second;
    }
    /* The volatile effects keep a real branch and join around these calls. */
    word third = abi_selective_leaf(value + second);
    return live + first + 2*second + third;
}

int main(void)
{
    /* (x ^ 0x2468) + 21*x + (odd ? 143 : 203), evaluated independently. */
    const word expected[] = {9567UL, 9617UL, 9727UL, 9881UL};
    const word traces[][4] = {{44UL, 51UL, 119UL, 138UL},
                             {166UL, 173UL, 233UL, 252UL}};
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int index;
        for (index = 0; index != 4; ++index) {
            if (abi_selective_caller(abi_inputs[index]) != expected[index] ||
                abi_selective_trace != traces[round][index])
                return 17;
        }
    }
    return 42;
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

#elif TEST_CASE == 9 || TEST_CASE == 14
volatile word abi_inputs[] = {1, 7, 13};

#if TEST_CASE == 14
#define ABI_FRAME_CALLER abi_large_fixed_stack_arguments
#else
#define ABI_FRAME_CALLER abi_dynamic_stack_arguments
#endif

NOINLINE word ABI_FRAME_CALLER(word value)
{
    /* Separate large fixed allocation from the original combined VLA case. */
    volatile word spill[1024];
    word fixed_index = (value & 511UL) + 1;
    word count = (value & 7UL) + 11;
#if TEST_CASE == 14
    volatile word dynamic[18];
#else
    volatile word dynamic[count];
#endif
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
#if TEST_CASE == 14
    unsigned int round;
    for (round = 0; round != 2; ++round)
#endif
    for (index = 0; index != 3; ++index) {
        if (ABI_FRAME_CALLER(abi_inputs[index]) != expected[index])
            return 17;
    }
    return 42;
}

#elif TEST_CASE == 15 || TEST_CASE == 19
volatile word abi_inputs[] = {1, 7, 13};
volatile word abi_first_counts[] = {3, 8, 17};
volatile word abi_second_counts[] = {9, 4, 21};

NOINLINE word abi_dynamic_pointer_leaf(const volatile word *array,
                                      word count, word bias)
{
    return array[0] + 3*array[count / 2] + 5*array[count - 1] + bias;
}

NOINLINE word abi_dynamic_pointer_middle(const volatile word *array,
                                        word count, word bias)
{
#if TEST_CASE == 19
    /* The noinline boundary observes the actual fixed/VLA address. */
    if (((word)array & 63UL) != 0)
        return 0;
#endif
    word leaf = abi_dynamic_pointer_leaf(array, count, bias);
    word ten = abi_ten_args(array[0], array[count - 1], bias, count,
                           bias + 2, bias + 3, bias + 4, bias + 5,
                           bias + 6, bias + 7);
    /* The incoming VLA pointer stays live across both nested calls. */
    return leaf + ten + array[count / 2];
}

#if TEST_CASE == 15
NOINLINE word abi_dynamic_small_frame(word value, word first_count,
                                     word second_count)
{
    volatile word fixed[5];
    word index;
    for (index = 0; index != 5; ++index)
        fixed[index] = value + 3*index + 7;

    volatile word first[first_count];
    for (index = 0; index != first_count; ++index)
        first[index] = value + 2*index + 5;
    word first_result = abi_dynamic_pointer_middle(first, first_count,
                                                 value + 1);

    /* Allocate another VLA while the first pointer and its contents stay live. */
    volatile word second[second_count];
    for (index = 0; index != second_count; ++index)
        second[index] = 3*value + 5*index + 11;
    word second_result = abi_dynamic_pointer_middle(second, second_count,
                                                  value + 3);
    word third_result = abi_dynamic_pointer_middle(first, first_count,
                                                 value + 5);
    word result = first_result + 2*second_result + 3*third_result;
    for (index = 0; index != 5; ++index)
        result += fixed[index] * (index + 1);
    for (index = 0; index != first_count; ++index)
        result += first[index] * (index + 1);
    for (index = 0; index != second_count; ++index)
        result += second[index] * (index + 1);
    return result;
}

int main(void)
{
    /* Middle = 2*a[0] + 4*a[n/2] + 7*a[n-1] + 49*bias + 4*n + 220.
     * These literals also include the three weighted whole-array checksums. */
    const word expected[] = {6474UL, 8400UL, 45236UL};
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int index;
        for (index = 0; index != 3; ++index) {
            if (abi_dynamic_small_frame(abi_inputs[index],
                                        abi_first_counts[index],
                                        abi_second_counts[index]) !=
                expected[index])
                return 17;
        }
    }
    return 42;
}

#else
volatile word abi_realigned_dynamic_residues;

/* Counts arrive in the ninth and tenth integer argument slots. */
NOINLINE word abi_realigned_dynamic_frame(word a, word b, word c, word d,
                                         word e, word f, word g, word h,
                                         word first_count, word second_count)
{
    volatile word fixed[33] __attribute__((aligned(64)));
    word index;
    for (index = 0; index != 33; ++index)
        fixed[index] = 2*a + 3*index + 7;

    volatile word first[first_count] __attribute__((aligned(64)));
    for (index = 0; index != first_count; ++index)
        first[index] = a + 2*index + 5;
    word first_result = abi_dynamic_pointer_middle(first, first_count, a + 1);

    /* Both arrays and the aligned fixed object remain live after allocation. */
    volatile word second[second_count] __attribute__((aligned(64)));
    for (index = 0; index != second_count; ++index)
        second[index] = 3*a + 5*index + 11;
    word second_result = abi_dynamic_pointer_middle(second, second_count,
                                                  a + 3);
    word third_result = abi_dynamic_pointer_middle(first, first_count, a + 5);
    word fixed_result = abi_dynamic_pointer_middle(fixed, 33, a + 7);
    word passed = abi_ten_args(a, b, c, d, e, f, g, h,
                              first_count, second_count);
    word result = first_result + 2*second_result + 3*third_result +
                  4*fixed_result + 5*passed;
    for (index = 0; index != 33; ++index)
        result += fixed[index] * (index + 1);
    for (index = 0; index != first_count; ++index)
        result += first[index] * (index + 1);
    for (index = 0; index != second_count; ++index)
        result += second[index] * (index + 1);
    return result;
}

/* Ordinary callers vary entry alignment without protecting the SP probe. */
NOINLINE word abi_realigned_dynamic_entry(word value, word first_count,
                                         word second_count, word pad_words)
{
    volatile word padding[pad_words];
    padding[0] = 0x12345UL;
    padding[pad_words - 1] = 0x6789UL;
    word before = abi_stack_pointer();
    word result = abi_realigned_dynamic_frame(value, value + 1, value + 2,
        value + 3, value + 4, value + 5, value + 6, value + 7,
        first_count, second_count);
    word after = abi_stack_pointer();
    if ((before & 15UL) != 0 || before != after ||
        padding[0] != 0x12345UL || padding[pad_words - 1] != 0x6789UL)
        return 0;
    abi_realigned_dynamic_residues |= 1UL << ((before & 63UL) >> 4);
    return result;
}

int main(void)
{
    /* Middle = 2*a[0]+4*a[n/2]+7*a[n-1]+49*bias+4*n+220.
     * Add four weighted middle results, 5*(36*x+168+9*n+10*m),
     * and the independent weighted checksums of all three arrays. */
    const word expected[] = {55692UL, 67115UL, 114728UL};
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int residue;
        for (residue = 0; residue != 4; ++residue) {
            word pad_words = 2 + residue * (16 / sizeof(word));
            unsigned int index;
            for (index = 0; index != 3; ++index) {
                if (abi_realigned_dynamic_entry(abi_inputs[index],
                        abi_first_counts[index], abi_second_counts[index],
                        pad_words) != expected[index])
                    return 17;
            }
        }
    }
#if defined(__riscv)
    /* The fixed outgoing call area shifts every residue by the same amount. */
    if (abi_realigned_dynamic_residues != 15UL)
        return 17;
#endif
    return 42;
}
#endif

#elif TEST_CASE == 16 || TEST_CASE == 17
volatile word abi_inputs[] = {1, 7, 13};
volatile word abi_libcall_counts[] = {3, 8, 17};

/* Keep a real variadic printf signature while avoiding a libc dependency.
 * This shim implements the literal characters and %c conversions used below. */
NOINLINE int abi_test_printf(const char *format, ...) __asm__("printf");

NOINLINE long abi_libcall_write(const char *buffer, word length)
{
#if defined(__riscv)
    register word descriptor __asm__("a0") = 1;
    register word address __asm__("a1") = (word)buffer;
    register word count __asm__("a2") = length;
    register word number __asm__("a7") = 64;
    __asm__ volatile ("ecall" : "+r" (descriptor)
                      : "r" (address), "r" (count), "r" (number) : "memory");
    return (long)descriptor;
#else
    extern long write(int, const void *, word);
    return write(1, buffer, length);
#endif
}

NOINLINE int abi_test_printf(const char *format, ...)
{
    char output[32];
    word length = 0;
    __builtin_va_list arguments;
    __builtin_va_start(arguments, format);
    while (*format != '\0') {
        if (*format == '%') {
            ++format;
            if (*format != 'c') {
                __builtin_va_end(arguments);
                return -1;
            }
            output[length++] = (unsigned char)__builtin_va_arg(arguments, int);
        } else {
            output[length++] = *format;
        }
        ++format;
    }
    __builtin_va_end(arguments);
    return abi_libcall_write(output, length) == (long)length ? (int)length : -1;
}

#if TEST_CASE == 16
#define ABI_LIBCALL_CALLER abi_libcall_stack_arguments
#else
#define ABI_LIBCALL_CALLER abi_libcall_dynamic_stack_arguments
#endif

NOINLINE word ABI_LIBCALL_CALLER(word value, word count)
{
#if defined(ABI_REALIGNED_DYNAMIC)
    volatile word fixed[7] __attribute__((aligned(64)));
    volatile word scratch[count] __attribute__((aligned(64)));
#else
    volatile word fixed[7];
#if TEST_CASE == 16
    volatile word scratch[9];
    count = 9;
#else
    volatile word scratch[count];
#endif
#endif
    word index;
    for (index = 0; index != 7; ++index)
        fixed[index] = value + 3*index + 5;
    for (index = 0; index != count; ++index)
        scratch[index] = value + 5*index + 7;
    word live = value ^ 0x1357UL;
    int first = abi_test_printf("%c%c%c%c%c%c%c%c%c%c\n",
        (int)('A' + value % 26), (int)('A' + (value + 1) % 26),
        (int)('A' + (value + 2) % 26), (int)('A' + (value + 3) % 26),
        (int)('A' + (value + 4) % 26), (int)('A' + (value + 5) % 26),
        (int)('A' + (value + 6) % 26), (int)('A' + (value + 7) % 26),
        (int)('A' + (value + 8) % 26), (int)('A' + (value + 9) % 26));
    int second = abi_test_printf("[%c%c%c%c%c%c%c%c%c%c]\n",
        (int)('a' + value % 26), (int)('a' + (value + 2) % 26),
        (int)('a' + (value + 4) % 26), (int)('a' + (value + 6) % 26),
        (int)('a' + (value + 8) % 26), (int)('a' + (value + 10) % 26),
        (int)('a' + (value + 12) % 26), (int)('a' + (value + 14) % 26),
        (int)('a' + (value + 16) % 26), (int)('a' + (value + 18) % 26));
    word result = first + 3*second + live;
    for (index = 0; index != 7; ++index)
        result += (index + 1) * fixed[index];
    for (index = 0; index != count; ++index)
        result += (index + 1) * scratch[index];
    return result;
}

int main(void)
{
    /* 50 + (28*x+476) + (x^4951)
     * + (x+7)*n*(n+1)/2 + 5*n*(n-1)*(n+1)/3. */
#if TEST_CASE == 16
    const word expected[] = {7064UL, 7496UL, 7944UL};
#else
    const word expected[] = {5592UL, 7010UL, 17064UL};
#endif
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int index;
        for (index = 0; index != 3; ++index) {
            if (ABI_LIBCALL_CALLER(abi_inputs[index],
                                   abi_libcall_counts[index]) != expected[index])
                return 17;
        }
    }
    return 42;
}

#elif TEST_CASE == 18
volatile word abi_inputs[] = {1, 7, 13};
#if defined(ABI_REALIGNED_DYNAMIC)
/* A volatile size keeps this a real VLA while preserving the literal oracle. */
volatile word abi_memcmp_count = 13;
#endif
const unsigned char abi_memcmp_reference[13] =
    {5, 8, 11, 14, 17, 20, 23, 26, 29, 32, 35, 38, 41};

NOINLINE int abi_test_memcmp(const void *left, const void *right, word count)
    __asm__("memcmp");

NOINLINE int abi_test_memcmp(const void *left, const void *right, word count)
{
    const volatile unsigned char *a = left;
    const volatile unsigned char *b = right;
    word index;
    for (index = 0; index != count; ++index) {
        if (a[index] != b[index])
            return (int)a[index] - (int)b[index];
    }
    return 0;
}

#if defined(__clang__)
__attribute__((no_builtin("memcmp")))
#endif
NOINLINE word abi_duplicated_libcall(word value)
{
#if defined(ABI_REALIGNED_DYNAMIC)
    unsigned char first[13] __attribute__((aligned(64)));
    unsigned char second[abi_memcmp_count] __attribute__((aligned(64)));
#else
    unsigned char first[13];
    unsigned char second[13];
#endif
    word index;
    for (index = 0; index != 13; ++index) {
        first[index] = (unsigned char)(3*index + 5);
        second[index] = (unsigned char)(3*index + 5);
    }
    word live = value ^ 0x315UL;
    int equal = abi_test_memcmp(first, abi_memcmp_reference, 13);
    first[value % 13] += (unsigned char)value;
    int negative = abi_test_memcmp(abi_memcmp_reference, first, 13);
    int positive = abi_test_memcmp(first, second, 13);
    /* memcmp guarantees the sign, including when LLVM folds a comparison. */
    if (equal != 0 || negative >= 0 || positive <= 0)
        return 0;
    word result = 37 + live;
    for (index = 0; index != 13; ++index)
        result += (index + 1) * (first[index] + 3*second[index]);
    return result;
}

int main(void)
{
    /* 37 + 4*2639 + x*(x%13+1) + (x^789), after checking all three signs. */
    const word expected[] = {11383UL, 11435UL, 11398UL};
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int index;
        for (index = 0; index != 3; ++index) {
            if (abi_duplicated_libcall(abi_inputs[index]) != expected[index])
                return 17;
        }
    }
    return 42;
}

#elif TEST_CASE == 10 || TEST_CASE == 13
volatile word abi_inputs[] = {3, 17, 29};

#if TEST_CASE == 13
NOINLINE word abi_array_alignment(const volatile word *array)
{
    return (word)array & 63UL;
}
#endif

NOINLINE word abi_realigned_live_values(word value)
{
    volatile word spill[32] __attribute__((aligned(64)));
    word index = value & 15UL;
#if TEST_CASE == 13
    /* The helper observes the actual address instead of folding known alignment. */
    if (abi_array_alignment(spill) != 0)
        return 0;
#endif
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

#if TEST_CASE == 13
volatile word abi_realigned_residues;

/* Keep the moving stack and its SP probe outside the protected selection. */
NOINLINE word abi_realigned_entry(word value, word pad_words)
{
    volatile word padding[pad_words];
    padding[0] = 0x12345UL;
    padding[pad_words - 1] = 0x6789UL;
    word before = abi_stack_pointer();
    word result = abi_realigned_live_values(value);
    word after = abi_stack_pointer();
    if ((before & 15UL) != 0 || before != after ||
        padding[0] != 0x12345UL || padding[pad_words - 1] != 0x6789UL)
        return 0;
    abi_realigned_residues |= 1UL << ((before & 63UL) >> 4);
    return result;
}
#endif

int main(void)
{
    /* Weighted XORs of x+17+odd or (x^291)+even with 3*x+8 or 3*x+11. */
    const word expected[] = {13826UL, 11998UL, 16510UL};
#if TEST_CASE == 13
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int residue;
        for (residue = 0; residue != 4; ++residue) {
            /* After ABI rounding, these allocate 16, 32, 48 and 64 bytes. */
            word pad_words = 2 + residue * (16 / sizeof(word));
            unsigned int index;
            for (index = 0; index != 3; ++index) {
                if (abi_realigned_entry(abi_inputs[index], pad_words) !=
                    expected[index])
                    return 17;
            }
        }
    }
#if defined(__riscv)
    /* Require every 16-byte-aligned entry residue modulo 64 to execute. */
    if (abi_realigned_residues != 15UL)
        return 17;
#endif
#else
    unsigned int index;
    for (index = 0; index != 3; ++index) {
        if (abi_realigned_live_values(abi_inputs[index]) != expected[index])
            return 17;
    }
#endif
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
