/* Pure C ABI checks for per-function DMR save/restore fallback. */
typedef unsigned long word;
#define NOINLINE __attribute__((noinline))
word dmr_helper(word value);
word dmr_twelve_leaf(word, word, word, word, word, word,
                           word, word, word, word, word, word);
volatile word dmr_values[] = {2, 7, 19};
volatile word dmr_counts[] = {3, 11, 19};

/* The same module must retain actual GNU helpers in this ordinary function. */
NOINLINE word dmr_control(word value)
{
    return 2*value + 9;
}

#if TEST_CASE == 1
#define OWNER dmr_leaf
NOINLINE word OWNER(word value)
{
    return 5*value + 7;
}
#elif TEST_CASE == 2
#define OWNER dmr_repeated_calls
NOINLINE word OWNER(word value)
{
    word live = (value ^ 53UL) + 11;
    word first = dmr_helper(value + 1);
    word second = dmr_helper(value + 3);
    return first + 2*second + live;
}
#elif TEST_CASE == 3
#define OWNER dmr_stack_arguments
NOINLINE word OWNER(word value)
{
    volatile word live = value ^ 85UL;
    word result = dmr_twelve_leaf(value, value+1, value+2, value+3,
                                        value+4, value+5, value+6, value+7,
                                        value+8, value+9, value+10, value+11);
    return result + live;
}
#elif TEST_CASE == 4 || TEST_CASE == 5
#if TEST_CASE == 4
#define OWNER dmr_dynamic_frame
NOINLINE word OWNER(word value, word count)
{
    volatile word dynamic[count];
#else
#define OWNER dmr_realigned_frame
NOINLINE word OWNER(word value, word count)
{
    volatile word fixed[7] __attribute__((aligned(64)));
    volatile word dynamic[count] __attribute__((aligned(64)));
    word fixed_index;
    for (fixed_index = 0; fixed_index != 7; ++fixed_index)
        fixed[fixed_index] = value + 2*fixed_index + 5;
#endif
    word index;
    for (index = 0; index != count; ++index)
        dynamic[index] = value + 3*index + 1;
    word result = dmr_twelve_leaf(value, value+1, value+2, value+3,
                                        value+4, value+5, value+6, value+7,
                                        value+8, value+9, value+10, value+11);
    for (index = 0; index != count; ++index)
        result += (index + 1) * dynamic[index];
#if TEST_CASE == 5
    for (fixed_index = 0; fixed_index != 7; ++fixed_index)
        result += (fixed_index + 1) * fixed[fixed_index];
#endif
    return result;
}
#elif TEST_CASE == 6
#define OWNER dmr_return_paths
NOINLINE word OWNER(word value)
{
    if (value == 2)
        return dmr_helper(value) + 7;
    if (value < 10)
        return 2*dmr_helper(value + 1);
    return dmr_helper(value - 1) - 3;
}
#elif TEST_CASE == 7
#define OWNER dmr_cold_branch
NOINLINE word OWNER(word value)
{
    if (__builtin_expect((value & 1UL) == 0, 1))
        return value + 17;
    return dmr_helper(value + 1) + 13;
}
#else
#error "Choose TEST_CASE 1-7"
#endif

int main(void)
{
#if TEST_CASE == 1
    const word expected[] = {17UL, 42UL, 102UL};
#elif TEST_CASE == 2
    const word expected[] = {120UL, 160UL, 256UL};
#elif TEST_CASE == 3
    /* 78*x+572+(x^85) for x=2,7,19. */
    const word expected[] = {815UL, 1200UL, 2124UL};
#elif TEST_CASE == 4
    /* 78*x+572+(x+1)*n*(n+1)/2+n*(n-1)*(n+1). */
    const word expected[] = {770UL, 2966UL, 12694UL};
#elif TEST_CASE == 5
    /* Dynamic expression plus 28*x+364 from the fixed aligned array. */
    const word expected[] = {1190UL, 3526UL, 13590UL};
#elif TEST_CASE == 6
    const word expected[] = {18UL, 58UL, 56UL};
#else
    const word expected[] = {19UL, 42UL, 78UL};
#endif
    const word control_expected[] = {13UL, 23UL, 47UL};
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int index;
        for (index = 0; index != 3; ++index) {
            if (dmr_control(dmr_values[index]) != control_expected[index])
                return 17;
#if TEST_CASE == 4 || TEST_CASE == 5
            if (OWNER(dmr_values[index], dmr_counts[index]) != expected[index])
#else
            if (OWNER(dmr_values[index]) != expected[index])
#endif
                return 17;
        }
    }
    return 42;
}
