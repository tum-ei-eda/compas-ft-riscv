/* Inherited pointers forwarded by genuine sibling-call candidates. */
#define NOINLINE __attribute__((noinline))
typedef unsigned long word;

#ifndef MERGED_POINTERS
#define MERGED_POINTERS 0
#endif
#ifndef STACK_POINTERS
#define STACK_POINTERS 0
#endif

volatile int pointer_tail_inputs[] = {2, 5, 9};
int pointer_tail_left[] = {4, 9, 15, 22, 30, 39, 49, 60, 72, 85};
int pointer_tail_right[] = {7, 12, 18, 25, 33, 42, 52, 63, 75, 88};

NOINLINE int pointer_tail_leaf(const int *left, const int *right, word token)
{
    volatile int saved[3] = {(int)token + 1, (int)token + 3,
                             (int)token + 5};
    return 3*left[0] + 5*left[2] + 7*right[1] + 11*right[3] +
           saved[0] + 2*saved[1] + 3*saved[2];
}

#if STACK_POINTERS
#define PREFIX word a0, word a1, word a2, word a3, word a4, word a5, \
               word a6, word a7,
#define PREFIX_SUM (a0 + 2*a1 + 3*a2 + 4*a3 + 5*a4 + 6*a5 + 7*a6 + 8*a7)
#else
#define PREFIX
#define PREFIX_SUM 0
#endif

NOINLINE int pointer_tail_middle(PREFIX const int *left, const int *right,
                                 word selector)
{
    volatile int saved[7];
    for (int index = 0; index != 7; ++index)
        saved[index] = (int)selector + 2*index + 1;
    const int *next_left = left + 1;
    const int *next_right = right + 2;
#if MERGED_POINTERS
    if (selector & 1)
        next_left = right + 1;
    if (selector & 2)
        next_right = pointer_tail_right + 2;
#endif
    word token = PREFIX_SUM;
    for (int index = 0; index != 7; ++index)
        token += (word)((index + 1)*saved[index]);
    /* No use follows this call: O2 must produce input tail IR/PseudoTAIL. */
    return pointer_tail_leaf(next_right, next_left, token);
}

NOINLINE int pointer_tail_owner(int input)
{
    volatile int local_left[10], local_right[10];
    for (int index = 0; index != 10; ++index) {
        local_left[index] = 2*input + 3*index + 1;
        local_right[index] = 5*input + 7*index + 2;
    }
#if STACK_POINTERS
#define ARGUMENTS (word)(input + 11), (word)(input + 12), \
                  (word)(input + 13), (word)(input + 14), \
                  (word)(input + 15), (word)(input + 16), \
                  (word)(input + 17), (word)(input + 18),
#else
#define ARGUMENTS
#endif
#define FORWARD(left, right, select) \
    pointer_tail_middle(ARGUMENTS left, right, (word)(select))
    int first = FORWARD((const int *)local_left + 1,
                        pointer_tail_right + 1, input);
    int second = FORWARD(pointer_tail_left + 1,
                         (const int *)local_right + 1, input + 1);
    int third = FORWARD((const int *)local_left,
                        (const int *)local_right, input + 2);
    int fourth = FORWARD(pointer_tail_left, pointer_tail_right, input + 3);
#undef FORWARD
    return first + 2*second + 3*third + 5*fourth +
           local_left[9] + 3*local_right[9];
}

int main(void)
{
    /* Literal tables expand all four calls independently of the tested code. */
#if STACK_POINTERS
    static const int expected[] = {74000, 87755, 106095};
#elif MERGED_POINTERS
    static const int expected[] = {32328, 39415, 47955};
#else
    static const int expected[] = {32024, 38651, 47487};
#endif
    for (int repeat = 0; repeat != 2; ++repeat)
        for (int index = 0; index != 3; ++index)
            if (pointer_tail_owner(pointer_tail_inputs[index]) != expected[index])
                return 17;
    return 42;
}
