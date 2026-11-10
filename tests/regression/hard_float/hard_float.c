#include "hard_float.h"

#if TEST_CASE == 1 || TEST_CASE == 3 || TEST_CASE == 5
#if TEST_CASE == 5
volatile float fp_inputs[] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
#else
volatile float fp_inputs[] = {1.25f, -2.5f, 5.75f, -3.5f, 6.25f, -0.75f};
#endif

static unsigned int fp_bits(float value)
{
    union { float value; unsigned int bits; } representation = {.value = value};
    return representation.bits;
}
#else
#if TEST_CASE == 6
/* Each value is n + n*2^-30 and has nonzero lower binary64 bits. */
volatile double fp_inputs[] = {
    0x1.00000004p+0, 0x1.00000004p+1, 0x1.80000006p+1, 0x1.00000004p+2,
    0x1.40000005p+2, 0x1.80000006p+2, 0x1.c0000007p+2, 0x1.00000004p+3
};
#else
/* All six values have nonzero lower 32 bits in their IEEE binary64 encoding. */
volatile double fp_inputs[] = {
    0x1.40000004p+0, -0x1.40000008p+1, 0x1.7000000cp+2,
    -0x1.c0000004p+1, 0x1.90000004p+2, -0x1.80000004p-1
};
#endif

static wide fp_bits(double value)
{
    union { double value; wide bits; } representation = {.value = value};
    return representation.bits;
}
#endif

#if TEST_CASE == 1
NOINLINE float fp_float_caller(float first, float second, float third)
{
    float left = fp_float_leaf(first, second);
    float right = fp_float_leaf(second, third);
    return ((left + right) + (first - second)) + third;
}

int main(void)
{
    /* 3*a + 2*b + 2*c is exactly 10.25 and 0.5 for the two input triples. */
    return fp_bits(fp_float_caller(fp_inputs[0], fp_inputs[1], fp_inputs[2])) == 0x41240000U &&
           fp_bits(fp_float_caller(fp_inputs[3], fp_inputs[4], fp_inputs[5])) == 0x3f000000U ? 42 : 17;
}
#elif TEST_CASE == 2
NOINLINE double fp_double_caller(double first, double second, double third)
{
    double left = fp_double_leaf(first, second);
    double right = fp_double_leaf(second, third);
    return ((left + right) + (first - second)) + third;
}

int main(void)
{
    /* Exact results: 10.25 + 19*2^-30 and 0.5 + 2^-30. */
    return fp_bits(fp_double_caller(fp_inputs[0], fp_inputs[1], fp_inputs[2])) == 0x4024800000980000ULL &&
           fp_bits(fp_double_caller(fp_inputs[3], fp_inputs[4], fp_inputs[5])) == 0x3fe0000000800000ULL ? 42 : 17;
}
#elif TEST_CASE == 3
volatile word fp_integer_inputs[] = {3, 10};

NOINLINE word fp_mixed_float_caller(float first, float second, word value)
{
    word sentinel = value ^ 0x1357UL;
    float left = fp_mixed_float_leaf(first, second, value);
    float right = fp_mixed_float_leaf(second, first, value + 1);
    return ((word)fp_bits((left + right) + (first - second)) ^ sentinel) + value;
}

int main(void)
{
    /* The FP results are exactly 7 and 3.5 before combination with the sentinel. */
    return fp_mixed_float_caller(fp_inputs[0], fp_inputs[1], fp_integer_inputs[0]) == 0x40e01357UL &&
           fp_mixed_float_caller(fp_inputs[3], fp_inputs[4], fp_integer_inputs[1]) == 0x40601367UL ? 42 : 17;
}
#elif TEST_CASE == 4
volatile word fp_integer_inputs[] = {3, 10};

NOINLINE wide fp_mixed_double_caller(double first, double second, word value)
{
    word sentinel = value ^ 0x1357UL;
    double left = fp_mixed_double_leaf(first, second, value);
    double right = fp_mixed_double_leaf(second, first, value + 1);
    return (fp_bits((left + right) + (first - second)) ^ (wide)sentinel) + value;
}

int main(void)
{
    /* The FP results are exactly 7 - 2^-28 and 3.5 before adding the sentinel. */
    return fp_mixed_double_caller(fp_inputs[0], fp_inputs[1], fp_integer_inputs[0]) == 0x401bffffffc01357ULL &&
           fp_mixed_double_caller(fp_inputs[3], fp_inputs[4], fp_integer_inputs[1]) == 0x400c000000001367ULL ? 42 : 17;
}
#elif TEST_CASE == 5
NOINLINE float fp_eight_float_caller(float first, float second, float third, float fourth,
                                    float fifth, float sixth, float seventh, float eighth)
{
    float result = fp_eight_float_leaf(first, second, third, fourth,
                                      fifth, sixth, seventh, eighth);
    /* Keep the four high argument values live across the unprotected call. */
    return (((result + fifth) + sixth) + seventh) + eighth;
}

int main(void)
{
    /* Weighted sums are 204 and 120; the retained terms add 26 and 10. */
    return fp_bits(fp_eight_float_caller(fp_inputs[0], fp_inputs[1], fp_inputs[2], fp_inputs[3],
                                         fp_inputs[4], fp_inputs[5], fp_inputs[6], fp_inputs[7])) == 0x43660000U &&
           fp_bits(fp_eight_float_caller(fp_inputs[7], fp_inputs[6], fp_inputs[5], fp_inputs[4],
                                         fp_inputs[3], fp_inputs[2], fp_inputs[1], fp_inputs[0])) == 0x43020000U ? 42 : 17;
}
#elif TEST_CASE == 6
NOINLINE double fp_eight_double_caller(double first, double second, double third, double fourth,
                                      double fifth, double sixth, double seventh, double eighth)
{
    double result = fp_eight_double_leaf(first, second, third, fourth,
                                        fifth, sixth, seventh, eighth);
    return (((result + fifth) + sixth) + seventh) + eighth;
}

int main(void)
{
    /* Exact results: 230 + 230*2^-30 and 130 + 130*2^-30. */
    return fp_bits(fp_eight_double_caller(fp_inputs[0], fp_inputs[1], fp_inputs[2], fp_inputs[3],
                                          fp_inputs[4], fp_inputs[5], fp_inputs[6], fp_inputs[7])) == 0x406cc00000730000ULL &&
           fp_bits(fp_eight_double_caller(fp_inputs[7], fp_inputs[6], fp_inputs[5], fp_inputs[4],
                                          fp_inputs[3], fp_inputs[2], fp_inputs[1], fp_inputs[0])) == 0x4060400000410000ULL ? 42 : 17;
}
#endif
