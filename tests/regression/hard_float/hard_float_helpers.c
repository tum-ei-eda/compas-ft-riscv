#include "hard_float.h"

/* A separate translation unit keeps the caller from learning register usage. */
#if TEST_CASE == 1
volatile float fp_float_scale = 2.0f;

NOINLINE float fp_float_leaf(float first, float second)
{
    return first * fp_float_scale + second;
}
#elif TEST_CASE == 2
volatile double fp_double_scale = 2.0;

NOINLINE double fp_double_leaf(double first, double second)
{
    return first * fp_double_scale + second;
}
#elif TEST_CASE == 3
volatile float fp_float_scale = 2.0f;

NOINLINE float fp_mixed_float_leaf(float first, float second, word value)
{
    return (first * fp_float_scale + second) + (float)(value & 7UL);
}
#elif TEST_CASE == 4
volatile double fp_double_scale = 2.0;

NOINLINE double fp_mixed_double_leaf(double first, double second, word value)
{
    return (first * fp_double_scale + second) + (double)(value & 7UL);
}
#endif
