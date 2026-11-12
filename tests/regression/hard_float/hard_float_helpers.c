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
#elif TEST_CASE == 5 || TEST_CASE == 6
#if TEST_CASE == 5
#define FP_TYPE float
#define FP_EIGHT_LEAF fp_eight_float_leaf
#else
#define FP_TYPE double
#define FP_EIGHT_LEAF fp_eight_double_leaf
#endif

NOINLINE FP_TYPE FP_EIGHT_LEAF(FP_TYPE first, FP_TYPE second, FP_TYPE third, FP_TYPE fourth,
                              FP_TYPE fifth, FP_TYPE sixth, FP_TYPE seventh, FP_TYPE eighth)
{
    FP_TYPE result = first + 2*second + 3*third + 4*fourth +
                    5*fifth + 6*sixth + 7*seventh + 8*eighth;
#ifdef __riscv
    /* These are caller-clobbered physical registers in both hard-float ABIs.
       They hold COMPAS shadows in the protected caller, but this helper is
       deliberately unprotected. Keep this assembly out of protected code. */
    __asm__ volatile("fmv.w.x ft7, zero\n\t"
                     "fmv.w.x ft8, zero\n\t"
                     "fmv.w.x ft9, zero\n\t"
                     "fmv.w.x ft10, zero\n\t"
                     "fmv.w.x ft11, zero"
                     : : : "ft7", "ft8", "ft9", "ft10", "ft11");
#endif
    return result;
}
#endif
