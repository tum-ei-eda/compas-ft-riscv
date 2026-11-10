/* Exact, fault-free floating-point calling-convention fixtures. */
#ifndef COMPAS_REGRESSION_HARD_FLOAT_H
#define COMPAS_REGRESSION_HARD_FLOAT_H

#ifndef TEST_CASE
#error "Select a hard-float scenario with TEST_CASE"
#endif

#define NOINLINE __attribute__((noinline))
typedef unsigned long word;
typedef unsigned long long wide;

#if TEST_CASE == 1
NOINLINE float fp_float_leaf(float first, float second);
#elif TEST_CASE == 2
NOINLINE double fp_double_leaf(double first, double second);
#elif TEST_CASE == 3
NOINLINE float fp_mixed_float_leaf(float first, float second, word value);
#elif TEST_CASE == 4
NOINLINE double fp_mixed_double_leaf(double first, double second, word value);
#elif TEST_CASE == 5
NOINLINE float fp_eight_float_leaf(float first, float second, float third, float fourth,
                                   float fifth, float sixth, float seventh, float eighth);
#elif TEST_CASE == 6
NOINLINE double fp_eight_double_leaf(double first, double second, double third, double fourth,
                                     double fifth, double sixth, double seventh, double eighth);
#else
#error "Unknown hard-float TEST_CASE"
#endif

#endif
