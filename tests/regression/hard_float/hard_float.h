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
#else
#error "Unknown hard-float TEST_CASE"
#endif

#endif
