/* Bit-preserving FP calls: no arithmetic may quiet signaling NaNs. */
#ifndef COMPAS_REGRESSION_FP_BIT_PATTERNS_H
#define COMPAS_REGRESSION_FP_BIT_PATTERNS_H

#define NOINLINE __attribute__((noinline))

#ifdef FP_DOUBLE
typedef double fp_value;
typedef unsigned long long fp_encoding;
#else
typedef float fp_value;
typedef unsigned int fp_encoding;
#endif

typedef union {
    fp_value value;
    fp_encoding bits;
} fp_representation;

extern fp_value fp_pattern_leaf_sink;
NOINLINE fp_value fp_pattern_leaf(fp_value value);

#endif
