#include "bit_patterns.h"

fp_value fp_pattern_leaf_sink;

/* Typed stores and returns preserve every input bit, including signaling NaNs.
   A separate translation unit prevents caller-side identity folding. */
NOINLINE fp_value fp_pattern_leaf(fp_value value)
{
    fp_pattern_leaf_sink = value;
    return value;
}
