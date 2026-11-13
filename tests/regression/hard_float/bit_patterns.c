#include "bit_patterns.h"

/* Volatile inputs retain FP loads and typed arguments across translation units.
   Literal integer encodings are independent of the hardened comparison. */
static volatile fp_representation inputs[] = {
#ifdef FP_DOUBLE
    {.bits = 0x7ff8000000000001ULL}, /* positive quiet NaN, low payload bit */
    {.bits = 0xfff8000000000001ULL}, /* negative quiet NaN */
    {.bits = 0x7ff8123456789abcULL}, /* quiet NaN with a distinct payload */
    {.bits = 0x7ff0000000000001ULL}, /* positive signaling NaN */
    {.bits = 0xfff0000012345678ULL}, /* negative signaling NaN */
    {.bits = 0x0000000000000000ULL}, /* positive zero */
    {.bits = 0x8000000000000000ULL}, /* negative zero */
    {.bits = 0x7ff0000000000000ULL}, /* positive infinity */
    {.bits = 0xfff0000000000000ULL}, /* negative infinity */
    {.bits = 0x0000000000000001ULL}, /* least positive subnormal */
    {.bits = 0x8000000000000001ULL}, /* least negative subnormal */
    {.bits = 0x000fffffffffffffULL}, /* greatest positive subnormal */
    {.bits = 0x800fffffffffffffULL}, /* greatest negative subnormal */
    {.bits = 0x0010000000000000ULL}, /* least positive normal */
    {.bits = 0x3ff0000000000001ULL}, /* finite values differing only in low bits */
    {.bits = 0x3ff0000000000002ULL},
    {.bits = 0xbff0000012345678ULL},
    {.bits = 0x7fefffffffffffffULL}  /* greatest positive finite value */
#else
    {.bits = 0x7fc00001U}, /* positive quiet NaN, low payload bit */
    {.bits = 0xffc00001U}, /* negative quiet NaN */
    {.bits = 0x7fc12345U}, /* quiet NaN with a distinct payload */
    {.bits = 0x7f800001U}, /* positive signaling NaN */
    {.bits = 0xff812345U}, /* negative signaling NaN */
    {.bits = 0x00000000U}, /* positive zero */
    {.bits = 0x80000000U}, /* negative zero */
    {.bits = 0x7f800000U}, /* positive infinity */
    {.bits = 0xff800000U}, /* negative infinity */
    {.bits = 0x00000001U}, /* least positive subnormal */
    {.bits = 0x80000001U}, /* least negative subnormal */
    {.bits = 0x007fffffU}, /* greatest positive subnormal */
    {.bits = 0x807fffffU}, /* greatest negative subnormal */
    {.bits = 0x00800000U}, /* least positive normal */
    {.bits = 0x3f800001U}, /* finite values differing only in low bits */
    {.bits = 0x3f800002U},
    {.bits = 0xbf812345U},
    {.bits = 0x7f7fffffU}  /* greatest positive finite value */
#endif
};

static fp_value caller_sink;

NOINLINE fp_value fp_pattern_caller(fp_value value)
{
#ifdef FP_PATTERN_TAIL
    return fp_pattern_leaf(value);
#else
    fp_value first = fp_pattern_leaf(value);
    caller_sink = first;
    return fp_pattern_leaf(first);
#endif
}

int main(void)
{
    for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i) {
        fp_representation input = inputs[i];
        fp_representation result = {.value = fp_pattern_caller(input.value)};
        fp_representation leaf_store = {.value = fp_pattern_leaf_sink};
#ifdef FP_PATTERN_TAIL
        if (result.bits != input.bits || leaf_store.bits != input.bits)
#else
        fp_representation caller_store = {.value = caller_sink};
        if (result.bits != input.bits || leaf_store.bits != input.bits ||
            caller_store.bits != input.bits)
#endif
            return 17;
    }
    return 42;
}
