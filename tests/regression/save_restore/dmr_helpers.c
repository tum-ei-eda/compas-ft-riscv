/* Compile separately with frame pointers so ordinary functions retain helpers. */
typedef unsigned long word;
#define NOINLINE __attribute__((noinline))
NOINLINE word dmr_helper(word value)
{
    return 3*value + 5;
}
NOINLINE word dmr_twelve_leaf(word a, word b, word c, word d,
                                   word e, word f, word g, word h,
                                   word i, word j, word k, word l)
{
    return a + 2*b + 3*c + 4*d + 5*e + 6*f +
           7*g + 8*h + 9*i + 10*j + 11*k + 12*l;
}
