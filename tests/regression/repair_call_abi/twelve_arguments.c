/* Four outgoing stack arguments keep this independent of spill-slot ordering. */
typedef unsigned long word;
#define NOINLINE __attribute__((noinline))

volatile word repair_inputs[] = {1, 7, 19};

NOINLINE word repair_twelve_leaf(word a, word b, word c, word d,
                                word e, word f, word g, word h,
                                word i, word j, word k, word l)
{
    return a + 2*b + 3*c + 4*d + 5*e + 6*f +
           7*g + 8*h + 9*i + 10*j + 11*k + 12*l;
}

NOINLINE word repair_twelve_caller(word value)
{
    volatile word sentinel = value ^ 0x55UL;
    word result = repair_twelve_leaf(value, value + 1, value + 2, value + 3,
                                    value + 4, value + 5, value + 6, value + 7,
                                    value + 8, value + 9, value + 10, value + 11);
    return result + sentinel;
}

int main(void)
{
    /* Leaf: 78*x+572 gives 650, 1118, 2054. Add x^85: 734, 1200, 2124. */
    const word expected[] = {734UL, 1200UL, 2124UL};
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int index;
        for (index = 0; index != 3; ++index) {
            if (repair_twelve_caller(repair_inputs[index]) != expected[index])
                return 17;
        }
    }
    return 42;
}
