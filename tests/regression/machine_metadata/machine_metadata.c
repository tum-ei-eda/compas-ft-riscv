/* Metadata checks also execute these functions against literal oracles. */
#define NOINLINE __attribute__((noinline))
typedef unsigned long word;

volatile unsigned int metadata_global[4] __attribute__((aligned(64))) =
    {11, 13, 17, 19};
volatile word metadata_input = 3;
const unsigned int metadata_constant[4] = {2, 5, 7, 23};
unsigned int metadata_atomic = 29;
unsigned int metadata_plain;

NOINLINE word metadata_memory(word a, word b, word c, word d, word e,
                             word f, word g, word h, word i)
{
    volatile unsigned int local[3];
    local[0] = metadata_global[1] + a;
    local[1] = b + c + d + e + f + g + h + i;
    metadata_global[2] = local[0] + local[1];
    unsigned int atomic = __atomic_load_n(&metadata_atomic, __ATOMIC_RELAXED);
    __atomic_store_n(&metadata_atomic, atomic + 1, __ATOMIC_RELAXED);
    metadata_plain = a * 7 + i;
    return metadata_global[2] + local[0] + local[1] +
           metadata_constant[a & 3] + atomic;
}

NOINLINE word metadata_stack(word a, word b, word c, word d, word e,
                            word f, word g, word h, word i)
{
    return a + b + c + d + e + f + g + h + 3*i;
}

NOINLINE word metadata_integer_leaf(word value)
{
    return value * 3 + 5;
}

word (*volatile metadata_integer_target)(word) = metadata_integer_leaf;

NOINLINE word metadata_indirect(word value)
{
    word live = value ^ 0x1234UL;
    word result = metadata_integer_target(value + 1);
    return result + live;
}

#ifdef METADATA_FLOAT
NOINLINE double metadata_float_leaf(word value, double input)
{
    return input * 2.0 + (double)value;
}

double (*volatile metadata_float_target)(word, double) = metadata_float_leaf;

NOINLINE double metadata_float_indirect(word value)
{
    double live = (double)value + 0.5;
    double result = metadata_float_target(value + 1, live);
    return result + live;
}
#endif

int main(void)
{
    /* 2*((13+3)+(2+3+4+5+6+7+8+9)) + 23 + 29 = 172. */
    if (metadata_memory(metadata_input, 2, 3, 4, 5, 6, 7, 8, 9) != 172 ||
        metadata_global[2] != 60 || metadata_global[1] != 13 ||
        metadata_atomic != 30 || metadata_plain != 30)
        return 17;
    if (metadata_stack(1, 2, 3, 4, 5, 6, 7, 8, 9) != 63)
        return 20;
    /* (3*4+5) + (3^0x1234) = 4680. */
    if (metadata_indirect(metadata_input) != 4680)
        return 18;
#ifdef METADATA_FLOAT
    /* 2*3.5 + 4 + 3.5 = 14.5, all operations exactly representable. */
    if (metadata_float_indirect(metadata_input) != 14.5)
        return 19;
#endif
    return 42;
}
