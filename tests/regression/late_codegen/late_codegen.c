/* The arithmetic and side-effect oracles are independent of machine layout. */
typedef unsigned long word;
#define NOINLINE __attribute__((noinline))

volatile word late_inputs[] = {2, 7, 10, 19};
volatile word late_trace;

NOINLINE word late_leaf(word value)
{
    late_trace += value;
    return 3 * value + 7;
}

NOINLINE word late_caller(word value)
{
    word first = late_leaf(value + 1);
    word second = late_leaf(value + 4);
    return first + 2 * second + (value ^ 0x123);
}

int main(void)
{
    const word expected[] = {355, 403, 435, 523};
    const word traces[][4] = {{9, 28, 53, 96}, {105, 124, 149, 192}};
    for (word round = 0; round < 2; ++round)
        for (word index = 0; index < 4; ++index)
            if (late_caller(late_inputs[index]) != expected[index] ||
                late_trace != traces[round][index])
                return 17;
    return 42;
}
