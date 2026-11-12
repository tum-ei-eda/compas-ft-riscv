/* Literal arithmetic and side-effect oracles for direct object generation. */
extern unsigned identity(unsigned);

volatile unsigned codegen_inputs[] = {0, 1, 7, 123};
volatile unsigned codegen_seen;

__attribute__((noinline)) unsigned codegen_calculate(unsigned value)
{
    volatile unsigned slots[] = {value + 7, value ^ 0x53, value << 2};
    codegen_seen += value;
    return slots[0] + 3 * slots[1] + slots[2];
}

int main(void)
{
    const unsigned expected[] = {256, 258, 294, 742};
    const unsigned traces[][4] = {{0, 1, 8, 131}, {131, 132, 139, 262}};
    for (unsigned round = 0; round < 2; ++round)
        for (unsigned index = 0; index < 4; ++index) {
            unsigned value = codegen_inputs[index];
            if (identity(value) != value ||
                codegen_calculate(value) != expected[index] ||
                codegen_seen != traces[round][index])
                return 17;
        }
    return 42;
}
