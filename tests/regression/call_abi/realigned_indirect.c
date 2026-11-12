/* Both realigned VLA frames share a known protection contract at an indirect call. */
#define NOINLINE __attribute__((noinline))
typedef unsigned long word;

NOINLINE word indirect_bp_leaf(word value, word count)
{
    volatile word fixed[9] __attribute__((aligned(64)));
    volatile word dynamic[count] __attribute__((aligned(64)));
    word index;
    for (index = 0; index != 9; ++index)
        fixed[index] = value + 3*index + 1;
    for (index = 0; index != count; ++index)
        dynamic[index] = 2*value + 5*index + 7;
    return fixed[3] + fixed[8] + dynamic[0] + dynamic[count - 1];
}

static word (* volatile indirect_bp_target)(word, word) = indirect_bp_leaf;

NOINLINE word indirect_bp_owner(word value, word count)
{
    volatile word fixed[17] __attribute__((aligned(64)));
    volatile word dynamic[count] __attribute__((aligned(64)));
    word index;
    for (index = 0; index != 17; ++index)
        fixed[index] = value + 2*index + 3;
    for (index = 0; index != count; ++index)
        dynamic[index] = 3*value + 4*index + 9;
    /* This sole call has no direct target for early frame reservation to inspect. */
    word result = indirect_bp_target(value + 5, count + 1);
    return result + fixed[7] + fixed[16] + dynamic[0] + dynamic[count - 1];
}

volatile word indirect_bp_values[] = {2, 7, 13};
volatile word indirect_bp_counts[] = {3, 11, 19};

int main(void)
{
    /* 14*value + 9*count + 145, evaluated independently. */
    const word expected[] = {200UL, 342UL, 498UL};
    unsigned int round;
    for (round = 0; round != 2; ++round) {
        unsigned int index;
        for (index = 0; index != 3; ++index) {
            if (indirect_bp_owner(indirect_bp_values[index],
                                  indirect_bp_counts[index]) != expected[index])
                return 17;
        }
    }
    return 42;
}
