/* Fault-free checks for PC-relative global addresses and their shadow values. */
#ifndef TEST_CASE
#error "Select a PC-relative address scenario with TEST_CASE"
#endif

#define NOINLINE __attribute__((noinline))

#if TEST_CASE == 1
volatile int pcrel_inputs[] = {-4, 0, 3, 9};
volatile int pcrel_accumulator = 19;
volatile unsigned int pcrel_effect = 5;

NOINLINE int pcrel_global_update(int delta)
{
    int previous = pcrel_accumulator;
    pcrel_accumulator = previous + delta * 3;
    pcrel_effect ^= (unsigned int)(delta + 16);
    return pcrel_accumulator * 2 + previous;
}

int main(void)
{
    const int results[] = {33, 21, 39, 102};
    const int accumulators[] = {7, 7, 16, 43};
    const unsigned int effects[] = {9, 25, 10, 19};
    unsigned int index;
    for (index = 0; index != 4; ++index) {
        if (pcrel_global_update(pcrel_inputs[index]) != results[index] ||
            pcrel_accumulator != accumulators[index] ||
            pcrel_effect != effects[index])
            return 17;
    }
    return 42;
}

#elif TEST_CASE == 2
volatile int pcrel_inputs[] = {-3, -1, 0, 2, 3};
volatile int pcrel_values[] = {3, 5, 11, 17, 23, 31, 41, 47, 59};

NOINLINE int pcrel_array_window(int offset)
{
    volatile int *base = &pcrel_values[4];
    return base[offset - 1] + 3 * base[offset] + 5 * base[offset + 1];
}

int main(void)
{
    const int results[] = {73, 177, 241, 389, 477};
    unsigned int index;
    for (index = 0; index != 5; ++index) {
        if (pcrel_array_window(pcrel_inputs[index]) != results[index])
            return 17;
    }
    return 42;
}

#elif TEST_CASE == 3
volatile int pcrel_indices[] = {0, 3, 1, 0};
volatile int pcrel_increments[] = {5, -7, 9, -3};
volatile int pcrel_slots[] = {7, 13, 29, 43, 61};

NOINLINE int pcrel_update_slot(volatile int *slot, int increment)
{
    int previous = *slot;
    *slot = previous + increment;
    return previous * 3 + *slot;
}

NOINLINE int pcrel_address_helper(int index, int increment)
{
    volatile int *slot = &pcrel_slots[index];
    int result = pcrel_update_slot(slot, increment);
    return result + *slot + pcrel_slots[4];
}

int main(void)
{
    const int results[] = {106, 262, 144, 115};
    const int slots[] = {9, 22, 29, 36, 61};
    unsigned int index;
    for (index = 0; index != 4; ++index) {
        if (pcrel_address_helper(pcrel_indices[index], pcrel_increments[index]) !=
            results[index])
            return 17;
    }
    for (index = 0; index != 5; ++index) {
        if (pcrel_slots[index] != slots[index])
            return 17;
    }
    return 42;
}

#elif TEST_CASE == 4
volatile int pcrel_inputs[] = {0, 1, 2, 3, -2};
volatile int pcrel_left[] = {11, 17, 23};
volatile int pcrel_right[] = {31, 37, 43};
volatile unsigned int pcrel_branch_effect;

NOINLINE int pcrel_branch_bases(int selector)
{
    volatile int *base;
    volatile int *other;
    if (selector & 1) {
        base = pcrel_right;
        other = pcrel_left;
    } else {
        base = pcrel_left;
        other = pcrel_right;
    }

    int value = base[1] + selector;
    if (selector > 0)
        base[2] = base[2] + selector;
    else
        base[0] = base[0] - selector;

    pcrel_branch_effect += (unsigned int)(base[0] + base[2]);
    return value + base[0] + base[2] + other[1];
}

int main(void)
{
    const int results[] = {88, 130, 92, 135, 90};
    const unsigned int effects[] = {34, 109, 145, 223, 261};
    const int left[] = {13, 17, 25};
    const int right[] = {31, 37, 47};
    unsigned int index;
    for (index = 0; index != 5; ++index) {
        if (pcrel_branch_bases(pcrel_inputs[index]) != results[index] ||
            pcrel_branch_effect != effects[index])
            return 17;
    }
    for (index = 0; index != 3; ++index) {
        if (pcrel_left[index] != left[index] || pcrel_right[index] != right[index])
            return 17;
    }
    return 42;
}

#else
#error "Unknown PC-relative address TEST_CASE"
#endif
