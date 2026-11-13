#include "bit_patterns.h"

extern volatile fp_representation fp_probe_primary;
fp_value fp_probe_sink;

NOINLINE void fp_bit_check_probe(fp_value value)
{
    fp_probe_sink = value;
}

/* These helpers are deliberately outside the protection selection. No opaque
   inline assembly occurs in protected code. Seed existing flags so a passing
   comparison must neither raise invalid for an sNaN nor clear prior flags. */
static NOINLINE void seed_flags(void)
{
    __asm__ volatile("fsflags %0" : : "r"(9));
}

static NOINLINE int flags_unchanged(void)
{
    unsigned flags;
    __asm__ volatile("frflags %0" : "=r"(flags));
    return flags == 9;
}

int main(void)
{
    seed_flags();
    fp_bit_check_probe(fp_probe_primary.value);
    return flags_unchanged() ? 42 : 17;
}
