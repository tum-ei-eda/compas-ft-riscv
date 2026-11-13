#include "rounding.h"

/* Deliberately unprotected helpers: changing architectural FP control state
   inside a protected function is a separate contract. */
NOINLINE unsigned round_set_mode(unsigned mode)
{
    unsigned previous;
    __asm__ volatile("fsrm %0, %1" : "=r"(previous) : "r"(mode) : "memory");
    return previous;
}

NOINLINE unsigned round_get_mode(void)
{
    unsigned mode;
    __asm__ volatile("frrm %0" : "=r"(mode) : : "memory");
    return mode;
}
