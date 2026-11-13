#include "rounding.h"

/* Separate volatile loads and a separate translation unit retain one real
   target FP addition. RISC-V's dynamic rounding operand consumes shared FRM;
   REPAIR must rename duplicated data registers while retaining that input. */
NOINLINE round_value repair_round_add(void)
{
    round_value first = round_first;
    round_value second = round_second;
    return first + second;
}

NOINLINE round_value repair_round_bridge(void)
{
    return repair_round_add();
}
