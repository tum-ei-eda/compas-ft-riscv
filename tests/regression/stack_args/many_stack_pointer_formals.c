/* The pointer follows 544 XLEN scalars: its outgoing ABI slot is beyond a
 * signed 12-bit store displacement on both RV32 and RV64.
 */
#define NOINLINE __attribute__((noinline))
typedef unsigned long abi_word;

#define WORD(group, lane) abi_word s##group##_##lane __attribute__((unused))
#define PARAM16(group) \
  WORD(group, 0), WORD(group, 1), WORD(group, 2), WORD(group, 3), \
  WORD(group, 4), WORD(group, 5), WORD(group, 6), WORD(group, 7), \
  WORD(group, 8), WORD(group, 9), WORD(group, 10), WORD(group, 11), \
  WORD(group, 12), WORD(group, 13), WORD(group, 14), WORD(group, 15)
#define ARG16(group) \
  16*(group)+1, 16*(group)+2, 16*(group)+3, 16*(group)+4, \
  16*(group)+5, 16*(group)+6, 16*(group)+7, 16*(group)+8, \
  16*(group)+9, 16*(group)+10, 16*(group)+11, 16*(group)+12, \
  16*(group)+13, 16*(group)+14, 16*(group)+15, 16*(group)+16
#define GROUPS(macro) \
  macro(0), macro(1), macro(2), macro(3), macro(4), macro(5), \
  macro(6), macro(7), macro(8), macro(9), macro(10), macro(11), \
  macro(12), macro(13), macro(14), macro(15), macro(16), macro(17), \
  macro(18), macro(19), macro(20), macro(21), macro(22), macro(23), \
  macro(24), macro(25), macro(26), macro(27), macro(28), macro(29), \
  macro(30), macro(31), macro(32), macro(33)

volatile int many_stack_inputs[] = {2, 7, 13};

NOINLINE int many_stack_pointer_sink(GROUPS(PARAM16), const int *pointer) {
  return (int)(s0_0 + s33_15) + pointer[1];
}

NOINLINE int many_stack_pointer_owner(int input) {
#ifdef MANY_DYNAMIC
  int count = 3 + (input & 3);
  volatile int local[count];
  for (int index = 0; index != count; ++index)
    local[index] = input - 1 + 11*index;
  int result = many_stack_pointer_sink(GROUPS(ARG16), (const int *)local);
  int checksum = 0;
  for (int index = 0; index != count; ++index)
    checksum += (index + 1)*local[index];
  return result + checksum;
#else
  volatile int local[2] = {input - 1, input + 10};
  return many_stack_pointer_sink(GROUPS(ARG16), (const int *)local);
#endif
}

int main(void) {
  /* First scalar + last scalar + local[1] = 1 + 544 + input + 10. */
#ifdef MANY_DYNAMIC
  /* Also retain the complete weighted VLA checksum across the large call. */
  const int expected[] = {1012, 1458, 908};
#else
  const int expected[] = {557, 562, 568};
#endif
  for (int round = 0; round != 2; ++round)
    for (int index = 0; index != 3; ++index)
      if (many_stack_pointer_owner(many_stack_inputs[index]) != expected[index])
        return 17;
  return 42;
}
