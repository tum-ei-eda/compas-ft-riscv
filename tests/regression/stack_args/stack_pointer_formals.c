/* Ordinary full-XLEN pointer formals passed on the stack.  The two shapes
 * put both pointers on the stack, or one in a7 and one on the stack. A wide
 * scalar prefix makes the same prototype use different locations on RV32/64.
 */
#define NOINLINE __attribute__((noinline))
typedef unsigned long abi_word;

#if TEST_CASE == 1
#define LEAF stack_pair_leaf
#define MIDDLE stack_pair_middle
#define OWNER stack_pair_owner
#define EXTRA_FORMAL , abi_word a6, abi_word a7
#define EXTRA_FIRST , a6 + 7, a7 + 8
#define EXTRA_SECOND , a6 + 9, a7 + 10
#define EXTRA_INITIAL , (abi_word)(input + 17), (abi_word)(input + 18)
#define EXTRA_SUM + 7*a6 + 8*a7
#elif TEST_CASE == 2
#define LEAF split_pair_leaf
#define MIDDLE split_pair_middle
#define OWNER split_pair_owner
#define EXTRA_FORMAL , abi_word a6
#define EXTRA_FIRST , a6 + 7
#define EXTRA_SECOND , a6 + 9
#define EXTRA_INITIAL , (abi_word)(input + 17)
#define EXTRA_SUM + 7*a6
#elif TEST_CASE == 3
#define LEAF wide_pair_leaf
#define MIDDLE wide_pair_middle
#define OWNER wide_pair_owner
#define EXTRA_FORMAL , unsigned long long tag
#define EXTRA_FIRST , tag + 0x0000000200000001ULL
#define EXTRA_SECOND , tag + 0x0000000400000003ULL
#define EXTRA_INITIAL , 0x0000001300000007ULL + (unsigned)input
#define EXTRA_SUM + (tag & 255ULL) + 3*((tag >> 32) & 255ULL)
#else
#error "Select a pointer-formal ABI shape"
#endif

volatile int stack_formal_inputs[] = {2, 5, 9};
int stack_formal_left[] = {4, 9, 15, 22, 30, 39, 49, 60, 72, 85};
int stack_formal_right[] = {7, 12, 18, 25, 33, 42, 52, 63, 75, 88};

NOINLINE int LEAF(abi_word a0, abi_word a1, abi_word a2, abi_word a3,
                  abi_word a4, abi_word a5 EXTRA_FORMAL,
                  const int *left, const int *right) {
  volatile int saved[3] = {(int)a0 + 1, (int)a1 + 2, (int)a2 + 3};
  int scalar = (int)(a0 + 2*a1 + 3*a2 + 4*a3 + 5*a4 + 6*a5 EXTRA_SUM);
  return 3*left[0] + 5*left[2] + 7*right[1] + 11*right[3] + scalar +
         saved[0] + 2*saved[1] + 3*saved[2];
}

NOINLINE int MIDDLE(abi_word a0, abi_word a1, abi_word a2, abi_word a3,
                    abi_word a4, abi_word a5 EXTRA_FORMAL,
                    const int *left, const int *right) {
#ifdef STACK_DYNAMIC
  int saved_count = 7 + (int)(a0 & 3);
#else
  int saved_count = 7;
#endif
#if STACK_DYNAMIC == 64
  volatile int saved[saved_count] __attribute__((aligned(64)));
#else
  volatile int saved[saved_count];
#endif
  for (int index = 0; index != saved_count; ++index)
    saved[index] = (int)a0 + index + 1;
  int first = LEAF(a0 + 1, a1 + 2, a2 + 3, a3 + 4, a4 + 5,
                   a5 + 6 EXTRA_FIRST, left + 1, right + 1);
  int second = LEAF(a0 + 3, a1 + 4, a2 + 5, a3 + 6, a4 + 7,
                    a5 + 8 EXTRA_SECOND, right + 1, left + 2);
  int checksum = 0;
  for (int index = 0; index != saved_count; ++index)
    checksum += (index + 1)*saved[index];
  /* Reuse both incoming pointers after the nested calls. */
  return first + 2*second + left[0] + 3*right[1] + checksum;
}

NOINLINE int OWNER(int input) {
  volatile int local_left[10], local_right[10];
  for (int index = 0; index != 10; ++index) {
    local_left[index] = 2*input + 3*index + 1;
    local_right[index] = 5*input + 7*index + 2;
  }
#define CALL(left, right) \
  MIDDLE((abi_word)(input + 11), (abi_word)(input + 12), \
         (abi_word)(input + 13), (abi_word)(input + 14), \
         (abi_word)(input + 15), (abi_word)(input + 16) \
         EXTRA_INITIAL, left, right)
  int local_global = CALL((const int *)local_left + 1, stack_formal_right + 1);
  int global_local = CALL(stack_formal_left + 1, (const int *)local_right + 1);
  int two_local = CALL((const int *)local_left, (const int *)local_right);
  int two_global = CALL(stack_formal_left, stack_formal_right);
#undef CALL
  return local_global + 2*global_local + 3*two_local + 5*two_global +
         local_left[9] + 3*local_right[9];
}

int main(void) {
  /* Literal oracles independently expanded from the weighted array formulas. */
#if TEST_CASE == 1 && defined(STACK_DYNAMIC)
  const int expected[] = {65490, 72630, 84614};
#elif TEST_CASE == 1
  const int expected[] = {63642, 72630, 84614};
#elif TEST_CASE == 2
  const int expected[] = {55898, 64094, 75022};
#else
  const int expected[] = {52169, 59771, 69907};
#endif
  for (int round = 0; round != 2; ++round)
    for (int index = 0; index != 3; ++index)
      if (OWNER(stack_formal_inputs[index]) != expected[index])
        return 17;
  return 42;
}
