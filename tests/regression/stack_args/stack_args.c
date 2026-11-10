/* Select one fault-free call-boundary scenario with -DTEST_CASE=<number>.
 * Each scenario has the same reference oracle: main returns 42 on success.
 */
#define NOINLINE __attribute__((noinline))
#define DIRECT 1
#define BRANCH 2
#define LOOP 3
#define SCALAR 4
#define MIXED 5
#define REGISTER_REUSE 6
#define GLOBAL 7
#define FORWARDED 8
#define FORWARDED_FRAMES 9
#define FORWARDED_WIDE 10

#ifndef TEST_CASE
#error "Select a stack-argument scenario with -DTEST_CASE=<number>"
#endif

volatile int selector;
int global_value = 11;

NOINLINE int scalar_sink(int value) { return value + 1; }
NOINLINE int pointer_sink(const int *pointer) { return *pointer; }
NOINLINE int mixed_sink(const int *pointer, int value) {
  return *pointer + value;
}

#if TEST_CASE == DIRECT
NOINLINE int direct_stack(int input) {
  int local = input;
  return pointer_sink(&local) + 1;
}

int main(void) { return direct_stack(7) == 8 ? 42 : 17; }

#elif TEST_CASE == BRANCH
NOINLINE int branch_stack(int input) {
  int local[2] = {input, input + 1};
  const int *pointer;
  if (input > 3) {
    selector = 1;
    pointer = &local[0];
  } else {
    selector = 2;
    pointer = &local[1];
  }
  return mixed_sink(pointer, input) + 1;
}

int main(void) {
  return branch_stack(4) == 9 && branch_stack(2) == 6 ? 42 : 17;
}

#elif TEST_CASE == LOOP
NOINLINE int loop_stack(int input) {
  int local[4] = {input, input + 1, input + 2, input + 3};
  const int *pointer = local;
  for (int i = 0; i < (input & 3); ++i) {
    selector = *pointer;
    ++pointer;
  }
  return mixed_sink(pointer, input) + 1;
}

int main(void) {
  return loop_stack(4) == 9 && loop_stack(5) == 12 && loop_stack(7) == 18
             ? 42
             : 17;
}

#elif TEST_CASE == SCALAR
NOINLINE int scalar_stack(int input) {
  volatile int local = input;
  return scalar_sink(local) + 1;
}

int main(void) { return scalar_stack(5) == 7 ? 42 : 17; }

#elif TEST_CASE == MIXED
NOINLINE int mixed_stack(int input) {
  volatile int local = input;
  return mixed_sink((const int *)&local, local) + 1;
}

int main(void) { return mixed_stack(6) == 13 ? 42 : 17; }

#elif TEST_CASE == REGISTER_REUSE
NOINLINE int scalar_after_pointer(int input) {
  int local = input;
  int value = pointer_sink(&local);
  return scalar_sink(value) + 1;
}

int main(void) { return scalar_after_pointer(8) == 10 ? 42 : 17; }

#elif TEST_CASE == GLOBAL
NOINLINE int global_pointer(void) { return pointer_sink(&global_value) + 1; }

int main(void) { return global_pointer() == 12 ? 42 : 17; }

#elif TEST_CASE == FORWARDED
NOINLINE int forward_pointer(const int *pointer, int value) {
  return mixed_sink(pointer, value) + 1;
}

NOINLINE int forwarded_stack(int input) {
  int local = input;
  return forward_pointer(&local, input) + 1;
}

int main(void) { return forwarded_stack(3) == 8 ? 42 : 17; }

#elif TEST_CASE == FORWARDED_FRAMES
volatile int inherited_inputs[] = {2, 5, 9};
int inherited_global_left[] = {4, 9, 15, 22, 30, 39, 49, 60};
int inherited_global_right[] = {7, 12, 18, 25, 33, 42, 52, 63};

NOINLINE int inherited_pair_sink(const int *left, const int *right, int bias) {
  return 3*left[0] + 5*right[1] + 7*bias;
}

NOINLINE int inherited_inner(const int *left, const int *right, int bias) {
  volatile int saved[3] = {bias + 1, bias + 2, bias + 3};
  int first = inherited_pair_sink(left + 1, right, bias + saved[0]);
  int second = inherited_pair_sink(right, left + 2, bias + saved[1]);
  int joined;
  if ((bias & 1) != 0)
    joined = first + 2*second;
  else
    joined = 2*first + second;
  return joined + saved[0] + 2*saved[1] + 3*saved[2];
}

NOINLINE int inherited_middle(const int *left, const int *right, int bias) {
  volatile int saved[7];
  for (int index = 0; index != 7; ++index)
    saved[index] = bias + index + 1;
  int first = inherited_inner(left + 1, right, bias + 1);
  int second = inherited_inner(right + 1, left, bias + 2);
  int checksum = 0;
  for (int index = 0; index != 7; ++index)
    checksum += saved[index];
  /* Incoming pointers remain live after both nested calls. */
  return first + 3*second + left[0] + 2*right[0] + checksum;
}

NOINLINE int inherited_local(int input) {
  volatile int left[8], right[8];
  for (int index = 0; index != 8; ++index) {
    left[index] = input + 2*index + 1;
    right[index] = 3*input + 5*index + 2;
  }
  int first = inherited_middle((const int *)left, (const int *)right, input);
  /* The two pointer arguments have different origins in this same call. */
  int second = inherited_middle((const int *)left + 1,
                                inherited_global_right + 1, input + 3);
  return first + 2*second + left[7] + 3*right[7];
}

NOINLINE int inherited_global(int input) {
  int first = inherited_middle(inherited_global_left, inherited_global_right,
                               input);
  int second = inherited_middle(inherited_global_left + 1,
                                inherited_global_right + 1, input + 3);
  return first + 2*second + inherited_global_left[7] +
         3*inherited_global_right[7];
}

int main(void) {
  /* Independent literals from expanding both inner branches and checksums. */
  const int local_expected[] = {9451, 11692, 15372};
  const int global_expected[] = {10768, 12341, 14729};
  for (int round = 0; round != 2; ++round) {
    for (int index = 0; index != 3; ++index) {
      int input = inherited_inputs[index];
      if (inherited_local(input) != local_expected[index] ||
          inherited_global(input) != global_expected[index])
        return 17;
    }
  }
  return 42;
}

#elif TEST_CASE == FORWARDED_WIDE
typedef unsigned long long wide;
volatile int wide_inputs[] = {2, 5, 9};
int wide_global_values[] = {7, 11, 19, 29};

NOINLINE int wide_leaf(wide tag, int marker, const int *pointer, int bias) {
  return 3*(*pointer) + 5*marker + bias + (int)(tag & 255ULL) +
         (int)((tag >> 32) & 255ULL);
}

NOINLINE int wide_forward(wide tag, int marker, const int *pointer, int bias) {
  volatile int saved[3] = {marker, bias, 7};
  return wide_leaf(tag + 1, marker + 2, pointer + 1, bias + 2) +
         saved[0] - saved[1] + saved[2];
}

NOINLINE int wide_local(int value) {
  volatile int local[4] = {value, value + 2, value + 4, value + 6};
  return wide_forward(0x0000000300000005ULL, value + 4,
                      (const int *)local, value);
}

NOINLINE int wide_global(int value) {
  return wide_forward(0x0000000300000005ULL, value + 4,
                      wide_global_values, value);
}

int main(void) {
  /* Expanded formulas: local 9*x+58, global 6*x+85. */
  const int local_expected[] = {76, 103, 139};
  const int global_expected[] = {97, 115, 139};
  for (int round = 0; round != 2; ++round) {
    for (int index = 0; index != 3; ++index) {
      int input = wide_inputs[index];
      if (wide_local(input) != local_expected[index] ||
          wide_global(input) != global_expected[index])
        return 17;
    }
  }
  return 42;
}

#else
#error "Unknown stack-argument TEST_CASE"
#endif
