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

#else
#error "Unknown stack-argument TEST_CASE"
#endif
