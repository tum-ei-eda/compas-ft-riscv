/* Merges between global, local and inherited pointers must preserve the source
 * program's result. These are functional tests, including for EDDI.
 */
#define NOINLINE __attribute__((noinline))

#ifndef TEST_CASE
#define TEST_CASE 1
#endif

volatile int selector;

#if TEST_CASE == 1

int global_value = 11;

NOINLINE int pointer_sink(const int *pointer) { return *pointer; }

NOINLINE int mixed_pointer(int input) {
  int local = input;
  const int *pointer = &global_value;
  if (selector) {
    selector = input;
    pointer = &local;
  }
  return pointer_sink(pointer) + 1;
}

int main(void) {
  selector = 0;
  int global_result = mixed_pointer(7);
  selector = 1;
  int local_result = mixed_pointer(7);
  return global_result == 12 && local_result == 8 ? 42 : 17;
}

#elif TEST_CASE == 2

int global_values[4] = {11, 17, 23, 31};
volatile int loop_inputs[3] = {2, 7, -3};

NOINLINE int pointer_sink(const int *pointer) { return *pointer; }

NOINLINE int mixed_pointer_loop(int input, unsigned choice) {
  int local[4] = {input + 3, input * 2 + 5, input * 3 + 7, input * 4 + 11};
  const int *pointer = global_values;
  int result = 0;
  for (unsigned i = 0; i < 6; ++i) {
    selector = (choice + i) % 3;
    if (selector == 1) {
      selector = input + (int)i;
      pointer = &local[i & 3];
    } else if (selector == 2) {
      selector = input - (int)i;
      pointer = &global_values[(i + 1) & 3];
    }
    /* The third path retains the previous iteration's pointer. */
    result += pointer_sink(pointer) * (int)(i + 1);
  }
  return result + pointer_sink(pointer) * 7;
}

int main(void) {
  static const int expected[3][3] = {
      {570, 502, 306}, {615, 587, 481}, {525, 417, 131}};
  for (unsigned repeat = 0; repeat < 2; ++repeat)
    for (unsigned input = 0; input < 3; ++input)
      for (unsigned choice = 0; choice < 3; ++choice)
        if (mixed_pointer_loop(loop_inputs[input], choice) !=
            expected[input][choice])
          return 17;
  return 42;
}

#elif TEST_CASE == 3

int global_values[4] = {29, 37, 43, 53};
volatile int origin_inputs[2] = {2, 7};

NOINLINE int mixed_pair_sink(const int *left, const int *right, int bias) {
  /* The observable write keeps later pointer loads across the call. */
  selector = bias + *left;
  return *left * 3 + *right * 5 + bias;
}

NOINLINE int mixed_pointer_origins(const int *first, const int *second,
                                   int input, unsigned choice) {
  volatile int private_values[5] = {input + 2, input + 5, input + 9, input + 14,
                                    input + 20};
  int local[3] = {input * 2 + 3, input * 3 + 5, input * 5 + 7};
  const int *left = first + 1;
  const int *right = second + 2;
  if (choice & 1) {
    selector = input + 1;
    left = second + 1;
  }
  if (choice & 2) {
    selector = input + 2;
    right = global_values + 1;
  }
  if (choice & 4) {
    selector = input + 4;
    left = local + 1;
  }
  int result = mixed_pair_sink(left, right, input);
  result += mixed_pair_sink(right, left, input + 4) * 2;
  result += *left * 7 + *right * 11;
  for (unsigned i = 0; i < 5; ++i)
    result += private_values[i] * (int)(i + 1);
  return result;
}

NOINLINE int mixed_pointer_caller(int input, unsigned choice, unsigned kind) {
  int first[4] = {input + 1, input + 4, input + 8, input + 13};
  int second[4] = {input * 2 + 2, input * 2 + 7, input * 2 + 12,
                   input * 2 + 17};
  const int *left = first;
  const int *right = second;
  if (kind == 0) {
    selector = input;
    right = global_values;
  } else if (kind == 1) {
    selector = input + 1;
    left = global_values;
  }
  return mixed_pointer_origins(left, right, input, choice) + first[0] +
         second[3];
}

int main(void) {
  static const int expected[2][3][8] = {
      {{1329, 1949, 1197, 1817, 1429, 1429, 1297, 1297},
       {1355, 835, 1817, 1297, 835, 835, 1297, 1297},
       {735, 835, 1197, 1297, 835, 835, 1297, 1297}},
      {{1534, 2054, 1402, 1922, 1834, 1834, 1702, 1702},
       {1680, 1360, 1922, 1602, 1460, 1460, 1702, 1702},
       {1160, 1360, 1402, 1602, 1460, 1460, 1702, 1702}}};
  for (unsigned repeat = 0; repeat < 2; ++repeat)
    for (unsigned input = 0; input < 2; ++input)
      for (unsigned kind = 0; kind < 3; ++kind)
        for (unsigned choice = 0; choice < 8; ++choice)
          if (mixed_pointer_caller(origin_inputs[input], choice, kind) !=
              expected[input][kind][choice])
            return 17;
  return 42;
}

#else
#error "Select a mixed-pointer case with TEST_CASE=1..3"
#endif
