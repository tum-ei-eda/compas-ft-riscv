/* RSM instruction selection must preserve arithmetic, branch, loop and call behavior. */

#define NOINLINE __attribute__((noinline))

volatile unsigned layering_values[] = {0, 1, 4, 9, 12};
volatile unsigned layering_rounds[] = {0, 1, 2, 3, 4};
volatile unsigned layering_effect;

/* Keep this leaf free of application branches: its entry checks are unambiguous. */
NOINLINE unsigned layering_entry(unsigned left, unsigned right) {
  return (left + right) * 3 + 1;
}

/* Volatile side effects retain both arms and the loop at the runner's -O1. */
NOINLINE unsigned layering_branches(unsigned value, unsigned rounds) {
  unsigned result = value + 5;
  for (unsigned i = 0; i < rounds; ++i) {
    if ((value + i) & 1) {
      layering_effect += 3;
      result = (result << 1) ^ 7;
    } else {
      layering_effect += 5;
      result += i + 2;
    }
  }
  if (result > 20) {
    layering_effect += 7;
    result -= 4;
  } else {
    layering_effect += 11;
    result += 6;
  }
  return result;
}

int main(void) {
  static const unsigned entry_results[] = {7, 13, 25, 43, 55};
  static const unsigned branch_results[] = {11, 17, 23, 55, 73};
  static const unsigned effects[] = {11, 14, 19, 18, 23};
  for (unsigned repeat = 0; repeat < 2; ++repeat) {
    for (unsigned i = 0; i < 5; ++i) {
      unsigned value = layering_values[i];
      unsigned rounds = layering_rounds[i];
      if (layering_entry(value, rounds + 2) != entry_results[i])
        return 17;
      layering_effect = 0;
      if (layering_branches(value, rounds) != branch_results[i] ||
          layering_effect != effects[i])
        return 17;
    }
  }
  return 42;
}
