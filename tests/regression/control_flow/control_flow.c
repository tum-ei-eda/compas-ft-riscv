/* Fault-free control-flow regressions. Every selected case returns 42 or 17. */

#ifndef TEST_CASE
#error "Select a control-flow case with TEST_CASE=1..6"
#endif

#define NOINLINE __attribute__((noinline))

#if TEST_CASE == 1

volatile int diamond_inputs[] = {-7, 0, 4, 9, 12};
volatile unsigned diamond_effect;

NOINLINE unsigned control_diamond(int value) {
  unsigned result;
  if (value < 0) {
    result = (unsigned)(-value) + 11;
    diamond_effect += 1;
  } else if (value & 1) {
    result = (unsigned)value * 3 + 5;
    diamond_effect += 3;
  } else {
    result = (unsigned)value * 2 + 7;
    diamond_effect += 5;
  }

  if (result > 20) {
    result -= 4;
    diamond_effect += 7;
  } else {
    result += 6;
    diamond_effect += 11;
  }
  return result;
}

int main(void) {
  static const unsigned results[] = {24, 13, 21, 28, 27};
  static const unsigned effects[] = {12, 16, 16, 10, 12};
  for (unsigned i = 0; i < 5; ++i) {
    diamond_effect = 0;
    if (control_diamond(diamond_inputs[i]) != results[i] ||
        diamond_effect != effects[i])
      return 17;
  }
  return 42;
}

#elif TEST_CASE == 2

volatile unsigned edge_inputs[] = {0, 1, 2, 3, 6, 9};
volatile unsigned edge_effect;

NOINLINE unsigned control_edges(unsigned value) {
  unsigned result = value + 3;
  if (value & 1) {
    edge_effect += 2;
    result *= 3;
  } else {
    edge_effect += 5;
    result += 8;
  }
  if (value < 3) {
    edge_effect += 7;
    result ^= 9;
  }
  if (value == 6) {
    edge_effect += 11;
    result += 17;
  }
  return result;
}

int main(void) {
  static const unsigned results[] = {2, 5, 4, 18, 34, 36};
  static const unsigned effects[] = {12, 9, 12, 2, 16, 2};
  for (unsigned i = 0; i < 6; ++i) {
    edge_effect = 0;
    if (control_edges(edge_inputs[i]) != results[i] ||
        edge_effect != effects[i])
      return 17;
  }
  return 42;
}

#elif TEST_CASE == 3

volatile int early_inputs[] = {-5, 0, 1, 4, 9};
volatile unsigned classify_inputs[] = {12, 9, 4, 1, 0};
volatile unsigned early_effect;

NOINLINE unsigned control_early(int value) {
  if (value < 0) {
    early_effect = 3;
    return (unsigned)(11 - value);
  }
  if (value == 0) {
    early_effect = 5;
    return 7;
  }
  unsigned result = (unsigned)value * 3;
  if (value > 8) {
    early_effect = 7;
    return result - 4;
  }
  early_effect = 11;
  return result + 2;
}

/* This second protected function has different joins and return paths. */
NOINLINE unsigned control_classify(unsigned value) {
  if (value == 0)
    return 3;
  if (value < 4)
    return value + 9;
  if (value & 1)
    return value * 2 + 1;
  return value + 5;
}

int main(void) {
  static const unsigned results[] = {16, 7, 5, 14, 23};
  static const unsigned effects[] = {3, 5, 11, 11, 7};
  static const unsigned classifications[] = {17, 19, 9, 10, 3};
  /* Alternate both functions repeatedly in the same translation unit. */
  for (unsigned repeat = 0; repeat < 3; ++repeat) {
    for (unsigned i = 0; i < 5; ++i) {
      early_effect = 0;
      if (control_early(early_inputs[i]) != results[i] ||
          early_effect != effects[i])
        return 17;
      if (control_classify(classify_inputs[i]) != classifications[i])
        return 17;
    }
  }
  return 42;
}

#elif TEST_CASE == 4

volatile unsigned short_inputs[] = {0, 1, 2, 3, 4, 5, 8};
volatile unsigned short_effect;

NOINLINE unsigned control_probe(unsigned value) {
  short_effect = short_effect * 3 + value + 1;
  return (value & 1) != 0;
}

NOINLINE unsigned control_short(unsigned value) {
  unsigned result;
  if (value != 0 && control_probe(value))
    result = 7;
  else
    result = 2;
  if (value < 3 || control_probe(value + 1))
    result += 11;
  else
    result += 5;
  return result;
}

int main(void) {
  static const unsigned results[] = {13, 18, 13, 12, 13, 12, 13};
  static const unsigned effects[] = {0, 2, 3, 17, 21, 25, 37};
  for (unsigned i = 0; i < 7; ++i) {
    short_effect = 0;
    if (control_short(short_inputs[i]) != results[i] ||
        short_effect != effects[i])
      return 17;
  }
  return 42;
}

#elif TEST_CASE == 5

volatile unsigned loop_inputs[] = {0, 1, 2, 5, 9};
volatile unsigned loop_effect;

NOINLINE unsigned control_loop(unsigned count, unsigned seed) {
  unsigned accumulator = seed;
  unsigned state = 3;
  for (unsigned i = 0; i < count; ++i) {
    if (i & 1) {
      accumulator += state + i;
      loop_effect += 2;
    } else {
      accumulator ^= state + i;
      loop_effect += 5;
    }
    state += 2;
  }
  return accumulator + state * 7;
}

int main(void) {
  static const unsigned results[] = {32, 43, 63, 119, 219};
  static const unsigned effects[] = {0, 5, 7, 19, 33};
  for (unsigned i = 0; i < 5; ++i) {
    loop_effect = 0;
    if (control_loop(loop_inputs[i], 11) != results[i] ||
        loop_effect != effects[i])
      return 17;
  }
  return 42;
}

#elif TEST_CASE == 6

volatile unsigned nested_inputs[] = {0, 1, 3, 4, 5, 9};
volatile unsigned nested_effect;

NOINLINE unsigned control_break_continue(unsigned limit) {
  unsigned sum = 1;
  for (unsigned outer = 0; outer < limit; ++outer) {
    if (outer == 2) {
      nested_effect += 1;
      continue;
    }
    for (unsigned inner = 0; inner < 5; ++inner) {
      if (inner == 1) {
        nested_effect += 2;
        continue;
      }
      if (outer + inner > 6) {
        nested_effect += 3;
        break;
      }
      sum += (outer + 1) * (inner + 2);
      nested_effect += 5;
    }
    if (sum > 120) {
      nested_effect += 7;
      break;
    }
  }
  return sum;
}

int main(void) {
  static const unsigned results[] = {1, 18, 52, 96, 126, 126};
  static const unsigned effects[] = {0, 22, 45, 65, 87, 87};
  for (unsigned i = 0; i < 6; ++i) {
    nested_effect = 0;
    if (control_break_continue(nested_inputs[i]) != results[i] ||
        nested_effect != effects[i])
      return 17;
  }
  return 42;
}

#else
#error "TEST_CASE must be in the range 1..6"
#endif
