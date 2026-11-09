/* Different function shapes share one compiler-pass instance and one module. */

#define NOINLINE __attribute__((noinline))

volatile unsigned multi_tiny_inputs[] = {0, 1, 4, 9};
volatile int multi_diamond_inputs[] = {-3, 0, 5, 8};
volatile unsigned multi_loop_inputs[] = {0, 1, 3, 5};
volatile int multi_early_inputs[] = {-4, 0, 3, 10};
volatile unsigned multi_effect;

/* Keep this definition order: every selected function is compiled in one TU. */
NOINLINE unsigned multi_tiny(unsigned value) {
  multi_effect += 1;
  return value * 5 + 1;
}

NOINLINE unsigned multi_diamond(int value) {
  unsigned result;
  if (value < 0) {
    multi_effect += 2;
    result = (unsigned)(7 - value);
  } else if (value & 1) {
    multi_effect += 3;
    result = (unsigned)value * 3 + 2;
  } else {
    multi_effect += 5;
    result = (unsigned)value + 11;
  }

  if (result > 15) {
    multi_effect += 7;
    result -= 4;
  } else {
    multi_effect += 11;
    result += 6;
  }
  return result;
}

/* This intervening function is deliberately never selected for hardening. */
NOINLINE unsigned multi_helper(unsigned value) {
  multi_effect += 19;
  return value * 2 + 3;
}

NOINLINE unsigned multi_loop(unsigned count, unsigned seed) {
  unsigned result = seed;
  for (unsigned i = 0; i < count; ++i) {
    result += i * 3 + 2;
    multi_effect += (i & 1) ? 5 : 2;
  }
  return result + count * 7;
}

NOINLINE unsigned multi_early(int value) {
  if (value < 0) {
    multi_effect += 7;
    return (unsigned)(2 - value);
  }
  if (value == 0) {
    multi_effect += 11;
    return 13;
  }
  if (value < 8) {
    multi_effect += 13;
    return (unsigned)value * 4 + 1;
  }
  multi_effect += 17;
  return (unsigned)value - 3;
}

NOINLINE unsigned multi_driver(unsigned index) {
  unsigned result = multi_tiny(multi_tiny_inputs[index]);
  result += multi_diamond(multi_diamond_inputs[index]) * 3;
  result ^= multi_loop(multi_loop_inputs[index], 9) << 1;
  result += multi_early(multi_early_inputs[index]) * 5;
  return result + multi_helper(index + 1);
}

#define CHECK(call, result, effect)                                             \
  do {                                                                        \
    multi_effect = 0;                                                          \
    if ((call) != (result) || multi_effect != (effect))                         \
      return 17;                                                              \
  } while (0)

int main(void) {
  /* Literal oracles are independent of both the reference and protected build. */
  static const unsigned tiny_results[] = {1, 6, 21, 46};
  static const unsigned diamond_results[] = {16, 17, 13, 15};
  static const unsigned diamond_effects[] = {13, 16, 10, 12};
  static const unsigned loop_results[] = {9, 18, 45, 84};
  static const unsigned loop_effects[] = {0, 2, 9, 16};
  static const unsigned early_results[] = {6, 13, 13, 7};
  static const unsigned early_effects[] = {7, 11, 13, 17};
  static const unsigned driver_results[] = {70, 101, 176, 289};
  static const unsigned driver_effects[] = {40, 49, 52, 65};

  for (unsigned repeat = 0; repeat < 4; ++repeat) {
    for (unsigned position = 0; position < 4; ++position) {
      unsigned index = (position + repeat) & 3;
      if (repeat & 1) {
        CHECK(multi_driver(index), driver_results[index], driver_effects[index]);
        CHECK(multi_early(multi_early_inputs[index]), early_results[index],
              early_effects[index]);
        CHECK(multi_loop(multi_loop_inputs[index], 9), loop_results[index],
              loop_effects[index]);
        CHECK(multi_diamond(multi_diamond_inputs[index]), diamond_results[index],
              diamond_effects[index]);
        CHECK(multi_tiny(multi_tiny_inputs[index]), tiny_results[index], 1);
      } else {
        CHECK(multi_tiny(multi_tiny_inputs[index]), tiny_results[index], 1);
        CHECK(multi_diamond(multi_diamond_inputs[index]), diamond_results[index],
              diamond_effects[index]);
        CHECK(multi_loop(multi_loop_inputs[index], 9), loop_results[index],
              loop_effects[index]);
        CHECK(multi_early(multi_early_inputs[index]), early_results[index],
              early_effects[index]);
        CHECK(multi_driver(index), driver_results[index], driver_effects[index]);
      }
    }
  }
  return 42;
}
