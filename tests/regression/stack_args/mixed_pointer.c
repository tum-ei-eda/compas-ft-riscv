/* Both paths of a merge between a global and a local pointer must preserve
 * the source program's result. This is a functional test, including for EDDI.
 */
#define NOINLINE __attribute__((noinline))

volatile int selector;
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
