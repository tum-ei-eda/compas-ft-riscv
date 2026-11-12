; RV32I lowers this mul to an ExternalSymbol helper without an IR call site.
target triple = "riscv32-unknown-unknown-elf"

@multiply_inputs = global [4 x i32] [i32 17, i32 23, i32 7, i32 13]

define i32 @libtail_mul(i32 %left, i32 %right) noinline {
entry:
  %product = mul i32 %left, %right
  ret i32 %product
}

define i32 @main() noinline {
entry:
  %left0 = load volatile i32, i32* getelementptr ([4 x i32], [4 x i32]* @multiply_inputs, i32 0, i32 0)
  %right0 = load volatile i32, i32* getelementptr ([4 x i32], [4 x i32]* @multiply_inputs, i32 0, i32 1)
  %left1 = load volatile i32, i32* getelementptr ([4 x i32], [4 x i32]* @multiply_inputs, i32 0, i32 2)
  %right1 = load volatile i32, i32* getelementptr ([4 x i32], [4 x i32]* @multiply_inputs, i32 0, i32 3)
  %product0 = call i32 @libtail_mul(i32 %left0, i32 %right0)
  %product1 = call i32 @libtail_mul(i32 %left1, i32 %right1)
  %ok0 = icmp eq i32 %product0, 391
  %ok1 = icmp eq i32 %product1, 91
  %ok = and i1 %ok0, %ok1
  %result = select i1 %ok, i32 42, i32 17
  ret i32 %result
}
