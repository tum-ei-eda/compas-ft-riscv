; Ordinary software multiplication companion, compiled in a separate module.
; Keep the shift/add loop intact so it cannot recursively become __mulsi3.
target triple = "riscv32-unknown-unknown-elf"

define i32 @__mulsi3(i32 %left, i32 %right) noinline optnone {
entry:
  br label %loop

loop:
  %value = phi i32 [ %left, %entry ], [ %next_value, %loop ]
  %bits = phi i32 [ %right, %entry ], [ %next_bits, %loop ]
  %accumulator = phi i32 [ 0, %entry ], [ %sum, %loop ]
  %low_bit = and i32 %bits, 1
  %set = icmp ne i32 %low_bit, 0
  %term = select i1 %set, i32 %value, i32 0
  %sum = add i32 %accumulator, %term
  %next_value = shl i32 %value, 1
  %next_bits = lshr i32 %bits, 1
  %again = icmp ne i32 %next_bits, 0
  br i1 %again, label %loop, label %done

done:
  ret i32 %sum
}
