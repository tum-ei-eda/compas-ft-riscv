; Mandatory inherited-pointer tail calls cannot keep the caller's delta bank.
; The unprotected reference still checks a literal arithmetic result.
@pointer_tail_value = global i32 13

define i32 @pointer_tail_musttail_leaf(i32* %pointer) noinline {
entry:
  %value = load i32, i32* %pointer
  %result = add i32 %value, 29
  ret i32 %result
}

define i32 @pointer_tail_musttail_middle(i32* %pointer) noinline {
entry:
  %result = musttail call i32 @pointer_tail_musttail_leaf(i32* %pointer)
  ret i32 %result
}

define i32 @main() {
entry:
  %result = call i32 @pointer_tail_musttail_middle(i32* @pointer_tail_value)
  %ok = icmp eq i32 %result, 42
  %exit = select i1 %ok, i32 42, i32 17
  ret i32 %exit
}
