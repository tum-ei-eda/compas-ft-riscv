; Explicit musttail cannot be changed into a returning selective EDDI call.
; The unprotected reference still checks an independent result and exits 42.
define i32 @abi_tail_musttail_leaf(i32 %value) noinline {
entry:
  %result = add i32 %value, 1
  ret i32 %result
}

define i32 @abi_tail_musttail_wrapper(i32 %value) noinline {
entry:
  %result = musttail call i32 @abi_tail_musttail_leaf(i32 %value)
  ret i32 %result
}

define i32 @main() {
entry:
  %result = call i32 @abi_tail_musttail_wrapper(i32 41)
  %ok = icmp eq i32 %result, 42
  %exit = select i1 %ok, i32 42, i32 17
  ret i32 %exit
}
