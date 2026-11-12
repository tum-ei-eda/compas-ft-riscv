# Deferred hardening failures

Keep open compiler work here and remove resolved entries once regression coverage confirms the fix. Preserve independent functional oracles and record build/verifier failures separately from runtime failures.

Run commands from the repository root after [configuring the tools](README.adoc#running-tests). Results below cover LLVM 13.0.1 and 16.0.6 backends with the Clang 13.0.1 frontend unless stated otherwise. A target error exit such as `-512` can be hidden by a zero host status. Only explicitly matching manifest runtime failures are `XFAIL`; build and verifier failures remain `ERROR`.

## Remaining inherited-pointer limitations: issue #14

**Fixed and regression-tested:** inherited-pointer forwarding in tail position with sibling-call optimization enabled. EDDI retains returning calls so frame-dependent checks remain valid. The `pointer_tail_*` cases cover protected and ordinary helpers, pointer merges, and incoming stack formals on RV32/RV64 with LLVM13/16.

Ordinary register- and stack-passed pointer formals and private full-word spills are also supported. The remaining extensions related to [issue #14](https://github.com/tum-ei-eda/compas-ft-riscv/issues/14) in [`stack_args`](regression/stack_args/suite.json) are:

- [ ] Support explicit LLVM `byval` aggregate copies, starting with fixed-size, pointer-free integer data.
- [ ] Define support for `byref` and other unsupported indirect argument conventions separately from `byval` copying.
- [ ] Support inherited-pointer `musttail` transfers, which require a separate frame-lifetime and outgoing-stack contract.
- [ ] Track pointer returns and pointer reloads from arbitrary memory.
- [ ] Extend pointer merges beyond pointer-typed IR PHI/select candidates, supported affine operations and encodable FP-relative metadata stores. Integer-encoded pointer merges and nonlinear operations on runtime origins remain unsupported.

```sh
python3 tests/regression/run.py --case 'stack_args/*' \
  --schedule cgs --schedule fgs --cfp none \
  --verify-machineinstrs --build-dir build/tests-todo-stack
```

## Call-boundary instrumentation

- [ ] Define preservation for remaining late tail-conversion paths and REPAIR tail calls.
- [ ] Make signature instrumentation aware of `+save-restore` prologue/epilogue helpers.

Remaining late tail-conversion paths use legacy `saveRegs`/`loadRegs` after the original epilogue has restored FP; they require a separate preservation contract. REPAIR rejects tail calls because its fixed caller snapshot requires a live frame; use `-fno-optimize-sibling-calls` for returning calls. Ordinary-to-EDDI direct calls use returning wrappers prepared before frame layout.

Compiler-generated `__riscv_save_*` calls execute before FP setup and can clobber G/RTS in `t0`. Signature initialization and preservation must account for their prologue placement.

## Floating-point checks

- [ ] Correct FP equality checks for NaNs and signed zero.
- [ ] Define protection of architectural FP control/status state.
- [ ] Resolve LLVM16 REPAIR FP shadow-register lookup failures.

The current `FEQ_S`/`FEQ_D` checks reject matching NaNs and accept oppositely signed zeroes. The rounding-mode input (`FRM`) is shared by primary and shadow computations; FP control/status state has no shadow. The [hard-float suite](regression/hard_float/README.adoc) checks finite values against exact-bit oracles, including nonzero lower binary64 bits on RV32.

With `-REPAIR` enabled, the `eight_float_rv64` and `eight_double_rv32` fixtures abort in `getPrimaryFromShadow()` on LLVM16 for all three NZDC modes. The assertion also occurs in the compiler before the call-preservation changes. LLVM13 passes both finite-value call probes with both schedules. The [REPAIR call suite](regression/repair_call_abi/README.adoc) currently covers integer-register ABIs.

```sh
python3 tests/regression/run.py --case 'hard_float/*' \
  --no-verify-machineinstrs --build-dir build/tests-todo-hard-float
```
