# Deferred hardening failures

Keep open compiler work here and remove resolved entries once regression coverage confirms the fix. Preserve independent functional oracles and record build/verifier failures separately from runtime failures.

Run commands from the repository root after [configuring the tools](README.adoc#running-tests). Results below cover LLVM 13.0.1 and 16.0.6 backends with the Clang 13.0.1 frontend unless stated otherwise. A target error exit such as `-512` can be hidden by a zero host status. Only explicitly matching manifest runtime failures are `XFAIL`; build and verifier failures remain `ERROR`.

## Remaining inherited-pointer limitations: issue #14

Ordinary register- and stack-passed pointer formals and private full-word spills are supported. The [`stack_args`](regression/stack_args/suite.json) regressions pass; the remaining extensions related to [issue #14](https://github.com/tum-ei-eda/compas-ft-riscv/issues/14) are:

- [ ] Support byval/byref and other indirect pointer formals, which are explicitly rejected.
- [ ] Support inherited-pointer tail calls, which are explicitly rejected.
- [ ] Track pointer returns and pointer reloads from arbitrary memory.
- [ ] Extend pointer merges beyond pointer-typed IR PHI/select candidates, supported affine operations and encodable FP-relative metadata stores. Integer-encoded pointer merges and nonlinear operations on runtime origins remain unsupported.

```sh
python3 tests/regression/run.py --case 'stack_args/*' \
  --schedule cgs --schedule fgs --cfp none \
  --verify-machineinstrs --build-dir build/tests-todo-stack
```

## Other DMR modes: realigned dynamic frames

- [ ] Support realigned variable-sized frames in SWIFT and NZDC modes.

SWIFT, NZDC, NZDC+NEMESIS and NZDC+NEMESEC still abort with `reg not found in P2S_` for a runtime-sized `__attribute__((aligned(64)))` local array on RV32/RV64 with both backends. These modes retain LLVM's `x9`/`s1` base pointer, conflicting with the monitor's shadow SP and lacking a primary-to-shadow register mapping. Extending support requires distinct base-pointer ownership and corresponding address tracking and call preservation. The realigned dynamic regression cases explicitly select EDDI only.

## Call-boundary instrumentation

- [ ] Audit repair-mode preservation that moves SP around calls.
- [ ] Make signature instrumentation aware of `+save-restore` prologue/epilogue helpers.

Moving SP in repair-mode call preservation still needs review, including its effect on outgoing stack arguments. Remaining late tail-conversion paths use legacy `saveRegs`/`loadRegs` after the original epilogue has restored FP; they require a separate preservation contract. Ordinary-to-EDDI direct calls now use returning wrappers prepared before frame layout.

Compiler-generated `__riscv_save_*` calls execute before FP setup and can clobber G/RTS in `t0`. Signature initialization and preservation must account for their prologue placement.

## Floating-point checks

- [ ] Correct FP equality checks for NaNs and signed zero.
- [ ] Define protection of architectural FP control/status state.

The current `FEQ_S`/`FEQ_D` checks reject matching NaNs and accept oppositely signed zeroes. The rounding-mode input (`FRM`) is shared by primary and shadow computations; FP control/status state has no shadow. The [hard-float suite](regression/hard_float/README.adoc) checks finite values against exact-bit oracles, including nonzero lower binary64 bits on RV32.

```sh
python3 tests/regression/run.py --case 'hard_float/*' \
  --no-verify-machineinstrs --build-dir build/tests-todo-hard-float
```
