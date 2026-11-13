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

- [ ] Retain returning calls for the remaining REPAIR tail transfers.

Direct calls across either selective DMR boundary now use returning wrappers prepared before frame layout in every DMR mode. The wrappers preserve context in fixed caller-frame slots; late machine IR that bypasses this decision is diagnosed. Scalar calls between compatible protected functions can still be tails. REPAIR rejects those tails and indirect tails because its fixed caller snapshot requires a live frame; use `-fno-optimize-sibling-calls` for returning calls. Defining the corresponding early REPAIR decision and explicit `musttail` behavior remains separate work.

- [ ] Check EDDI's stack relation before tearing down compatible tail-call frames.

The `hard_float/*bits_tail*` cases expose a stale EDDI stack check after the paired epilogue releases both frames. It compares `SP + 16` with shadow SP even though they are already equal. With any CFP selection, these cases reach target `-512` on RV32/RV64 with LLVM13/16 and both schedules, including `orig`, `orig+dmr` and `balance` selections under RACFED. Forcing a frame pointer also exposes the failure without CFP. Baseline and patched traces take this branch before any FP comparison; finite-only probes fail too. This is independent of the corrected NaN/signed-zero checks. The new tail cases default to CFP disabled; caller/callee FP cases retain the complete CFP matrix.

```sh
python3 tests/regression/run.py --case 'hard_float/double_bits_tail_rv32' \
  --mode EDDI --cfp CFCSS --verify-machineinstrs
```

## Global signature selection with save/restore helpers

- [ ] Preserve RASM/RACFED signatures when all helper wrappers are selected.

`save_restore/repeated_calls` with `--cfp-functions=-1` exits with target `-256` under RASM and RACFED on RV32/RV64 with LLVM13/16. The same four configurations fail with main's pre-rebase compiler. Selecting only `helper_repeated_calls` passes, including the `orig+dmr` and `balance` masks. Keep the global-selection call-boundary issue separate from the resolved CFCSS balance checks.

```sh
python3 tests/regression/run.py --case 'save_restore/repeated_calls' \
  --cfp RASM --cfp RACFED --cfp-functions=-1 --verify-machineinstrs
```

## Floating-point checks

- [ ] Define protection of architectural FP control/status state.
- [ ] Resolve LLVM16 REPAIR FP shadow-register lookup failures.

The rounding-mode input (`FRM`) is shared by primary and shadow computations; FP control/status state has no shadow. Balance checks now compare raw register bits, including NaN boxing, without changing exception flags. The [hard-float suite](regression/hard_float/README.adoc) covers matching quiet/signaling NaNs, signed zeros, subnormals, protected tail calls and nonzero lower binary64 bits on RV32. Its controlled comparison probes require different encodings to reach the error handler and identical encodings to pass with unchanged exception flags.

With `-REPAIR` enabled, the `eight_float_rv64` and `eight_double_rv32` fixtures abort in `getPrimaryFromShadow()` on LLVM16 for all three NZDC modes. The same assertion affects `float_live_rv32` and `double_live_rv64` with both schedules, before and after the bitwise-comparison fix. LLVM13 passes these finite-value call probes with both schedules. The [REPAIR call suite](regression/repair_call_abi/README.adoc) currently covers integer-register ABIs.

```sh
python3 tests/regression/run.py --case 'hard_float/*' \
  --verify-machineinstrs --build-dir build/tests-todo-hard-float
python3 tests/regression/hard_float/run_bit_checks.py
```
