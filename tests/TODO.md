# Deferred hardening failures

Keep open compiler work here and remove resolved entries once regression coverage confirms the fix. Preserve independent functional oracles and record build/verifier failures separately from runtime failures.

Run commands from the repository root after [configuring the tools](README.adoc#running-tests). Results below cover LLVM 13.0.1 and 16.0.6 backends with the Clang 13.0.1 frontend unless stated otherwise. A target error exit such as `-512` can be hidden by a zero host status. Only explicitly matching manifest runtime failures are `XFAIL`; build and verifier failures remain `ERROR`.

## Stack-pointer arguments: issue #14

- [ ] Extend inherited-pointer tracking beyond ordinary register formals and private full-word spills.

In [`stack_args`](regression/stack_args/suite.json) ([issue #14](https://github.com/tum-ei-eda/compas-ft-riscv/issues/14)), stack-passed/byval pointer formals and inherited-pointer tail calls are explicitly unsupported; pointer returns and reloads from arbitrary memory are not tracked. Tracking pointer merges currently requires pointer-typed IR PHI/select candidates, supported affine pointer operations and encodable FP-relative metadata stores. Integer-encoded pointer merges and nonlinear operations on runtime origins remain unsupported.

```sh
python3 tests/regression/run.py --case 'stack_args/*' \
  --mode EDDI --mode SWIFT --schedule cgs --schedule fgs --cfp none \
  --verify-machineinstrs --build-dir build/tests-todo-stack
```

## EDDI: realigned dynamic frames

- [ ] Give realigned variable-sized EDDI frames a separate base-pointer contract.

VLAs requiring additional stack realignment, such as a runtime-sized `__attribute__((aligned(64)))` local array, are explicitly rejected with `realigned EDDI dynamic frames require a separate base pointer`. LLVM uses `x9`/`s1` as a base pointer for this combination, conflicting with EDDI's shadow SP. Supporting it requires distinct base-pointer ownership and corresponding primary/shadow addressing; accepting the current register assignment would overwrite an allocated bank.

## Call-boundary instrumentation

- [ ] Correct outgoing-argument displacement in late tail-conversion and repair-mode preservation.
- [ ] Exclude CFP-owned state from selective-call balance checks when DMR and CFP select different functions.
- [ ] Make signature instrumentation aware of `+save-restore` prologue/epilogue helpers.

The first item concerns remaining legacy `saveRegs`/`loadRegs` paths that move SP. Returning libcalls now use separate fixed caller-context and result banks without moving outgoing stack arguments. Duplicable calls copy the duplicate result to shadows, then reload the original result into its primary registers using the saved layout. Late tail wrappers run after the original epilogue restores FP and need earlier conversion or another preservation plan.

For the balance-check issue, a RACFED-protected caller without DMR can invoke a DMR-protected callee while its evolving RTS in `t0` differs from ordinary shadow `t4`, causing target `-512`. Returning EDDI calls now exclude discarded caller-clobbered temporaries; CFP ownership still needs review for other DMR modes and preservation paths. Large RASM signature-slot offsets can expose the same comparison when address formation borrows `t4`. LLVM13's large-offset DMR-bank MIR probe also hits an assembly-printer assertion, leaving that validation incomplete.

Compiler-generated `__riscv_save_*` calls execute before FP setup and can clobber G/RTS in `t0`. Signature initialization and preservation must account for their prologue placement.

## Machine-instruction metadata

- [ ] Describe the shadow calling convention at indirect calls with unknown target protection.
- [ ] Give ordinary EDDI duplicate memory operations independent pointer/alias metadata.

Functional indirect-call coverage does not establish complete shadow argument/result and preserved-register metadata for unknown targets. Ordinary duplicated loads/stores can still carry primary-bank pointer or fixed-stack provenance; updating it must preserve the separate handling of incoming stack arguments and store loadbacks.

## Protected inline assembly: stack-pointer probe

- [ ] Support or explicitly diagnose hardening the inline-assembly `abi_stack_pointer` helper.

The normal alignment case leaves this helper unprotected so it observes the caller's SP without creating a frame. Selecting it for EDDI reproduces LLVM13's `MachineOperand::getReg()` / `isReg()` assertion during the DMR pass.

```sh
python3 tests/regression/run.py --case call_abi/stack_alignment \
  --arch rv64 --mode EDDI --cfp none --no-verify-machineinstrs \
  --functions 'abi_stack_caller,abi_stack_callee,abi_stack_pointer' \
  --build-dir build/tests-todo-protected-inline-asm
```

## Floating-point checks

- [ ] Correct FP equality checks for NaNs and signed zero.
- [ ] Define protection of architectural FP control/status state.

The current `FEQ_S`/`FEQ_D` checks reject matching NaNs and accept oppositely signed zeroes. The rounding-mode input (`FRM`) is shared by primary and shadow computations; FP control/status state has no shadow. The [hard-float suite](regression/hard_float/README.adoc) checks finite values against exact-bit oracles, including nonzero lower binary64 bits on RV32.

```sh
python3 tests/regression/run.py --case 'hard_float/*' \
  --no-verify-machineinstrs --build-dir build/tests-todo-hard-float
```
