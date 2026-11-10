# Deferred hardening failures

Keep open compiler work here and remove resolved entries once regression coverage confirms the fix. Preserve independent functional oracles and record build/verifier failures separately from runtime failures.

Run commands from the repository root after [configuring the tools](README.adoc#running-tests). Results below cover LLVM 13.0.1 and 16.0.6 backends with the Clang 13.0.1 frontend unless stated otherwise. A target error exit such as `-512` can be hidden by a zero host status. Only explicitly matching manifest runtime failures are `XFAIL`; build and verifier failures remain `ERROR`.

## Stack-pointer arguments: issue #14

- [ ] Correct EDDI's forwarded pointers into the caller's duplicated stack frame.
- [ ] Define support for mixed global/local stack-address merges.
- [ ] Remove stale stack-argument failure allowances after reviewing the passing configurations.

In [`stack_args`](regression/stack_args/suite.json) ([issue #14](https://github.com/tum-ei-eda/compas-ft-riscv/issues/14)), EDDI `forwarded` still exits `-512` on RV32/RV64 with both schedules. With CFP disabled it matches an existing `XFAIL`; CFP-enabled runs also fail. EDDI `mixed_pointer` instead reports the unsupported/mixed-address diagnostic at compilation. The CFP-disabled EDDI/SWIFT matrix has 34 stale `XPASS` entries; the original broad scheduling failures are resolved.

```sh
python3 tests/regression/run.py --case 'stack_args/*' \
  --mode EDDI --mode SWIFT --schedule cgs --schedule fgs --cfp none \
  --no-verify-machineinstrs --build-dir build/tests-todo-stack
```

## EDDI: large and dynamic frames

- [ ] Correct EDDI's large/dynamic frame handling in `dynamic_stack_arguments` and `dynamic_stack_arguments_caller_only`.

Both scenarios still produce sixteen build errors per backend across RV32/RV64 and all CFP selections in the [call-ABI suite](regression/call_abi/README.adoc). Variable-sized EDDI frames are explicitly diagnosed as unsupported before transformation; the earlier investigation encountered `MachineOperand::setImm()` assertions or incorrect execution instead. Realigned-frame support requires one encodable fixed allocation, without save/restore libcalls or incoming stack-argument loads. Large incoming argument offsets with a small callee frame do not establish support for a large EDDI frame.

```sh
python3 tests/regression/run.py --case 'call_abi/dynamic_stack_arguments*' \
  --mode EDDI --cfp none --cfp CFCSS --cfp RASM --cfp RACFED \
  --no-verify-machineinstrs --build-dir build/tests-todo-eddi-frames
```

## Call-boundary instrumentation

- [ ] Correct outgoing-argument displacement in duplicated-libcall, late tail-conversion and repair-mode preservation.
- [ ] Exclude CFP-owned state from selective-call balance checks when DMR and CFP select different functions.
- [ ] Make signature instrumentation aware of `+save-restore` prologue/epilogue helpers.

The first item concerns legacy `saveRegs`/`loadRegs` paths that still move SP. Duplicated calls need distinct outer and argument/result snapshots with positional return-to-shadow reloads. Late tail wrappers run after the original epilogue restores FP and need earlier conversion or another preservation plan.

For the balance-check issue, a RACFED-protected caller without DMR can invoke a DMR-protected callee while its evolving RTS in `t0` differs from ordinary shadow `t4`, causing target `-512`. Returning EDDI calls now exclude discarded caller-clobbered temporaries; CFP ownership still needs review for other DMR modes and preservation paths. Large RASM signature-slot offsets can expose the same comparison when address formation borrows `t4`. LLVM13's large-offset DMR-bank MIR probe also hits an assembly-printer assertion, leaving that validation incomplete.

Compiler-generated `__riscv_save_*` calls execute before FP setup and can clobber G/RTS in `t0`. Signature initialization and preservation must account for their prologue placement.

## Machine-instruction and CFG verification

- [ ] Correct verifier errors across the regression suites, including `control_flow`, `crc_control_flow`, `call_abi` and `multi_function`.

Observed diagnostics include definitions marked as uses, undefined physical registers, instructions after terminators, missing/unexpected or duplicate CFG edges, missing `mayStore` flags and expected-register-operand errors. DMR and CFP-only CFCSS still expose errors even where functional execution passes. CFP-only RASM/RACFED pass call-ABI verification.

Keep the runner's `functional_status` separate from verification: a verifier error makes the overall result `ERROR` even when execution passes. Do not turn these into runtime `XFAIL` allowances.

```sh
python3 tests/regression/run.py --case control_flow/diamond \
  --arch rv32 --mode SWIFT --cfp none --verify-machineinstrs \
  --build-dir build/tests-todo-machine-verifier
```

## Protected inline assembly: stack-pointer probe

- [ ] Support or explicitly diagnose hardening the inline-assembly `abi_stack_pointer` helper.

The normal alignment case leaves this helper unprotected so it observes the caller's SP without creating a frame. Selecting it for EDDI reproduces LLVM13's `MachineOperand::getReg()` / `isReg()` assertion during the DMR pass.

```sh
python3 tests/regression/run.py --case call_abi/stack_alignment \
  --arch rv64 --mode EDDI --cfp none --no-verify-machineinstrs \
  --functions 'abi_stack_caller,abi_stack_callee,abi_stack_pointer' \
  --build-dir build/tests-todo-protected-inline-asm
```

## CRC: LLVM13 EDDI assembly-printer assertion

- [ ] Investigate the LLVM13 `MCOperand::getReg()` / `isReg()` assertion when compiling CRC with EDDI on all four functions.

Previously reproduced during assembly printing of `main` with RV64 `rv64gc`, `cgs` and no CFP, including with the original CRC sources and older compiler. The LLVM16 backend did not reproduce this failure in that investigation. This is a build error.

```sh
python3 tests/apps/run.py --case 'crc/*' --arch rv64 \
  --mode EDDI --cfp none --schedule cgs \
  --functions 'main,crcInit,crcSlow,crcFast' \
  --build-dir build/tests-todo-crc-llvm13
```

## Hard-float calls

- [ ] Correct FP shadow-register mapping and call/dataflow failures.
- [ ] Revalidate and correct the previously observed LLVM13 SWIFT comparisons using FP operands in integer branches.

The latest EDDI checks of the [hard-float suite](regression/hard_float/README.adoc), with all four CFP selections and both schedules, retain:

| Backend | Profiles | Observation |
| --- | --- | --- |
| LLVM13 | Four `*_live_*` and two `mixed_*` cases | Target `-512`; both callee-only cases pass. |
| LLVM16 | All eight ISA/ABI profiles | Backend abort in `genShadowFromPrimary`: `reg not found in P2S_`. |

Earlier all-mode `cgs` runs also found LLVM13 SWIFT assembler/link errors such as `bne fa0,fs8,...`, and NZDC/NEMESIS/NEMESEC runtime exits `-512` in caller/mixed cases. Recheck those selections when fixing the FP paths. Preserve full-width RV32+D saves/restores and the exact-bit oracles, which include nonzero lower binary64 bits.

```sh
python3 tests/regression/run.py --case 'hard_float/*' \
  --no-verify-machineinstrs --build-dir build/tests-todo-hard-float
```

## PC-relative addresses

- [ ] Correct LLVM13 `medany` backend assertions, relocation errors and runtime failures.

The [PC-relative suite](regression/pc_relative/README.adoc) disables relaxation and covers both architectures and code models. Current EDDI `cgs` checks retain:

| Backend / model | Cases / CFP | Observation |
| --- | --- | --- |
| LLVM13 / `medany` | `global_read_write`, every CFP; `branch_bases`, enabled CFP | `!NodePtr->isKnownSentinel()` backend assertion. |
| LLVM13 / `medany` | `array_offsets`, `address_helpers`, enabled CFP | `%pcrel_lo missing matching %pcrel_hi` linker error. |
| LLVM13 / `medany` | `array_offsets`, `address_helpers`, `branch_bases`, CFP `none` | Target `-512`. |

Earlier all-mode runs also found LLVM13 CFP-only and other DMR selections affected by the assertions/relocation errors; revalidate those when changing address or signature emission.

```sh
python3 tests/regression/run.py --case 'pc_relative/*' \
  --no-verify-machineinstrs --build-dir build/tests-todo-pc-relative
```
