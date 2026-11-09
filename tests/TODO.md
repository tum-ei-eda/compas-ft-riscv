# Deferred hardening failures

These items track compiler work for later. Keep the functional checks and their independent expected results intact while investigating failures.

Run the commands below from the repository root after [configuring the tools](README.adoc#running-tests). Select `COMPAS_LLVM_ROOT`, and any `COMPAS_CLANG` or `COMPAS_LLC` overrides, for the compiler combination being investigated. Validation with the LLVM 16.0.6 backend used the Clang 13.0.1 frontend; it does not establish results for a Clang 16 frontend.

## Stack arguments and instruction scheduling

- [ ] Correct the fault-free stack argument and scheduling failures tracked by [issue #14](https://github.com/tum-ei-eda/compas-ft-riscv/issues/14).

The following configurations fail on both RV32 and RV64 with the LLVM 13.0.1 and LLVM 16.0.6 backends, using the per-case function selections in the [stack argument manifest](regression/stack_args/suite.json):

| DMR mode | Schedule | Affected cases |
| --- | --- | --- |
| EDDI | `cgs` | `branch`, `loop`, `forwarded`, `mixed_pointer` |
| EDDI | `fgs` | All nine cases |
| SWIFT | `fgs` | All cases except `scalar` |

Control-flow protection is disabled. Each affected execution reaches target exit `-512` without an injected fault; the unprotected reference returns `42`. Host status alone can hide this difference. The full matrix produced **48 PASS and 42 XFAIL**, including unprotected references, for each backend. The manifest records these exact known runtime failures; review those entries when a compiler correction produces `XPASS`.

```sh
python3 tests/regression/run.py \
  --case 'stack_args/*' --arch rv32 --arch rv64 \
  --mode EDDI --mode SWIFT --schedule cgs --schedule fgs --cfp none \
  --build-dir build/tests-todo-stack
```

## CRC: truncated output with CFCSS combinations

- [ ] Investigate why `NZDC+NEMESIS` and `NZDC+NEMESEC` combined with `CFCSS` terminate before completing CRC.

Both failures use RV64 (`rv64gc`), coarse-grained scheduling and all four functions (`main`, `crcInit`, `crcSlow`, `crcFast`) selected for both DMR and CFP. They were observed with the LLVM 16.0.6 backend and Clang 13.0.1 frontend. The process returns status `0` after printing only the initial check-value banner. The [independent CRC oracle](apps/crc/expected.stdout) requires four lines, including the computed slow and fast CRC values and the completion line.

The full CRC matrix with these function selections, six DMR selections (`none` and the five supported modes) and four CFP selections (`none`, `CFCSS`, `RASM`, `RACFED`) produced **22 PASS and 2 FAIL**. The root cause has not been investigated and no issue or known-failure allowance has been added. Keep these configurations as `FAIL` while investigation is deferred.

```sh
python3 tests/apps/run.py \
  --case 'crc/*' --arch rv64 --schedule cgs \
  --mode NZDC+NEMESIS --mode NZDC+NEMESEC --cfp CFCSS \
  --functions 'main,crcInit,crcSlow,crcFast' \
  --cfp-functions 'main,crcInit,crcSlow,crcFast' \
  --build-dir build/tests-todo-crc-cfcss
```

## CRC: LLVM 13 EDDI backend assertion

- [ ] Investigate the LLVM 13.0.1 `MCInst.h` assertion when compiling CRC with EDDI on all four functions.

This configuration uses RV64 (`rv64gc`), coarse-grained scheduling and no CFP. The LLVM 13.0.1 backend fails in `MCOperand::getReg()` / `isReg()` during assembly printing of `main`. It reproduces with the original CRC sources and the older compiler binary, so it predates the test reorganization. It did not reproduce with the LLVM 16.0.6 backend in the validation using the Clang 13.0.1 frontend.

Run this with the LLVM 13.0.1 tool configuration. This is a build `ERROR`, not a known runtime `XFAIL`; keep that distinction while the compiler fix is deferred.

```sh
python3 tests/apps/run.py \
  --case 'crc/*' --arch rv64 --mode EDDI --cfp none --schedule cgs \
  --functions 'main,crcInit,crcSlow,crcFast' \
  --build-dir build/tests-todo-crc-llvm13
```

## Control-flow combinations: fault-free signature failures

- [ ] Investigate the failing combinations in the [control-flow suite](regression/control_flow/README.adoc).

All six native oracles pass at `-O1` and `-O2`, and all RV32/RV64 unprotected references return `42`. The following protected configurations instead reach target exit `-256`, with empty stdout and host status zero. Scheduling is `cgs`, and the selected functions are declared per case in the manifest.

| Cases | DMR | CFP | Architecture | Backend |
| --- | --- | --- | --- | --- |
| `edges` | `NZDC+NEMESIS`, `NZDC+NEMESEC` | `CFCSS` | RV32, RV64 | LLVM 13.0.1, 16.0.6 |
| `short_circuit` | `EDDI` | `RACFED` | RV32, RV64 | LLVM 13.0.1, 16.0.6 |
| `break_continue` | `NZDC+NEMESIS`, `NZDC+NEMESEC` | `CFCSS` | RV64 | LLVM 13.0.1 only |

The 288-execution matrix per backend has **280 functional PASS / 8 FAIL** on LLVM13 and **282 functional PASS / 6 FAIL** on LLVM16. No new runtime-failure allowances have been added. The cause of each signature failure remains to be investigated.

```sh
python3 tests/regression/run.py --case 'control_flow/*' \
  --no-verify-machineinstrs --build-dir build/tests-todo-control-flow
```

## Remaining machine-instruction and CFG verification errors

- [ ] Correct the metadata and CFG violations reported by LLVM's machine verifier on the new suites.

The control-flow matrix reports verifier errors for every enabled DMR mode with every CFP selection, and for CFP-only `CFCSS`, on both architectures and both tested backends: **252 verifier errors / 36 verifier passes** per backend.

Diagnostics include explicit definitions marked as uses, undefined physical registers, ordinary instructions after terminators, missing or unexpected CFG successors, duplicate successor/predecessor entries and missing `mayStore` flags. These are observed diagnostics; they do not establish a single common root cause. Existing fixes for destination flags and signature-block normalization do not cover every instruction path exercised by these cases.

The runner preserves normal execution results under `functional_status` and records verification separately. A verifier error makes the overall configuration `ERROR` even if runtime behavior passes or matches a known failure. Do not convert these errors into runtime `XFAIL` entries.

```sh
python3 tests/regression/run.py --case control_flow/diamond \
  --arch rv32 --mode SWIFT --cfp none --verify-machineinstrs \
  --build-dir build/tests-todo-machine-verifier
```
