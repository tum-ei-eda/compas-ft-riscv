# Contributing to compas-ft-riscv

COMPAS implements software fault tolerance as LLVM passes for the RISC-V backend. Contributions should preserve fault-free program behavior, respect the target ISA and calling convention, and keep the contracts between data-flow protection, control-flow protection and their combinations explicit. State the fault model and assumptions when describing detection guarantees.

## Design and coding conventions

Start with the [README](../README.adoc), the [user manual sources](manual/src/), and the interfaces and implementation for the behavior being changed. Update documentation, interface comments and relevant regression cases when changing a pass option, register assignment, signature scheme or supported instruction pattern. Identify proposals and deferred features as such.

The transformation passes and shared helpers live in [src](../src/), with corresponding interfaces in [include](../include/):

- `RISCVDmr` implements data-flow protection and conditional-branch protection.
- `RISCVCfcss` and `RISCVRasm` implement control-flow protection, including RASM and RACFED.
- `common` provides shared register, instruction and calling-convention helpers.

LLVM backend integration belongs in the version-specific [patches](../patches/). The [cmake](../cmake/) directory provides consumer-project integration and RISC-V toolchain files. [tests/regression](../tests/regression/) holds functional regression cases and benchmark suites; [tests/apps](../tests/apps/) holds selected application tests, including [CRC](../tests/apps/crc/). Configuration parsing utilities live in [config_parser](../config_parser/). Register new pass sources in the root [CMakeLists.txt](../CMakeLists.txt).

Use the C++ standard configured for the LLVM build, currently C++17 in [docker/.env](../docker/.env), and follow the LLVM style in [.clang-format](../.clang-format). Format changed code consistently with its surroundings. Keep assumptions about LLVM machine instructions, register aliases, relocations, CFG edges and pass ordering explicit. When adding an instruction or ISA extension, account for both primary and shadow operands, register widths, stack alignment and interactions with other enabled protection passes.

The backend schedules `RISCVCompasHardening`, which runs DMR, CFCSS, RASM and RACFED in their existing order. This shared pass preserves the signature regions and completes CFG and physical-register liveness updates before LLVM verifies the result. The implementation lives in [RISCVCompasHardening.cpp](../src/RISCVCompasHardening.cpp); control-flow normalization is shared through [common.cpp](../src/common.cpp).

## Development and validation

COMPAS builds as part of a patched LLVM source tree. The root CMake project uses LLVM's `add_llvm_library`; it is not a standalone LLVM plugin build. The current [CI workflow](../.github/workflows/ci.yml) and [container configuration](../docker/.env) select LLVM 16.0.6. Match the LLVM release to its integration patch; the historical manual also describes LLVM 13.0.1.

Install a host C++ compiler, CMake, a build tool, Git and Python 3, plus LLVM's dependencies. The Debian dependency list and build helpers are in [docker/setup_debian.sh](../docker/setup_debian.sh); container instructions are in [docker/README.adoc](../docker/README.adoc). To develop against LLVM 16.0.6, run the following from the COMPAS repository root with these tools available:

```sh
COMPAS_SRC="$(pwd)"
LLVM_SRC="${COMPAS_SRC}/build/llvm-project"
LLVM_BUILD="${COMPAS_SRC}/build/llvm-build"

mkdir -p "${COMPAS_SRC}/build"
git clone --depth 1 --branch llvmorg-16.0.6 \
  https://github.com/llvm/llvm-project.git "${LLVM_SRC}"
git -C "${LLVM_SRC}" apply "${COMPAS_SRC}/patches/llvm16.0.6_src.patch"
ln -s "${COMPAS_SRC}" "${LLVM_SRC}/llvm/lib/Target/RISCV/compas-ft-riscv"

cmake -S "${LLVM_SRC}/llvm" -B "${LLVM_BUILD}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_STANDARD=17 \
  -DLLVM_ENABLE_PROJECTS=clang \
  -DLLVM_TARGETS_TO_BUILD=RISCV \
  -DLLVM_ENABLE_ASSERTIONS=ON
cmake --build "${LLVM_BUILD}" --parallel 2 --target clang llc llvm-objdump
"${LLVM_BUILD}/bin/clang" --version
"${LLVM_BUILD}/bin/llc" --help-hidden
```

Clone and apply the patch once per LLVM source tree. After editing COMPAS sources, rerun the build command. Choose parallelism to fit available memory, and use separate source and build directories for different LLVM releases. Check that `llc --help-hidden` lists the expected COMPAS options; an upstream LLVM binary without the integration patch cannot run these passes.

### Compiler caching

CI uses [sccache](https://github.com/mozilla/sccache) through [ccache-action](https://github.com/hendrikmuhs/ccache-action) to cache host C/C++ compilation for LLVM and COMPAS. The 2 GB cache is scoped by OS, LLVM release, build configuration and C++ standard. Source changes can reuse unchanged compilation results; a cold cache still requires the full build. Linking and the RISC-V regression programs are not cached by this launcher. The action reports cache statistics at the end of the LLVM build job.

For local builds, install `sccache` or `ccache` and add both launcher options to the LLVM configure command above:

```sh
-DCMAKE_C_COMPILER_LAUNCHER=sccache \
-DCMAKE_CXX_COMPILER_LAUNCHER=sccache
```

When using `configure_llvm` from `docker/setup_debian.sh`, set `COMPAS_COMPILER_LAUNCHER=sccache` (or `ccache`) before calling it. The launcher must be on `PATH`, or specified as an executable path. Unset this variable and rerun `configure_llvm` to disable caching; the helper clears both launcher entries even in an existing build directory. Direct CMake users can clear the two options by setting them to empty strings. Use compiler launchers without also enabling `LLVM_CCACHE_BUILD`.

This cache belongs to the LLVM CI build job. Docker image builds do not yet restore this compiler cache across workflow runs.

### Functional validation

Use the [shared test runner](../tests/README.adoc) to build unprotected references, run programs through the COMPAS flow and compare their functional behavior against independent expected results. `python3 tests/run.py --list` lists available cases without requiring tools. The runners under `tests/regression` and `tests/apps` select each group; use manifests to add cases without writing a separate build/run script. The current suite checks fault-free equivalence, not fault-detection capability or coverage.

Runtime validation requires a RISC-V GNU toolchain for assembly and linking, QEMU user-mode executables for freestanding regressions, and Spike with a matching proxy kernel (`pk`) for CMake applications. Application builds also need the toolchain's C library headers. For example, run the CRC configuration through the shared harness:

```sh
python3 tests/apps/run.py --case 'crc/*' \
  --llvm-root "${LLVM_BUILD}" \
  --riscv-prefix /path/to/riscv-toolchain \
  --riscv-basename riscv-none-elf \
  --spike /path/to/riscv-toolchain/bin/spike \
  --pk /path/to/riscv-toolchain/riscv-none-elf/bin/pk \
  --mode NZDC+NEMESEC --cfp RASM \
  --functions 'crcSlow;crcFast' --cfp-functions 'crcSlow;crcFast'
```

The runner requires execution tools, retains build and runtime logs, and writes `build/tests/results.json`. Known runtime failures must match explicit manifest expectations; build failures and missing tools remain failures. An unexpected pass fails by default so that the known-failure entry can be updated. See the [test documentation](../tests/README.adoc) for tool environment variables, selection options and manifest examples.

For a direct CMake build while debugging the application integration, use the following commands. Replace the installation prefix and executable basename with those of your toolchain. `COMPAS_LLVM_ROOT` may point to the LLVM build directory above or to an installed COMPAS-enabled LLVM prefix.

```sh
RISCV_PREFIX=/path/to/riscv-toolchain
RISCV_BASENAME=riscv-none-elf

cmake -S tests/apps/crc -B build/crc-nemesec-rasm \
  -DCOMPAS_LLVM_ROOT="${LLVM_BUILD}" \
  -DRISCV_TOOLCHAIN_PREFIX="${RISCV_PREFIX}" \
  -DRISCV_TOOLCHAIN_BASENAME="${RISCV_BASENAME}" \
  -DRISCV_ISA=rv64gc \
  '-DDMR_MOD=NZDC+NEMESEC' '-DDMR_FUNCTIONS=crcSlow;crcFast' \
  -DCFP_MOD=RASM '-DCFP_FUNCTIONS=crcSlow;crcFast'
cmake --build build/crc-nemesec-rasm --parallel 2
"${RISCV_PREFIX}/bin/spike" \
  "${RISCV_PREFIX}/${RISCV_BASENAME}/bin/pk" \
  build/crc-nemesec-rasm/crc
```

Function selections are CMake lists separated by semicolons; the consumer helper converts them to comma-separated `llc` arguments. Use separate build directories for unprotected, individual-pass and combined-pass configurations. The direct CMake build does not perform the shared runner's reference and expected-output comparisons. A zero host exit status alone is insufficient evidence of correct execution, since target error exits may be truncated by the execution environment.

Run checks appropriate to the change. Use small C/C++ or LLVM IR reproducers and inspect emitted assembly as well as execution results. Check fault-free equivalence to an unprotected reference, selected and unselected functions, calls and returns, branch successors and signature adjustments, and primary/shadow register consistency. Cover RV32/RV64, enabled ISA extensions, code models and scheduling modes where the affected contract requires them. Record exact commands, tool revisions, random seeds where applicable, results and untested configurations.

For fault-detection changes, report the injected instruction or data faults, their locations and timing, and which preparation, checks and error paths are assumed intact. Distinguish fault-free regression results from fault-injection evidence or a formal proof. Preserve known counterexamples as regression cases and document unsupported patterns rather than silently broadening a protection claim.

For performance or benchmark claims, compare matched source programs, inputs, target ISA/ABI, LLVM revisions, optimization flags and protection settings. Report compilation cost, binary size and execution overhead separately. For fault campaigns, include the fault model, campaign size, seeds and outcome classification. Keep generated IR, assembly, executables and logs under an ignored `build/` directory, and include concise results and reproduction commands in the contribution.

## Documentation

The LaTeX user manual and published PDFs live in [docs/manual](manual/). Install `latexmk` and the LaTeX packages used by [main.tex](manual/src/main.tex), then run this from the repository root:

```sh
latexmk -cd -pdf -outdir="$(pwd)/build/manual" docs/manual/src/main.tex
```

The `-cd` option resolves included sources and figures from `docs/manual/src`. Open `build/manual/main.pdf` to review the result. The source contains an `@VERSION@` placeholder that the [documentation workflow](../.github/workflows/doc.yml) replaces for releases. Keep generated build files out of the source directory; update published PDFs only when preparing the corresponding documentation release. Documentation-only changes need link, path and formatting checks, plus a manual build when changing LaTeX sources or build instructions.

## Issues and pull requests

For a bug report, include the expected and observed behavior, COMPAS and LLVM revisions, host compiler, target ISA/ABI, optimization level, code model, protection options and function selections. Provide exact `clang`, `llc`, assembler/linker and runtime commands, diagnostics and a small C/C++ or LLVM IR reproducer. Include emitted assembly or machine IR when it helps locate a pass failure. For runtime failures, identify the simulator or hardware and distinguish an error-handler transfer from a crash or an incorrect result.

Keep each commit focused on one logical change. A pull request should explain the motivation, resulting behavior, validation and material limitations. Link related issues and document architecture or interface decisions where they are defined. Preserve upstream notices when importing code; see [LICENSE](../LICENSE) for the repository's license text.

## Commit messages

Use an emoji prefix, a brief lower-case subject ending in a colon, a blank line, then three or four lines summarizing the motivation/cause, change and effect:

```text
<emoji> <brief>:

<details>
```

Start the first detail sentence in lower case as a continuation of the subject's colon. Capitalize subsequent sentences normally. Preserve conventional casing for identifiers and acronyms such as `LLVM`, `RISC-V`, `NZDC`, `RASM` and `MachineFunction`. Hard line breaks are allowed. The details are optional for sufficiently small and clear commits.

| Prefix | Type |
| --- | --- |
| 🐛 | Bug fix |
| 🔥 | Hotfix |
| 💡 | Feature |
| 📝 | Documentation |
| ⚙️ | CI and build automation |

For example:

```text
🐛 preserve signature updates across local branches:

local jumps were handled as calls and skipped the edge adjustment.
Recognize their basic-block targets before processing call boundaries.
Keep the runtime signature consistent on taken and fallthrough paths.
```
