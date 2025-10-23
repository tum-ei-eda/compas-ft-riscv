/*
 * Copyright 2021 Chair of EDA, Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "RISCV.h"
#include "llvm/CodeGen/MachineBasicBlock.h"

namespace riscv_common {
// ISA-wise settings
struct ISAConfig {
  // default initialized for riscv32
  unsigned word_length{4};
  unsigned store_opcode{llvm::RISCV::SW};
  unsigned load_opcode{llvm::RISCV::LW};

  ISAConfig();
};
// Reg Types
enum class RegType { I, FS, FD, FH };
// ED0: on error-detection, jump to error-block and keep executing it
// ED1: same as ED0 but it quits after notifying safety-unit
// ED2: on error-detection, call a function passing the specific checker's
//      code
// ED3: on error-detection, invoke ecall with riscv-newlib codes: a7=SYS_exit=93
// see: https://github.com/riscv-collab/riscv-newlib/blob/master/libgloss/riscv/machine/syscall.h
// with error code in a0 indicating control flow error (-256) or dataflow error
// (-512) 
enum class ErrorDetectionStrategy { ED0, ED1, ED2, ED3 }; // TODO: these do not have a reasonable command line interface yet

// for convenience:
// zero register
const unsigned k0{llvm::RISCV::X0};
// return address register
const unsigned kRA{llvm::RISCV::X1};
// stack pointer register
const unsigned kSP{llvm::RISCV::X2};
// global pointer register
const unsigned kGP{llvm::RISCV::X3};
// thread pointer register
const unsigned kTP{llvm::RISCV::X4};
// frame pointer register
const unsigned kFP{llvm::RISCV::X8};

RegType getRegType(llvm::Register);
// save registers in the vector one by one onto the stack and do this
// at the instruction point pointed to by iterator
void saveRegs(std::vector<llvm::Register>, llvm::MachineBasicBlock*,
              llvm::MachineBasicBlock::iterator, llvm::Register sp = kSP);
// load regs to the vector ony by one from the stack and do this
// at the instruction point pointed to by iterator
void loadRegs(std::vector<llvm::Register>, llvm::MachineBasicBlock*,
              llvm::MachineBasicBlock::iterator, llvm::Register sp = kSP);

template <class ContainerT, class ValueT>
bool setmapContains(const ContainerT& c, const ValueT& v) {
  return (c.find(v) != c.end());
}

template <class MapT, class ValueT>
bool mapValContains(const MapT& m, const ValueT& v) {
  for (const auto& p : m) {
    if (p.second == v) {
      return true;
    }
  }
  return false;
}
}  // namespace riscv_common
