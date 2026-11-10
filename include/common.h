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

#include <map>
#include <set>

#include "RISCV.h"
#include "llvm/CodeGen/MachineBasicBlock.h"

namespace riscv_common {
// Composable instruction provenance classes selected on CFP function names.
enum class RsmCategory : unsigned { Original = 1, Dmr = 2, Balance = 4 };
constexpr unsigned kRsmAll = 7;
unsigned getRsmInstructionMask(const llvm::MachineFunction &MF,
                               const std::string &selection);

// ISA-wise settings
struct ISAConfig {
  // default initialized for riscv32
  unsigned word_length{4};
  unsigned store_opcode{llvm::RISCV::SW};
  unsigned load_opcode{llvm::RISCV::LW};

  ISAConfig() = default;
  explicit ISAConfig(const llvm::MachineFunction &MF);
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
// Realigned variable-sized DMR frames reserve t1/t5 as an independent BP
// pair. Ordinary ABI calls can clobber both; COMPAS preserves them at calls.
const unsigned kDmrBP{llvm::RISCV::X6};

RegType getRegType(llvm::Register);
bool isDmrFunction(const std::string &name);
bool usesDmrBasePointer(const llvm::MachineFunction &MF);
// Stable before/after RA: identify EDDI variable frames and pointer-typed IR
// merges. Their bank appends GPR deltas and one delta per ordinary FI;
// variable frames reserve three outgoing-call words, plus two BP words when
// realigned fixed locals need a stable base independent of the moving SP.
bool usesPointerProvenance(const llvm::MachineFunction &MF);
// Entry bank: immutable register/stack formal deltas, plus one word preserving
// the actual shadow RA while the two incoming stack banks are read.
unsigned incomingPointerDeltaSlots(const llvm::MachineFunction &MF);
unsigned pointerProvenanceSlots(const llvm::MachineFunction &MF);
// Finalize emitted instrumentation without changing instruction order or
// assigning signatures to the continuation blocks introduced here. An optional
// selection splits only monitored conditionals before RSM region assignment.
void normalizeControlFlow(
    llvm::MachineFunction &MF,
    const std::set<const llvm::MachineInstr *> *selected_branches = nullptr);
// Runtime control-flow state owned by the selected signature scheme.
std::vector<llvm::Register> signatureRegisters(const std::string &name);
std::vector<llvm::Register> signatureRegisters(const llvm::MachineFunction &MF);
// Compiler-generated prologue/epilogue helpers have a special calling
// convention: the save helper links through t0 before FP exists, and restore
// tail-returns after removing the frame. Ordinary calls with similar names
// must retain their normal handling.
enum class FrameHelper { None, Save, Restore };
FrameHelper frameHelper(const llvm::MachineInstr &);
// Signatures start after an entry save helper, before the remaining prologue.
// A forced shrink-wrapped helper needs preservation of incoming signature
// history, which this entry-only contract cannot provide.
llvm::MachineBasicBlock::iterator
signatureEntryInsertion(llvm::MachineFunction &);
// Preserve actual signature state in the preallocated fixed frame, without
// moving the outgoing argument area at the call. Scratch must be reserved.
void preserveSignatureAcrossCall(llvm::MachineInstr *call,
                                 const std::vector<llvm::Register> &regs,
                                 llvm::Register scratch);
// Preserve selective-call context in a preallocated fixed frame. These helpers
// leave both stack pointers unchanged at the call boundary.
// A duplicated libcall keeps its post-call ABI values in a separate bank
// while the caller's original monitor state remains saved in Caller.
enum class CallFrameBank {
  Caller,
  Libcall,
  BasePointer,
  Repair,
  RepairPrimaryResult,
  RepairShadowResult
};
// Supported RISC-V ABIs return at most two registers, each at most 64 bits.
// The result snapshot also retains the ABI's sixteen-byte stack alignment.
constexpr unsigned kLibcallResultFrameSize = 16;
// Non-EDDI realigned dynamic frames retain both actual BP banks across calls.
// Two XLEN words fit in one ABI-aligned area on RV32 and RV64.
constexpr unsigned kBasePointerCallFrameSize = 16;
// REPAIR snapshots both physical banks before canonicalizing call arguments.
// The two result banks must survive restoration of that immutable snapshot.
constexpr unsigned kRepairResultFrameSize = 16;
unsigned repairCallFrameSize(const llvm::MachineFunction &MF);
void saveCallRegs(const std::vector<llvm::Register> &, llvm::MachineBasicBlock *,
                  llvm::MachineBasicBlock::iterator,
                  CallFrameBank = CallFrameBank::Caller);
void loadCallRegs(const std::vector<llvm::Register> &, llvm::MachineBasicBlock *,
                  llvm::MachineBasicBlock::iterator,
                  CallFrameBank = CallFrameBank::Caller);
// Read selected source slots using exactly snapshot_regs' spill layout and
// assign their values to the mapped destinations. FP aliases use the physical
// register's full enabled FLEN, matching saveCallRegs' alias deduplication.
void loadCallRegsAs(const std::vector<llvm::Register> &snapshot_regs,
                    const std::map<llvm::Register, llvm::Register> &copies,
                    llvm::MachineBasicBlock *,
                    llvm::MachineBasicBlock::iterator, CallFrameBank);
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
