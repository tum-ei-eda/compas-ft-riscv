/*
 * Copyright 2026 Chair of EDA, Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "common.h"

#include <map>
#include <set>

namespace riscv_common {

// Owned by the target's MachineFunctionInfo, never by a process-wide pointer
// registry. Instruction identities survive block splits and instruction moves.
struct RsmFunctionInfo {
  const llvm::MachineFunction *owner = nullptr;
  bool recorded = false;
  std::map<const llvm::MachineInstr *, RsmCategory> instructions;
  std::set<const llvm::MachineBasicBlock *> duplicate_blocks;
  std::set<const llvm::MachineBasicBlock *> error_blocks;
};

RsmFunctionInfo &rsmFunctionInfo(llvm::MachineFunction &MF);
void captureOriginalRsmInstructions(llvm::MachineFunction &MF);
void recordNewRsmInstructions(llvm::MachineFunction &MF, RsmCategory category);
void setRsmInstructionCategory(llvm::MachineInstr &MI, RsmCategory category);

// A logical view of the existing machine CFG. Excluded DMR checking bridges
// remain executable, but are traversed without a separate block signature.
class RsmRegions {
public:
  RsmRegions(llvm::MachineFunction &MF, const std::string &selection);

  bool isTransparent(const llvm::MachineBasicBlock *MBB) const;
  llvm::MachineBasicBlock *resolve(llvm::MachineBasicBlock *MBB) const;
  bool monitorsInstruction(const llvm::MachineInstr &MI) const;
  bool monitorsBranch(const llvm::MachineInstr &MI) const;
  std::set<llvm::MachineBasicBlock *>
  predecessors(llvm::MachineBasicBlock *MBB) const;

private:
  RsmFunctionInfo &info_;
  unsigned mask_;
};

// Split real conditional transfers and restore PHI/CFG/liveness metadata.
// Selected branches are split before choosing regions. Every mode can call
// this after inserting monitoring code without signing those new checks.
void normalizeRsmControlFlow(llvm::MachineFunction &MF);

} // namespace riscv_common
