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

#include "RISCVRsm.h"

#include "RISCVMachineFunctionInfo.h"
#include "RISCVSubtarget.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"

#include <algorithm>
#include <memory>
#include <vector>

namespace {

bool is_error_block(const llvm::MachineBasicBlock *MBB,
                    const riscv_common::RsmFunctionInfo &info) {
  return info.error_blocks.count(MBB) ||
         (MBB->succ_size() == 1 && *MBB->succ_begin() == MBB);
}

} // namespace

riscv_common::RsmFunctionInfo &
riscv_common::rsmFunctionInfo(llvm::MachineFunction &MF) {
  auto *target_info = MF.getInfo<llvm::RISCVMachineFunctionInfo>();
  auto info = target_info->getCompasRsmInfo();
  // LLVM can copy target MFI while cloning a function. Never let a copied
  // shared_ptr expose instruction identities belonging to another function.
  if (!info || info->owner != &MF) {
    info = std::make_shared<RsmFunctionInfo>();
    info->owner = &MF;
    target_info->setCompasRsmInfo(info);
  }
  return *info;
}

void riscv_common::captureOriginalRsmInstructions(llvm::MachineFunction &MF) {
  auto &info = rsmFunctionInfo(MF);
  info.instructions.clear();
  info.duplicate_blocks.clear();
  info.error_blocks.clear();
  for (const auto &MBB : MF)
    for (const auto &MI : MBB)
      info.instructions.emplace(&MI, RsmCategory::Original);
  info.recorded = true;
}

void riscv_common::recordNewRsmInstructions(llvm::MachineFunction &MF,
                                            RsmCategory category) {
  auto &info = rsmFunctionInfo(MF);
  for (const auto &MBB : MF)
    for (const auto &MI : MBB)
      info.instructions.emplace(&MI, category);
}

void riscv_common::setRsmInstructionCategory(llvm::MachineInstr &MI,
                                             RsmCategory category) {
  auto &MF = *MI.getParent()->getParent();
  rsmFunctionInfo(MF).instructions[&MI] = category;
}

riscv_common::RsmRegions::RsmRegions(llvm::MachineFunction &MF,
                                     const std::string &selection)
    : info_(rsmFunctionInfo(MF)), mask_(getRsmInstructionMask(MF, selection)) {
  // Standalone RSM invocations need no preceding DMR pass. In that case every
  // current instruction is application code, exactly as it is at DMR entry.
  if (!info_.recorded)
    captureOriginalRsmInstructions(MF);

  // Split selected conditionals before assigning region signatures. Unknown
  // instructions inserted by another RSM pass never acquire a category here.
  std::set<const llvm::MachineInstr *> selected_branches;
  for (const auto &MBB : MF)
    for (const auto &MI : MBB)
      if (MI.isConditionalBranch() && monitorsInstruction(MI))
        selected_branches.insert(&MI);
  normalizeControlFlow(MF, &selected_branches);
}

bool riscv_common::RsmRegions::isTransparent(
    const llvm::MachineBasicBlock *MBB) const {
  if (!info_.duplicate_blocks.count(MBB))
    return false;
  return std::none_of(MBB->begin(), MBB->end(), [this](const auto &MI) {
    return monitorsInstruction(MI);
  });
}

llvm::MachineBasicBlock *
riscv_common::RsmRegions::resolve(llvm::MachineBasicBlock *MBB) const {
  std::set<llvm::MachineBasicBlock *> visited;
  while (MBB && isTransparent(MBB)) {
    if (!visited.insert(MBB).second)
      return nullptr;
    llvm::MachineBasicBlock *successor = nullptr;
    for (auto *candidate : MBB->successors()) {
      if (is_error_block(candidate, info_))
        continue;
      if (successor && successor != candidate)
        return nullptr;
      successor = candidate;
    }
    MBB = successor;
  }
  return MBB && !is_error_block(MBB, info_) ? MBB : nullptr;
}

bool riscv_common::RsmRegions::monitorsInstruction(
    const llvm::MachineInstr &MI) const {
  const auto found = info_.instructions.find(&MI);
  return found != info_.instructions.end() &&
         (mask_ & static_cast<unsigned>(found->second));
}

bool riscv_common::RsmRegions::monitorsBranch(
    const llvm::MachineInstr &MI) const {
  return MI.isBranch() && monitorsInstruction(MI);
}

std::set<llvm::MachineBasicBlock *>
riscv_common::RsmRegions::predecessors(llvm::MachineBasicBlock *MBB) const {
  std::set<llvm::MachineBasicBlock *> result, visited;
  std::vector<llvm::MachineBasicBlock *> pending(MBB->pred_begin(),
                                                 MBB->pred_end());
  while (!pending.empty()) {
    auto *predecessor = pending.back();
    pending.pop_back();
    if (!visited.insert(predecessor).second ||
        is_error_block(predecessor, info_))
      continue;
    if (!isTransparent(predecessor)) {
      result.insert(predecessor);
      continue;
    }
    pending.insert(pending.end(), predecessor->pred_begin(),
                   predecessor->pred_end());
  }
  return result;
}

void riscv_common::normalizeRsmControlFlow(llvm::MachineFunction &MF) {
  normalizeControlFlow(MF);
}
