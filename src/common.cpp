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

#include "common.h"

#include <algorithm>
#include <sstream>

#include "RISCVSubtarget.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/Support/MathExtras.h"

namespace {

struct SpillSlot {
  llvm::Register reg;
  unsigned store_opcode;
  unsigned load_opcode;
  unsigned width;
  unsigned offset;
};

SpillSlot spill_slot(llvm::Register reg,
                     const riscv_common::ISAConfig &isa_config,
                     const llvm::RISCVSubtarget &subtarget) {
  unsigned fp_index = 0;
  switch (riscv_common::getRegType(reg)) {
  case riscv_common::RegType::I:
    return {reg, isa_config.store_opcode, isa_config.load_opcode,
            isa_config.word_length, 0};
  case riscv_common::RegType::FS:
    fp_index = reg - llvm::RISCV::F0_F;
    break;
  case riscv_common::RegType::FD:
    fp_index = reg - llvm::RISCV::F0_D;
    break;
  case riscv_common::RegType::FH:
    fp_index = reg - llvm::RISCV::F0_H;
    break;
  }
  // Liveness can contain subregister and superregister aliases even when a
  // view's instruction set is unavailable. Preserve the physical register's
  // enabled FLEN once, independently of XLEN or the supplied alias.
  if (subtarget.hasStdExtD())
    return {llvm::RISCV::F0_D + fp_index, llvm::RISCV::FSD, llvm::RISCV::FLD,
            std::max(isa_config.word_length, 8u), 0};
  assert(subtarget.hasStdExtF() && "FP spill requires the F extension");
  return {llvm::RISCV::F0_F + fp_index, llvm::RISCV::FSW, llvm::RISCV::FLW,
          std::max(isa_config.word_length, 4u), 0};
}

struct SpillFrame {
  std::vector<SpillSlot> slots;
  unsigned size;
};

SpillFrame spill_frame(const std::vector<llvm::Register> &regs,
                       const llvm::MachineFunction &MF) {
  riscv_common::ISAConfig isa_config{MF};
  const auto &subtarget = MF.getSubtarget<llvm::RISCVSubtarget>();
  SpillFrame frame{{}, 0};
  for (auto reg : regs) {
    auto slot = spill_slot(reg, isa_config, subtarget);
    bool already_saved = false;
    if (riscv_common::getRegType(reg) != riscv_common::RegType::I) {
      // LivePhysRegs includes overlapping FP views. Reloading a narrower
      // alias last would otherwise destroy the upper bits of a live double.
      for (auto &existing : frame.slots) {
        if (existing.reg == slot.reg) {
          already_saved = true;
          break;
        }
      }
    }
    if (!already_saved)
      frame.slots.push_back(slot);
  }
  for (auto &slot : frame.slots) {
    frame.size = llvm::alignTo(frame.size, slot.width);
    slot.offset = frame.size;
    frame.size += slot.width;
  }
  frame.size = llvm::alignTo(frame.size, 16);
  return frame;
}

} // namespace

bool riscv_common::inCSString(std::string cs_string, std::string x) {
  std::istringstream iss{cs_string};
  std::string f{};
  if (cs_string == "-1")
    return true;
  while (std::getline(iss, f, ',')) {
    if (x.compare(f) == 0) {
      return true;
    }
  }

  return false;
}

riscv_common::ISAConfig::ISAConfig(const llvm::MachineFunction &MF) {
  if (MF.getSubtarget<llvm::RISCVSubtarget>().is64Bit()) {
    word_length = 8;
    store_opcode = llvm::RISCV::SD;
    load_opcode = llvm::RISCV::LD;
  }
}

riscv_common::RegType riscv_common::getRegType(llvm::Register r) {
  if (r >= llvm::RISCV::X0 && r <= llvm::RISCV::X31) {
    return RegType::I;
  } else if (r >= llvm::RISCV::F0_F && r <= llvm::RISCV::F31_F) {
    return RegType::FS;
  } else if (r >= llvm::RISCV::F0_D && r <= llvm::RISCV::F31_D) {
    return RegType::FD;
  } else if (r >= llvm::RISCV::F0_H && r <= llvm::RISCV::F31_H) {
    return RegType::FH;
  } else {
    assert(0 && "invalid register passed in");
  }
}

void riscv_common::saveRegs(std::vector<llvm::Register> regs,
                            llvm::MachineBasicBlock *MBB,
                            llvm::MachineBasicBlock::iterator mbb_it,
                            llvm::Register sp) {
  if (regs.size() == 0) {
    return;
  }

  auto DLL{MBB->front().getDebugLoc()};
  auto TII{MBB->getParent()->getSubtarget().getInstrInfo()};
  const auto frame = spill_frame(regs, *MBB->getParent());

  // allocating space on stack
  if (sp != kSP) {
    llvm::BuildMI(*MBB, mbb_it, DLL, TII->get(llvm::RISCV::ADDI))
        .addReg(sp, llvm::RegState::Define)
        .addReg(sp)
        .addImm(-static_cast<int64_t>(frame.size));
  }
  llvm::BuildMI(*MBB, mbb_it, DLL, TII->get(llvm::RISCV::ADDI))
      .addReg(kSP, llvm::RegState::Define)
      .addReg(kSP)
      .addImm(-static_cast<int64_t>(frame.size));

  // now saving onto stack one by one
  for (const auto &slot : frame.slots) {
    llvm::BuildMI(*MBB, mbb_it, DLL, TII->get(slot.store_opcode))
        .addReg(slot.reg)
        .addReg(kSP)
        .addImm(slot.offset);
  }
}

void riscv_common::loadRegs(std::vector<llvm::Register> regs,
                            llvm::MachineBasicBlock *MBB,
                            llvm::MachineBasicBlock::iterator mbb_it,
                            llvm::Register sp) {
  if (regs.size() == 0) {
    return;
  }

  auto DLL{MBB->front().getDebugLoc()};
  auto TII{MBB->getParent()->getSubtarget().getInstrInfo()};
  const auto frame = spill_frame(regs, *MBB->getParent());

  // loading from stack one by one
  for (const auto &slot : frame.slots) {
    llvm::BuildMI(*MBB, mbb_it, DLL, TII->get(slot.load_opcode))
        .addReg(slot.reg, llvm::RegState::Define)
        .addReg(sp)
        .addImm(slot.offset);
  }

  // now deallocating space on stack
  if (sp != kSP) {
    llvm::BuildMI(*MBB, mbb_it, DLL, TII->get(llvm::RISCV::ADDI))
        .addReg(sp, llvm::RegState::Define)
        .addReg(sp)
        .addImm(frame.size);
  }
  llvm::BuildMI(*MBB, mbb_it, DLL, TII->get(llvm::RISCV::ADDI))
      .addReg(kSP, llvm::RegState::Define)
      .addReg(kSP)
      .addImm(frame.size);
}
