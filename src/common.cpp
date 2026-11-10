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
#include <iterator>
#include <sstream>

#include "RISCVFrameLowering.h"
#include "RISCVInstrInfo.h"
#include "RISCVMachineFunctionInfo.h"
#include "RISCVSubtarget.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineMemOperand.h"
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

std::vector<llvm::Register>
riscv_common::signatureRegisters(const llvm::MachineFunction &MF) {
  const std::string name{MF.getName()};
  if (inCSString(llvm::cl::enable_cfcss, name))
    return {llvm::RISCV::X5, llvm::RISCV::X29};
  if (inCSString(llvm::cl::enable_rasm, name) ||
      inCSString(llvm::cl::enable_racfed, name))
    return {llvm::RISCV::X5};
  return {};
}

void riscv_common::preserveSignatureAcrossCall(
    llvm::MachineInstr *call, const std::vector<llvm::Register> &regs,
    llvm::Register scratch) {
  assert(call->isCall() && !regs.empty() &&
         "Expected a call with signature state");
  auto *MBB = call->getParent();
  auto *MF = MBB->getParent();
  const int frame_index = MF->getInfo<llvm::RISCVMachineFunctionInfo>()
                              ->getCompasSignatureFrameIndex();
  if (frame_index >= 0)
    llvm::report_fatal_error("COMPAS: signature call frame was not prepared");

  const auto &subtarget = MF->getSubtarget<llvm::RISCVSubtarget>();
  const auto *tii = subtarget.getInstrInfo();
  const ISAConfig isa_config{*MF};
  assert(regs.size() * isa_config.word_length <=
             static_cast<uint64_t>(
                 MF->getFrameInfo().getObjectSize(frame_index)) &&
         "Signature frame is too small");
  llvm::Register frame_reg;
  const auto offset = subtarget.getFrameLowering()->getFrameIndexReference(
      *MF, frame_index, frame_reg);
  if (offset.getScalable())
    llvm::report_fatal_error("COMPAS: scalable signature frame unsupported");

  const auto DL = call->getDebugLoc();
  const bool large_offset =
      !llvm::isInt<12>(offset.getFixed()) ||
      !llvm::isInt<12>(
          offset.getFixed() +
          static_cast<int64_t>((regs.size() - 1) * isa_config.word_length));
  const bool scratch_is_state =
      std::find(regs.begin(), regs.end(), scratch) != regs.end();

  auto access = [&](llvm::MachineBasicBlock::iterator insert, bool restore,
                    llvm::Register value, llvm::Register base,
                    int64_t displacement, unsigned index) {
    auto *memory = MF->getMachineMemOperand(
        llvm::MachinePointerInfo::getFixedStack(*MF, frame_index,
                                                index * isa_config.word_length),
        restore ? llvm::MachineMemOperand::MOLoad
                : llvm::MachineMemOperand::MOStore,
        isa_config.word_length, llvm::Align(isa_config.word_length));
    llvm::BuildMI(
        *MBB, insert, DL,
        tii->get(restore ? isa_config.load_opcode : isa_config.store_opcode))
        .addReg(value, restore ? llvm::RegState::Define : 0)
        .addReg(base)
        .addImm(displacement)
        .addMemOperand(memory);
  };

  auto preserve = [&](llvm::MachineBasicBlock::iterator insert, bool restore) {
    llvm::Register base = frame_reg;
    int64_t displacement = offset.getFixed();
    llvm::Register buffer{0};
    if (large_offset) {
      if (!restore && scratch_is_state) {
        // CFCSS owns both reserved registers. Temporarily spill the payload
        // before borrowing D for address formation; restore SP before the call.
        auto other =
            std::find_if(regs.begin(), regs.end(),
                         [&](llvm::Register r) { return r != scratch; });
        assert(other != regs.end() && "No signature value buffer available");
        buffer = *other;
        saveRegs(regs, MBB, insert);
      }
      tii->movImm(*MBB, insert, DL, scratch, displacement);
      llvm::BuildMI(*MBB, insert, DL, tii->get(llvm::RISCV::ADD))
          .addReg(scratch, llvm::RegState::Define)
          .addReg(frame_reg)
          .addReg(scratch);
      base = scratch;
      displacement = 0;
    }

    for (unsigned i = 0; i != regs.size(); ++i) {
      if (restore && large_offset && regs[i] == scratch)
        continue; // Reload the address register last.
      llvm::Register value = regs[i];
      if (buffer) {
        llvm::BuildMI(*MBB, insert, DL, tii->get(isa_config.load_opcode))
            .addReg(buffer, llvm::RegState::Define)
            .addReg(kSP)
            .addImm(i * isa_config.word_length);
        value = buffer;
      }
      access(insert, restore, value, base,
             displacement + i * isa_config.word_length, i);
    }
    if (restore && large_offset && scratch_is_state) {
      auto index = std::find(regs.begin(), regs.end(), scratch) - regs.begin();
      access(insert, true, scratch, base,
             displacement + index * isa_config.word_length, index);
    }
    if (buffer)
      loadRegs(regs, MBB, insert);
  };
  preserve(call->getIterator(), false);
  preserve(std::next(call->getIterator()), true);
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
