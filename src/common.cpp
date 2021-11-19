/*
 * Copyright [2020] [Technical University of Munich]
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

#include <sstream>

#include "RISCVSubtarget.h"
#include "llvm/CodeGen/CommandFlags.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"

bool riscv_common::inCSString(std::string cs_string, std::string x) {
  std::istringstream iss{cs_string};
  std::string f{};
  while (std::getline(iss, f, ',')) {
    if (x.compare(f) == 0) {
      return true;
    }
  }

  return false;
}

riscv_common::ISAConfig::ISAConfig() {
  auto march{llvm::codegen::getMArch()};

  if (march == "riscv64") {
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
  ISAConfig isa_config{};
  auto store_opcode{isa_config.store_opcode};

  // allocating space on stack
  if (sp != kSP) {
    llvm::BuildMI(*MBB, mbb_it, DLL, TII->get(llvm::RISCV::ADDI))
        .addReg(sp)
        .addReg(sp)
        .addImm(-regs.size() * isa_config.word_length);
  }
  llvm::BuildMI(*MBB, mbb_it, DLL, TII->get(llvm::RISCV::ADDI))
      .addReg(kSP)
      .addReg(kSP)
      .addImm(-regs.size() * isa_config.word_length);

  // now saving onto stack one by one
  unsigned stack_offset{0};
  for (const auto &r : regs) {
    if (getRegType(r) != RegType::I) {
      store_opcode = (isa_config.store_opcode == llvm::RISCV::SW)
                         ? llvm::RISCV::FSW
                         : llvm::RISCV::FSD;
    } else {
      store_opcode = isa_config.store_opcode;
    }

    llvm::BuildMI(*MBB, mbb_it, DLL, TII->get(store_opcode))
        .addReg(r)
        .addReg(kSP)
        .addImm(stack_offset);
    stack_offset += isa_config.word_length;
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
  ISAConfig isa_config{};
  auto load_opcode{isa_config.load_opcode};

  // loading from stack one by one
  unsigned stack_offset{0};
  for (auto &r : regs) {
    if (getRegType(r) != RegType::I) {
      load_opcode = (isa_config.load_opcode == llvm::RISCV::LW)
                        ? llvm::RISCV::FLW
                        : llvm::RISCV::FLD;
    } else {
      load_opcode = isa_config.load_opcode;
    }

    llvm::BuildMI(*MBB, mbb_it, DLL, TII->get(load_opcode))
        .addReg(r)
        .addReg(sp)
        .addImm(stack_offset);
    stack_offset += isa_config.word_length;
  }

  // now deallocating space on stack
  if (sp != kSP) {
    llvm::BuildMI(*MBB, mbb_it, DLL, TII->get(llvm::RISCV::ADDI))
        .addReg(sp)
        .addReg(sp)
        .addImm(regs.size() * isa_config.word_length);
  }
  llvm::BuildMI(*MBB, mbb_it, DLL, TII->get(llvm::RISCV::ADDI))
      .addReg(kSP)
      .addReg(kSP)
      .addImm(regs.size() * isa_config.word_length);
}
