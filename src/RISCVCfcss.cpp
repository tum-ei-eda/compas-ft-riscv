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

#include "RISCVCfcss.h"

#include "RISCVSubtarget.h"
#include "llvm/CodeGen/CommandFlags.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"

llvm::FunctionPass *llvm::createRISCVCfcss() { return new RISCVCfcss(); }

RISCVCfcss::RISCVCfcss() : RISCVDmr{} {}

bool RISCVCfcss::runOnMachineFunction(llvm::MachineFunction &MF) {
  MF_ = &MF;
  TII_ = MF_->getSubtarget().getInstrInfo();

  if (!riscv_common::inCSString(llvm::cl::enable_cfcss,
                                std::string{MF_->getName()})) {
    return false;
  }

  llvm::outs() << "Running CFCSS pass on " << MF_->getName() << "\n";

  for (auto &MBB : *MF_) {
    for (auto &MI : MBB) {
      if (MI.getOpcode() == llvm::RISCV::PseudoBRIND) {
        llvm::outs() << "\t NOTE: the source has switch semantics which are "
                        "not supported yet!\n";
        llvm::outs() << "\t no CFCSS done here\n";
        return false;
      }
    }
  }

  init();
  harden();

  return true;
}

void RISCVCfcss::init() {
  // reset
  mbb_info_.clear();
  cf_err_bb_ = nullptr;

  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED1) {
    // insert an error-BB in MF_
    insertErrorBB();
  } else {
    assert(0 && "TODO");
  }

  // filling up MBBInfo struct for each MBB
  // NOTE: here we use a simple strategy of using incrementing count as
  // signature for each MBB. I guess its ok considering we just have to ensure
  // unique signatures for each block
  unsigned cnt{0};
  for (auto &MBB : *MF_) {
    for (auto PBB : MBB.predecessors()) {
      mbb_info_[&MBB].predecessors.emplace(PBB);
    }
    if (mbb_info_[&MBB].predecessors.size() > 1) {
      mbb_info_[&MBB].is_fanin = true;
    }
    mbb_info_[&MBB].s = cnt++;
  }
  for (auto &MBB : *MF_) {
    auto PBB{*std::begin(mbb_info_[&MBB].predecessors)};
    mbb_info_[&MBB].s_i1 = mbb_info_[PBB].s;
    mbb_info_[&MBB].d = mbb_info_[PBB].s ^ mbb_info_[&MBB].s;
  }

  // setting G to entry-BB signature at start of MF_
  llvm::BuildMI(MF_->front(), std::begin(MF_->front()),
                MF_->front().front().getDebugLoc(),
                TII_->get(llvm::RISCV::ADDI))
      .addReg(kG)
      .addReg(riscv_common::k0)
      .addImm(mbb_info_[&MF_->front()].s);
}

// CFCSS hardening scheme
void RISCVCfcss::harden() {
  // iterating over all MBBs in MF
  for (auto &MBB : *MF_) {
    // ignoring entryBB
    if (MBB.pred_empty()) {
      continue;
    }

    // there could be err-BBs from other passes
    // the convention is if a BB keeps jumping to itself then this is also
    // an error-BB
    if (MBB.succ_size() == 1 && &MBB == *MBB.succ_begin()) {
      continue;
    }

    auto insert{std::begin(MBB)};
    // G = G ^ d_j
    llvm::BuildMI(MBB, insert, insert->getDebugLoc(),
                  TII_->get(llvm::RISCV::XORI))
        .addReg(kG)
        .addReg(kG)
        .addImm(mbb_info_[&MBB].d);

    // in case G != s_j we signal error by jumping to error-handler
    // NOTE: we don't have a instruction that checks a register with an
    //       immediate value hence using kD temporarily for holding immediate
    //       looks to be safe for now but have to work on several programs to
    //       see if this implementation works out
    llvm::BuildMI(MBB, insert, insert->getDebugLoc(),
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(kD)
        .addReg(riscv_common::k0)
        .addImm(mbb_info_[&MBB].s);
    llvm::BuildMI(MBB, insert, insert->getDebugLoc(),
                  TII_->get(llvm::RISCV::BNE))
        .addReg(kG)
        .addReg(kD)
        .addMBB(cf_err_bb_);
  }

  // special processing for fanin basicblocks
  for (auto &MBB : *MF_) {
    if (mbb_info_[&MBB].is_fanin) {
      // G = G ^ D at start
      llvm::BuildMI(MBB, std::next(std::begin(MBB)),
                    std::begin(MBB)->getDebugLoc(), TII_->get(llvm::RISCV::XOR))
          .addReg(kG)
          .addReg(kG)
          .addReg(kD);

      // updating D accordingly on this faninBB's predecessors
      for (auto PBB : mbb_info_[&MBB].predecessors) {
        auto insert{std::begin(*PBB)};

        // in case the PBB is not entry BB then we want to move insert to
        // the instruction point after CFCSS BNE check
        if (!PBB->pred_empty()) {
          for (auto &MI : *PBB) {
            if (MI.isBranch()) {
              insert = std::next(MI.getIterator());
              break;
            }
          }
        }

        // further, if this PBB has both successors as faninBBs then insert has
        // to be updated corresponding to the path towards MBB
        if (hasMultipleFaninSBB(PBB)) {
          // here we assume MBB is not on the taken path of PBB
          if (PBB->back().isUnconditionalBranch()) {
            // in case last instruction is a jump then we have to update
            // D before it for taken
            insert = PBB->back().getIterator();
          } else {
            // otherwise just do it at the end
            insert = std::end(*PBB);
          }

          // if rather MBB is on the taken path then we have to update insert
          // before the terminator
          for (auto RMI = std::rbegin(*PBB); RMI != std::rend(*PBB); ++RMI) {
            if (RMI->isBranch() && (RMI->getOperand(0).isReg() &&
                                    RMI->getOperand(0).getReg() != kG)) {
              assert(RMI->getNumOperands() == 3 && RMI->getOperand(2).isMBB());

              if (RMI->getOperand(2).getMBB() == &MBB) {
                insert = RMI->getIterator();
              }
              break;
            }
          }
        }

        // updating D on insert via D_i,m = s_i,1 ^ s_i,m
        llvm::BuildMI(*PBB, insert, PBB->front().getDebugLoc(),
                      TII_->get(llvm::RISCV::ADDI))
            .addReg(kD)
            .addReg(riscv_common::k0)
            .addImm(mbb_info_[&MBB].s_i1 ^ mbb_info_[PBB].s);
      }
    }
  }

  // in case we call another function then G,D regs would be corrupted
  // as we use t0,t1 RISCV regs hence
  for (auto &MBB : *MF_) {
    for (auto &MI : MBB) {
      if (MI.isCall()) {
        if (TII_->isTailCall(MI)) {
          continue;
        }

        // jumps are also considered as calls so filtering them out
        if (MI.getOperand(0).isReg() &&
            MI.getOperand(0).getReg() == llvm::RISCV::X0) {
          continue;
        }

        llvm::MachineBasicBlock::iterator insert{MI.getIterator()};
        insert++;

        // NOTE: stack can be used to pass args if they exceed arg regs hence
        //       we shouldn't use stack for CFC signatures
        // for G, we simply move the expected value back into G
        llvm::BuildMI(MBB, insert, MI.getDebugLoc(),
                      TII_->get(llvm::RISCV::ADDI))
            .addReg(kG)
            .addReg(riscv_common::k0)
            .addImm(mbb_info_[&MBB].s);
        // for D, we clone the instruction that is already at the start of the
        // block
        bool check_block_passed{false};
        for (auto &MI2 : MBB) {
          if (MBB.pred_empty()) {
            check_block_passed = true;
          }

          if (!check_block_passed) {
            if (MI2.getOpcode() == llvm::RISCV::BNE &&
                MI2.getOperand(0).getReg() == kG &&
                MI2.getOperand(1).getReg() == kD) {
              check_block_passed = true;
            }
            continue;
          }

          if (MI2.getOperand(0).isReg() && MI2.getOperand(0).getReg() == kD &&
              MI2.getOpcode() == llvm::RISCV::ADDI &&
              MI2.getOperand(1).isReg() &&
              MI2.getOperand(1).getReg() == riscv_common::k0) {
            auto si{MF_->CloneMachineInstr(&MI2)};
            MBB.insertAfter(&MI, si);
            break;
          } else if (&MI2 == &MI) {
            break;
          }
        }
      }
    }
  }
}

bool RISCVCfcss::hasMultipleFaninSBB(llvm::MachineBasicBlock *PBB) {
  unsigned num_succ_fanin{0};
  for (auto SBB : PBB->successors()) {
    if (mbb_info_[SBB].is_fanin) {
      num_succ_fanin++;
    }
  }

  return (num_succ_fanin >= 2);
}

// for now we just write '1' to special memory address (0xfff8) to tell the
// simulator that this FI is covered in a separate error-BB. Further we
// stay in this loop to avoid further functional execution
void RISCVCfcss::insertErrorBB() {
  cf_err_bb_ = MF_->CreateMachineBasicBlock();
  MF_->push_back(cf_err_bb_);

  auto DLL{MF_->front().front().getDebugLoc()};

  // storing '1' to addr : (0xfff8 = 0x10000 - 0x8):
  // lui t1, 16 -> makes t1 = 0x10000
  llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                TII_->get(llvm::RISCV::LUI))
      .addReg(llvm::RISCV::X6)
      .addImm(16);
  // addi t2, zero, 1 -> makes t2 = 1
  llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                TII_->get(llvm::RISCV::ADDI))
      .addReg(llvm::RISCV::X7)
      .addReg(riscv_common::k0)
      .addImm(1);
  // sw t2, -8(t1) -> stores t2 to (t1 - 8) i.e. store 1 to 0xfff8
  llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                TII_->get(isa_config_.store_opcode))
      .addReg(llvm::RISCV::X7)
      .addReg(llvm::RISCV::X6)
      .addImm(-8);

  // to encode the error-BB in order to make it a label so as to be able to
  // jump to it from anywhere in asm
  cf_err_bb_->addSuccessor(cf_err_bb_);

  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0) {
    // keep on repeating this errBB as we dont want to execute code now
    // J cf_err_bb_ = JALR X0, cf_err_bb_ because J is a pseudo-jump instr in
    // RISCV
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::JAL))
        .addReg(riscv_common::k0)
        .addMBB(cf_err_bb_);
  } else {
    // quit early using ebreak
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::EBREAK));
  }
}
