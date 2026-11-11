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
#include "llvm/CodeGen/LivePhysRegs.h"

namespace {

llvm::DebugLoc blockDebugLoc(const llvm::MachineBasicBlock &MBB) {
  return MBB.empty() ? llvm::DebugLoc() : MBB.front().getDebugLoc();
}

} // namespace

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
  config_.eds = riscv_common::ErrorDetectionStrategy::ED3; // TODO: should be
                                                           // exposed to CLI
  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED1 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED3) {
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
    // there could be err-BBs from other passes
    // the convention is if a BB keeps jumping to itself then this is also
    // an error-BB
    if (MBB.succ_size() == 1 && &MBB == *MBB.succ_begin()) {
      continue;
    }

    for (auto PBB : MBB.predecessors()) {
      mbb_info_[&MBB].predecessors.emplace(PBB);
    }
    if (mbb_info_[&MBB].predecessors.size() > 1) {
      mbb_info_[&MBB].is_fanin = true;
    }
    mbb_info_[&MBB].s = cnt++;
  }
  for (auto &MBB : *MF_) {
    if (mbb_info_[&MBB].predecessors.empty())
      continue;
    auto PBB{*std::begin(mbb_info_[&MBB].predecessors)};
    mbb_info_[&MBB].s_i1 = mbb_info_[PBB].s;
    mbb_info_[&MBB].d = mbb_info_[PBB].s ^ mbb_info_[&MBB].s;
  }

  auto insert = MF_->front().begin();
  const auto DL = blockDebugLoc(MF_->front());
  // G starts at the entry signature.
  llvm::BuildMI(MF_->front(), insert, DL, TII_->get(llvm::RISCV::ADDI))
      .addReg(kG, llvm::RegState::Define)
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
    const auto DL = blockDebugLoc(MBB);
    // G = G ^ d_j
    llvm::BuildMI(MBB, insert, DL, TII_->get(llvm::RISCV::XORI))
        .addReg(kG, llvm::RegState::Define)
        .addReg(kG)
        .addImm(mbb_info_[&MBB].d);

    // in case G != s_j we signal error by jumping to error-handler
    // NOTE: we don't have a instruction that checks a register with an
    //       immediate value hence using kD temporarily for holding immediate
    //       looks to be safe for now but have to work on several programs to
    //       see if this implementation works out
    llvm::BuildMI(MBB, insert, DL, TII_->get(llvm::RISCV::ADDI))
        .addReg(kD, llvm::RegState::Define)
        .addReg(riscv_common::k0)
        .addImm(mbb_info_[&MBB].s);
    llvm::BuildMI(MBB, insert, DL, TII_->get(llvm::RISCV::BNE))
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
          .addReg(kG, llvm::RegState::Define)
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
        llvm::BuildMI(*PBB, insert, blockDebugLoc(*PBB),
                      TII_->get(llvm::RISCV::ADDI))
            .addReg(kD, llvm::RegState::Define)
            .addReg(riscv_common::k0)
            .addImm(mbb_info_[&MBB].s_i1 ^ mbb_info_[PBB].s);
      }
    }
  }

  // D is initially dead, but a call can precede its first adjustment. Insert
  // this definition after constructing fan-in updates so it executes before
  // any entry-block adjustment rather than overwriting one.
  llvm::BuildMI(MF_->front(), MF_->front().begin(),
                blockDebugLoc(MF_->front()),
                TII_->get(llvm::RISCV::ADDI))
      .addReg(kD, llvm::RegState::Define)
      .addReg(riscv_common::k0)
      .addImm(0);

  // Both G (t0) and D (t4) are caller-saved. Preserve their actual runtime
  // values: reconstructing constants here would erase an existing mismatch.
  for (auto &MBB : *MF_) {
    for (auto &MI : MBB) {
      if (!MI.isCall() || TII_->isTailCall(MI))
        continue;
      // LLVM also describes no-link jumps as calls.
      if (MI.getNumOperands() && MI.getOperand(0).isReg() &&
          MI.getOperand(0).getReg() == llvm::RISCV::X0)
        continue;
      riscv_common::preserveSignatureAcrossCall(&MI, {kG, kD}, kD);
    }
  }
}

bool RISCVCfcss::hasMultipleFaninSBB(llvm::MachineBasicBlock *PBB) {
  unsigned num_succ_fanin{0};
  std::set<int> already_seen{};

  for (auto SBB : PBB->successors()) {
    if (riscv_common::setmapContains(already_seen, SBB->getNumber())) {
      continue;
    }

    if (mbb_info_[SBB].is_fanin) {
      num_succ_fanin++;
    }
    already_seen.emplace(SBB->getNumber());
  }

  return (num_succ_fanin >= 2);
}

// for now we just write '1' to special memory address (0xfff8) to tell the
// simulator that this FI is covered in a separate error-BB. Further we
// stay in this loop to avoid further functional execution
void RISCVCfcss::insertErrorBB() {
  cf_err_bb_ = MF_->CreateMachineBasicBlock();
  MF_->push_back(cf_err_bb_);

  const auto DLL = blockDebugLoc(MF_->front());

  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0) {
    // storing '1' to addr : (0xfff8 = 0x10000 - 0x8):
    // lui t1, 16 -> makes t1 = 0x10000
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::LUI))
        .addReg(llvm::RISCV::X6, llvm::RegState::Define)
        .addImm(16);
    // addi t2, zero, 1 -> makes t2 = 1
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(llvm::RISCV::X7, llvm::RegState::Define)
        .addReg(riscv_common::k0)
        .addImm(1);
    // sw t2, -8(t1) -> stores t2 to (t1 - 8) i.e. store 1 to 0xfff8
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(isa_config_.store_opcode))
        .addReg(llvm::RISCV::X7)
        .addReg(llvm::RISCV::X6)
        .addImm(-8);

  } else if (config_.eds == riscv_common::ErrorDetectionStrategy::ED3) {
    // storing '93' to a7, aka SYS_exit code ECALL code:
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(llvm::RISCV::X17, llvm::RegState::Define) // a7
        .addReg(llvm::RISCV::X0)  // zero
        .addImm(93);
    // storing '-256' to a0, aka exit return value when ecall forces newlib sys
    // exit:
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(llvm::RISCV::X10, llvm::RegState::Define) // a0
        .addReg(llvm::RISCV::X0)  // zero
        .addImm(-256);
    // invoke 'ecall'
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::ECALL))
        .addReg(llvm::RISCV::X17, llvm::RegState::Implicit)
        .addReg(llvm::RISCV::X10, llvm::RegState::Implicit);
  }

  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED3) {

    // to encode the error-BB in order to make it a label so as to be able to
    // jump to it from anywhere in asm
    cf_err_bb_->addSuccessor(cf_err_bb_);

    // Use a branch descriptor so LLVM recognizes the loop's successor.
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::PseudoBR))
        .addMBB(cf_err_bb_);
  } else {
    // quit early using ebreak
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::EBREAK));
  }
}
