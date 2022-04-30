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

#include "RISCVDmr.h"

#include <random>

#include "RISCVSubtarget.h"
#include "common.h"
#include "llvm/CodeGen/CommandFlags.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"

// #define DBG

llvm::FunctionPass *llvm::createRISCVDmr() { return new RISCVDmr(); }

RISCVDmr::RISCVDmr() : llvm::MachineFunctionPass{ID} {}

bool RISCVDmr::ignoreMF() {
  bool ret{true};

  // NOTE: doesn't make sense to generalize below as we only expect
  //       upto 10 SIHFTs

  // is this function passed in NZDC list?
  if (riscv_common::inCSString(llvm::cl::enable_nzdc, fname_)) {
    ret = false;
  } else {
    if (llvm::cl::enable_nzdc.size()) {
      llvm::outs() << "COMPAS: Ignoring " << fname_ << " for NZDC\n";
    }
  }
  // is this function passed in NZDC+NEMESIS list?
  if (riscv_common::inCSString(llvm::cl::enable_nzdc_nemesis, fname_)) {
    ret = false;
  } else {
    if (llvm::cl::enable_nzdc_nemesis.size()) {
      llvm::outs() << "COMPAS: Ignoring " << fname_ << " for NZDC+NEMESIS\n";
    }
  }
  // is this function passed in NZDC+NEMESEC list?
  if (riscv_common::inCSString(llvm::cl::enable_nzdc_nemesec, fname_)) {
    ret = false;
  } else {
    if (llvm::cl::enable_nzdc_nemesec.size()) {
      llvm::outs() << "COMPAS: Ignoring " << fname_ << " for NZDC+NEMESEC\n";
    }
  }
  // is this function passed in SWIFT list?
  if (riscv_common::inCSString(llvm::cl::enable_swift, fname_)) {
    ret = false;
  } else {
    if (llvm::cl::enable_swift.size()) {
      llvm::outs() << "COMPAS: Ignoring " << fname_ << " for SWIFT\n";
    }
  }
  // is this function passed in EDDI list?
  if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_)) {
    ret = false;
  } else {
    if (llvm::cl::enable_eddi.size()) {
      llvm::outs() << "COMPAS: Ignoring " << fname_ << " for EDDI\n";
    }
  }

  return ret;
}

bool RISCVDmr::runOnMachineFunction(llvm::MachineFunction &MF) {
  MF_ = &MF;
  fname_ = std::string{MF_->getName()};

  // if this function is not to be transformed then return early
  init(); // FIXME: init() will insert errorBBs for all functions (non-DMR, DMR,
          // and DMR calling non-DMRs alike)

  if (!ignoreMF()) {
    duplicateInstructions();
    protectCalls();
    protectStores();
    protectLoads();
    protectBranches();
    if (llvm::cl::enable_repair) {
      repair();
    }
    protectGP();
  }
  if (config_.sh != SelectiveHardening::SH0 && !user_calls_.empty()) {
    llvm::outs() << "d0: Updating function call according to selective "
                    "hardening technique\n";
    updateSelectiveCalls();
  }

  return !ignoreMF();
}

void RISCVDmr::protectGP() {
  // hard to do GP duplication at this level as GP gets addr later in assembly
  // phase
  // if GP and its shadow remain matching throughout the MF then there is
  // high chance that we dont have SDC due to corrupt GP
  for (auto &MBB : *MF_) {
    for (auto &MI : MBB) {
      if (MI.isReturn()) {
        llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                      TII_->get(llvm::RISCV::BNE))
            .addReg(riscv_common::kGP)
            .addReg(P2S_.at(riscv_common::kGP))
            .addMBB(err_bb_);
      }
    }
  }
}

void RISCVDmr::init() {
  TII_ = MF_->getSubtarget().getInstrInfo();
  MRI_ = &MF_->getRegInfo();
  TRI_ = MRI_->getTargetRegisterInfo();
  config_.eds = riscv_common::ErrorDetectionStrategy::ED3; // TODO: should be
                                                           // exposed to CLI
  for (auto &s : llvm::codegen::getMAttrs()) {
    if (!s.compare(std::string{"+f"}) || !s.compare(std::string{"+d"})) {
      uses_FPregfile_ = true;
      break;
    }
  }

  // how to handle instruction schedule for DMR
  std::string schedule_string{"CGS"};
  if (riscv_common::inCSString(llvm::cl::enable_fgs, fname_)) {
    config_.is = InstructionSchedule::FGS;
    schedule_string = "FGS";
  }

  // how to handle lib-calls
  config_.pslc = ProtectStrategyLibCall::LC1;

  // NOTE: doesn't make sense to generalize below as we only expect
  //       upto 10 SIHFTs
  if (riscv_common::inCSString(llvm::cl::enable_nzdc, fname_)) {
    // setting up nzdc configs
    config_.pss = ProtectStrategyStore::S3;
    config_.psl = ProtectStrategyLoad::L0;
    config_.psuc = ProtectStrategyUserCall::UC3;
    config_.psb = ProtectStrategyBranch::B0;

    llvm::outs() << "COMPAS: Running NZDC pass with " << schedule_string
                 << " on " << fname_ << "\n";
  } else if (riscv_common::inCSString(llvm::cl::enable_nzdc_nemesis, fname_)) {
    // setting up nzdc configs
    config_.pss = ProtectStrategyStore::S3;
    config_.psl = ProtectStrategyLoad::L0;
    config_.psuc = ProtectStrategyUserCall::UC3;
    config_.psb = ProtectStrategyBranch::B2;

    llvm::outs() << "COMPAS: Running NZDC+NEMESIS pass with " << schedule_string
                 << " on " << fname_ << "\n";
  } else if (riscv_common::inCSString(llvm::cl::enable_nzdc_nemesec, fname_)) {
    // setting up nzdc configs
    config_.pss = ProtectStrategyStore::S3;
    config_.psl = ProtectStrategyLoad::L0;
    config_.psuc = ProtectStrategyUserCall::UC3;
    config_.psb = ProtectStrategyBranch::B3;

    llvm::outs() << "COMPAS: Running NZDC+NEMESEC pass with " << schedule_string
                 << " on " << fname_ << "\n";
  } else if (riscv_common::inCSString(llvm::cl::enable_swift, fname_)) {
    // setting swift configs
    config_.pss = ProtectStrategyStore::S1;
    config_.psl = ProtectStrategyLoad::L1;
    config_.psuc = ProtectStrategyUserCall::UC1;
    config_.psb = ProtectStrategyBranch::B1;

    llvm::outs() << "COMPAS: Running SWIFT pass with " << schedule_string
                 << " on " << fname_ << "\n";
  } else if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_)) {
    // setting edd configs
    config_.pss = ProtectStrategyStore::S2;
    config_.psl = ProtectStrategyLoad::L2;
    config_.psuc = ProtectStrategyUserCall::UC1;
    config_.psb = ProtectStrategyBranch::B1;
    use_shadow_for_stack_ops_ = false;

    llvm::outs() << "COMPAS: Running EDDI pass with " << schedule_string
                 << " on " << fname_ << "\n";
  }

  err_bb_ = nullptr;
  entry_bb_ = nullptr;
  exit_bbs_.clear();
  stores_.clear();
  user_calls_.clear();
  lib_calls_.clear();
  branches_.clear();
  nemesis_bbs_.clear();
  loadbacks_.clear();
  indirect_calls_.clear();
  loads_.clear();
  shadow_loads_.clear();
  frame_size_ = 0;

  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED1 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED3) {
    // insert an error-BB in MF_
    insertErrorBB();
  } else {
    assert(0 && "TODO");
  }

  // collecting special instruction points in containers for later use
  // std::set<llvm::MachineInstr *> stores_avoid_for_prot{};
  std::set<std::string> already_seen_func_names{};
  for (auto &MBB : *MF_) {
    if (&MBB == err_bb_) {
      continue;
    }

    if (MBB.pred_empty()) {
      entry_bb_ = &MBB;
    }
    if (MBB.succ_empty()) {
      exit_bbs_.emplace(&MBB);
    }

    for (auto &MI : MBB) {
      if (MI.mayStore()) {
        stores_.emplace(&MI);
      } else if (MI.mayLoad()) {
        loads_.emplace(&MI);
      } else if (MI.isCall()) {
        if (MI.getOpcode() == llvm::RISCV::PseudoCALLIndirect ||
            MI.getOpcode() ==
                llvm::RISCV::PseudoTAILIndirect) { //[joh]: tail may also be an
                                                   // indirect call
          indirect_calls_.emplace(&MI);
          continue;
        }
        assert(MI.getOperand(0).isGlobal() || MI.getOperand(0).isSymbol());

        auto called_func_name{getCalledFuncName(&MI)};
        if (riscv_common::setmapContains(knownLibcalls2Duplicable_,
                                         called_func_name)) {
          lib_calls_.emplace(&MI);
        } else {
          user_calls_.emplace(&MI);

          if (!riscv_common::setmapContains(already_seen_func_names,
                                            called_func_name)) {
            llvm::outs() << "\tNOTE: Considering " << called_func_name
                         << " as a user-func call\n";
            already_seen_func_names.emplace(called_func_name);
          }
        }
      } else if (MI.isBranch()) {
        branches_.emplace(&MI);
      }
    }
  }

  for (auto &MI : *entry_bb_) {
    if (MI.getFlag(llvm::MachineInstr::FrameSetup) && !MI.isCFIInstruction() &&
        MI.getOperand(0).isReg() &&
        MI.getOperand(0).getReg() ==
            riscv_common::kSP // is reg and stack pointer
        && MI.getOperand(1).isReg() &&
        MI.getOperand(1).getReg() ==
            riscv_common::kSP       // is reg and stack pointer
        && MI.getOperand(2).isImm() // is immediate field
        // < this check for `addi sp, sp, -<stacksize>` might just ask for
        // trouble
    ) {
      frame_size_ = std::abs(MI.getOperand(2).getImm());
    }
  }

#ifdef DBG
  llvm::outs() << "COMPAS_DBG: init() done\n";
#endif
}

llvm::MachineInstr *
RISCVDmr::genShadowFromPrimary(const llvm::MachineInstr *MI) const {
  auto si{MF_->CloneMachineInstr(MI)};
  for (auto &o : si->operands()) {
    if (o.isReg()) {
      assert((riscv_common::setmapContains(P2S_, o.getReg())) &&
             "reg not found in P2S_");
      o.setReg(P2S_.at(o.getReg()));
    }
  }
  return si;
}

void RISCVDmr::duplicateInstructions() {
  if (config_.is == InstructionSchedule::CGS) {
    for (auto &MBB : *MF_) {
      if (err_bb_ == &MBB) {
        continue;
      }

      std::vector<llvm::MachineInstr *> shadow_block{};
      std::map<llvm::MachineInstr *, std::vector<llvm::MachineInstr *>>
          insert2Shadowblock{};
      bool terminator_reached{false};
      for (auto &MI : MBB) {
        if (MI.isCall() || MI.mayStore() || MI.isBranch() || MI.isReturn()) {
          terminator_reached = true;
        } else {
          if (MI.mayLoad() && config_.psl == ProtectStrategyLoad::L1) {
            terminator_reached = true;
          }
        }

        if (terminator_reached) {
          insert2Shadowblock[&MI] = shadow_block;
          shadow_block.clear();
          terminator_reached = false;
        } else {
          shadow_block.emplace_back(genShadowFromPrimary(&MI));

          if (MI.mayLoad()) {
            shadow_loads_.emplace(shadow_block.back());
          }
        }
      }

      for (const auto &p : insert2Shadowblock) {
        for (const auto &si : insert2Shadowblock[p.first]) {
          MBB.insert(p.first, si);
        }
      }
      if (shadow_block.size()) {
        for (const auto &si : shadow_block) {
          MBB.insertAfter(&MBB.back(), si);
        }
      }
    }
  } else if (config_.is == InstructionSchedule::FGS) {
    for (auto &MBB : *MF_) {
      if (err_bb_ == &MBB) {
        continue;
      }

      for (auto &MI : MBB) {
        if (MI.isCall() || MI.mayStore() || MI.isBranch() || MI.isReturn()) {
          continue;
        } else {
          MBB.insert(&MI, genShadowFromPrimary(&MI));
        }
      }
    }
  } else {
    assert(0 && "this instruction-schedule for DMR is not supported yet");
  }

  llvm::BuildMI(MF_->front(), std::begin(MF_->front()),
                MF_->front().front().getDebugLoc(),
                TII_->get(llvm::RISCV::ADDI))
      .addReg(P2S_.at(riscv_common::kRA))
      .addReg(riscv_common::kRA)
      .addImm(0);

  if (fname_ == "main") {
    llvm::BuildMI(MF_->front(), std::begin(MF_->front()),
                  MF_->front().front().getDebugLoc(),
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(P2S_.at(riscv_common::kSP))
        .addReg(riscv_common::kSP)
        .addImm(0);
    llvm::BuildMI(MF_->front(), std::begin(MF_->front()),
                  MF_->front().front().getDebugLoc(),
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(P2S_.at(riscv_common::k0))
        .addReg(riscv_common::k0)
        .addImm(0);
    llvm::BuildMI(MF_->front(), std::begin(MF_->front()),
                  MF_->front().front().getDebugLoc(),
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(P2S_.at(riscv_common::kGP))
        .addReg(riscv_common::kGP)
        .addImm(0);
  }

  // for EDDI, we need 2x the stack space..following code manages this
  if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_)) {
    // prologue
    for (auto &MI : *entry_bb_) {
      if (MI.getFlag(llvm::MachineInstr::FrameSetup) &&
          !MI.isCFIInstruction()) {
        if (!isShadowInstr(&MI)) {
          MI.getOperand(2).setImm(frame_size_ * -2);
        } else {
          MI.getOperand(1).setReg(riscv_common::kSP);
          MI.getOperand(2).setImm(frame_size_);

          break;
        }
      }
    }
    // epilogue
    for (auto exit_BB : exit_bbs_) {
      for (auto &MI : *exit_BB) {
        if (MI.getFlag(llvm::MachineInstr::FrameDestroy) &&
            MI.getOperand(0).isReg() &&
            MI.getOperand(0).getReg() == riscv_common::kSP) {
          MI.getOperand(2).setImm(frame_size_ * 2);

          break;
        }
      }
    }
  }

#ifdef DBG
  llvm::outs() << "COMPAS_DBG: duplicateInstructions() done\n";
#endif
}

void RISCVDmr::syncFPRegs(llvm::MachineBasicBlock *MBB,
                          llvm::MachineBasicBlock::iterator insert,
                          llvm::Register r1, llvm::Register r2) {
  auto DLL{MBB->front().getDebugLoc()};
  auto shadow_zero{P2S_.at(riscv_common::k0)};

  auto feq_opcode{llvm::RISCV::FEQ_S};
  if (riscv_common::getRegType(r1) == riscv_common::RegType::FD) {
    feq_opcode = llvm::RISCV::FEQ_D;
  } else if (riscv_common::getRegType(r1) == riscv_common::RegType::FH) {
    assert(0 && "this FP mode not supported yet");
  } else if (riscv_common::getRegType(r1) != riscv_common::RegType::FS) {
    assert(0 && "unexpected reg operands passed");
  }

  llvm::BuildMI(*MBB, insert, DLL, TII_->get(feq_opcode))
      .addReg(shadow_zero)
      .addReg(r1)
      .addReg(r2);
  llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::ADDI))
      .addReg(shadow_zero)
      .addReg(shadow_zero)
      .addImm(-1);
  llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::BNE))
      .addReg(shadow_zero)
      .addReg(riscv_common::k0)
      .addMBB(err_bb_);
}

void RISCVDmr::protectStores() {
  if (config_.pss == ProtectStrategyStore::S3) {
    // for (auto MI : stores_to_protect_) {
    for (auto MI : stores_) {
      auto opcode{MI->getOpcode()};
      if (MI->hasOrderedMemoryRef() || //[joh] do not protect volatile or
                                       // ordered
                                       // memory instr
          (MI->isInlineAsm() &&
           MI->getOperand(0)
               .isSymbol())) { //[joh]: inline fence.i also maystore
#ifdef DBG
        llvm::outs()
            << *MI
            << "RISCVDmr::protectStores(): skip inline assembly and volatiles"
               "instructions -- needs fix\n";
#endif
        continue;
      }
      auto data_reg{MI->getOperand(0).getReg()};
      auto addr_reg{MI->getOperand(1).getReg()};
      auto MBB{MI->getParent()};
      auto DLL{MI->getDebugLoc()};
      llvm::MachineBasicBlock::iterator insert{MI->getIterator()};
      insert++;

      if (riscv_common::setmapContains(LBStore2Load_, opcode)) {
        auto shadow_zero{P2S_.at(riscv_common::k0)};
        auto si{MF_->CloneMachineInstr(MI)};
        si->getOperand(1).setReg(P2S_.at(addr_reg));
        si->setDesc(TII_->get(LBStore2Load_.at(opcode)));
        MBB->insertAfter(MI, si);
        loadbacks_.emplace(si);

        // loading back to zero could lead to exception hence here
        // avoiding this by storing shadow and checking the loaded back
        // value with primary
        if (data_reg == riscv_common::k0) {
          MI->getOperand(0).setReg(P2S_.at(data_reg));
          MI->getOperand(1).setReg(P2S_.at(addr_reg));
          si->getOperand(0).setReg(P2S_.at(data_reg));
          si->getOperand(1).setReg(addr_reg);
        }

        if (opcode == llvm::RISCV::FSW || opcode == llvm::RISCV::FSD) {
          // loadback for FP stores
          syncFPRegs(MBB, insert, data_reg, P2S_.at(data_reg));
        } else {
          // loadback for integer stores

          bool shadow_zero_needed{false};
          if (opcode == isa_config_.store_opcode ||
              opcode == llvm::RISCV::SC_D) {
            shadow_zero_needed = false;
          } else {
            shadow_zero_needed = true;
          }
          if (shadow_zero_needed) {
            si->getOperand(0).setReg(shadow_zero);
          }

          if (!shadow_zero_needed) {
            auto mi_builder{
                llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::BNE))
                    .addReg(data_reg)
                    .addReg(P2S_.at(data_reg))
                    .addMBB(err_bb_)};
            loadbacks_.emplace(mi_builder.getInstr());
          } else {
            auto slli_imm{isa_config_.store_opcode == llvm::RISCV::SD ? 64
                                                                      : 32};
            if (opcode == llvm::RISCV::SB) {
              slli_imm -= 8;
            } else if (opcode == llvm::RISCV::SH) {
              slli_imm -= 16;
            } else {
              assert(slli_imm == 64 && "we should be RV64x here");
              slli_imm -= 32;
            }

            auto mi_builder{
                llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::XOR))
                    .addReg(shadow_zero)
                    .addReg(shadow_zero)
                    .addReg(P2S_.at(data_reg))};
            loadbacks_.emplace(mi_builder.getInstr());
            llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::SLLI))
                .addReg(shadow_zero)
                .addReg(shadow_zero)
                .addImm(slli_imm);
            llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::BNE))
                .addReg(shadow_zero)
                .addReg(riscv_common::k0)
                .addMBB(err_bb_);
          }
        }
      } else {
        MI->dump();
        assert(0 && "this store is not supported yet");
      }
    }
  } else if (config_.pss == ProtectStrategyStore::S1) {
    for (const auto &MI : stores_) {
      for (const auto &op : MI->operands()) {
        if (op.isReg()) {
          if (riscv_common::getRegType(op.getReg()) ==
              riscv_common::RegType::I) {
            llvm::BuildMI(*MI->getParent(), MI->getIterator(),
                          MI->getDebugLoc(), TII_->get(llvm::RISCV::BNE))
                .addReg(op.getReg())
                .addReg(P2S_.at(op.getReg()))
                .addMBB(err_bb_);
          } else {
            syncFPRegs(MI->getParent(), MI->getIterator(), op.getReg(),
                       P2S_.at(op.getReg()));
          }
        }
      }
    }
  } else if (config_.pss == ProtectStrategyStore::S2) {
    for (const auto &MI : stores_) {
      auto data_operand{MI->getOperand(0).getReg()};
      if (riscv_common::getRegType(data_operand) == riscv_common::RegType::I) {
        llvm::BuildMI(*MI->getParent(), MI->getIterator(), MI->getDebugLoc(),
                      TII_->get(llvm::RISCV::BNE))
            .addReg(data_operand)
            .addReg(P2S_.at(data_operand))
            .addMBB(err_bb_);
      } else {
        syncFPRegs(MI->getParent(), MI->getIterator(), data_operand,
                   P2S_.at(data_operand));
      }

      auto si{MF_->CloneMachineInstr(MI)};
      MI->getParent()->insertAfter(MI, si);

      for (auto &op : si->operands()) {
        if (op.isImm()) {
          op.setImm(op.getImm());
        } else if (op.isReg()) {
          op.setReg(P2S_.at(op.getReg()));
        }
      }
    }
  } else {
    assert(0 && "this protect-strategy for stores is not supported yet");
  }

#ifdef DBG
  llvm::outs() << "COMPAS_DBG: protectStores() done\n";
#endif
}

void RISCVDmr::protectLoads() {
  if (config_.psl == ProtectStrategyLoad::L0) {
    return;
  } else if (config_.psl == ProtectStrategyLoad::L1) {
    for (const auto &MI : loads_) {
      for (const auto &op : MI->operands()) {
        if (op.isReg()) {
          if (op.isUse()) {
            llvm::BuildMI(*MI->getParent(), MI->getIterator(),
                          MI->getDebugLoc(), TII_->get(llvm::RISCV::BNE))
                .addReg(op.getReg())
                .addReg(P2S_.at(op.getReg()))
                .addMBB(err_bb_);
          } else if (op.isDef()) {
            // inserting a move operation in order to do duplicate load
            moveIntoShadow(MI->getParent(), std::next(MI->getIterator()),
                           op.getReg(), P2S_.at(op.getReg()));
          }
        }
      }
    }
  } else if (config_.psl == ProtectStrategyLoad::L2) {
    for (auto &MI : shadow_loads_) {
      for (auto &op : MI->operands()) {
        if (op.isImm()) {
          if (op.getImm()) {
            op.setImm(op.getImm());
          }
        }
      }
    }
  } else {
    assert(0 && "this protect-strategy for loads is not supported yet");
  }

#ifdef DBG
  llvm::outs() << "COMPAS_DBG: protectLoads() done\n";
#endif
}

RISCVDmr::RegSetType RISCVDmr::getArgRegs(const llvm::MachineInstr *MI) const {
  assert(MI->isCall() && "call not passed in");

  RegSetType to_ret{};
  for (auto &iop : MI->implicit_operands()) {
    if (iop.isReg()) {
      if (iop.isUse()) {
        to_ret.emplace(iop.getReg());
      }
    }
  }

  return to_ret;
}

RISCVDmr::RegSetType RISCVDmr::getRetRegs(const llvm::MachineInstr *MI) const {
  assert(MI->isCall() && "call not passed in");

  RegSetType to_ret{};
  for (auto &iop : MI->implicit_operands()) {
    if (iop.isReg()) {
      if (iop.isDef() && !iop.isDead()) {
        if (iop.getReg() == riscv_common::kSP) {
          continue;
        }
        to_ret.emplace(iop.getReg());
      }
    }
  }

  return to_ret;
}

std::string RISCVDmr::getCalledFuncName(const llvm::MachineInstr *MI) const {
  std::string called_func_name{};
  if (MI->getOperand(0).isGlobal()) {
    called_func_name = std::string(MI->getOperand(0).getGlobal()->getName());
  } else {
    called_func_name = std::string(MI->getOperand(0).getSymbolName());
  }

  return called_func_name;
}

void RISCVDmr::moveIntoShadow(llvm::MachineBasicBlock *MBB,
                              llvm::MachineBasicBlock::iterator insert,
                              llvm::Register rp, llvm::Register rs) {
  auto DLL{MBB->begin()->getDebugLoc()};

  if (riscv_common::getRegType(rp) == riscv_common::RegType::I) {
    llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::ADDI))
        .addReg(rs)
        .addReg(rp)
        .addImm(0);
  } else if (riscv_common::getRegType(rp) == riscv_common::RegType::FS) {
    llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::FSGNJ_S))
        .addReg(rs)
        .addReg(rp)
        .addReg(rp);
  } else if (riscv_common::getRegType(rp) == riscv_common::RegType::FD) {
    llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::FSGNJ_D))
        .addReg(rs)
        .addReg(rp)
        .addReg(rp);
  } else if (riscv_common::getRegType(rp) == riscv_common::RegType::FH) {
    assert(0 && "TODO");
  }
}

void RISCVDmr::updateSelectiveCalls() {

  auto is_func_dmr = [&](const std::string &func_name) {
    return (riscv_common::inCSString(llvm::cl::enable_nzdc, func_name) ||
            riscv_common::inCSString(llvm::cl::enable_nzdc_nemesis,
                                     func_name) ||
            riscv_common::inCSString(llvm::cl::enable_nzdc_nemesec,
                                     func_name) ||
            riscv_common::inCSString(llvm::cl::enable_swift, func_name) ||
            riscv_common::inCSString(llvm::cl::enable_eddi, func_name))
               ? true
               : false;
  };

  if (config_.sh == SelectiveHardening::SH0) {

  } else if (config_.sh == SelectiveHardening::SH1) {
    for (auto MI : user_calls_) {
      auto callee_func_name{getCalledFuncName(MI)};
      auto callee_is_dmr = is_func_dmr(callee_func_name);
      auto caller_is_dmr = is_func_dmr(fname_);

      if (callee_is_dmr) {   // the callee is a DMRed function
        if (caller_is_dmr) { // the caller is a DMRed function, so we do not
                             // have to do anything here since calling
                             // convention is not changing
          llvm::outs()
              << "dbg: both caller[" << fname_ << "]->callee["
              << callee_func_name
              << "] are DMR: so don't care about calling convention...\n";
        } else { // the caller is not a DMR so we have to prepare all calls to
                 // DMR-functions
          llvm::outs() << "dbg: caller[" << fname_ << "]->DMR-callee["
                       << callee_func_name
                       << "] adhere to DMR-callee calling convention...\n";

          // 0) get live shadow registers
          // 1) if isTail() then add `ra` to lives/spills
          // 2) if isTail() replace `tail` with `call` + `ret`
          // 3) spill lives to stack
          // 4) duplicate primaries to shadows before `call`
          // 5) unspill lives from stack after `call`

          llvm::LivePhysRegs lregs(*TRI_);
          auto MBB{MI->getParent()};
          lregs.addLiveIns(*MBB);
#ifdef DBG
          for (auto &li : MBB->liveins()) {
            llvm::outs() << "li: " << li.PhysReg << "\n";
          }
          for (auto &lo : MBB->liveouts()) {
            llvm::outs() << "lo: " << lo.PhysReg << "\n";
          }
#endif // DBG
          llvm::SmallVector<
              std::pair<llvm::MCPhysReg, const llvm::MachineOperand *>, 2>
              Clobbers;
#ifdef DBG
          for (auto &lr : lregs) {
            llvm::outs() << "ilr: x" << lr - llvm::RISCV::X0 << "\n";
          }
#endif // DBG
          auto call_iter = MI->getIterator();
          for (const auto &mi : *MBB) {
            // lregs.accumulate(mi);
            if (&mi == MI)
              break;
            Clobbers.clear();
            lregs.stepForward(mi, Clobbers);
#ifdef DBG
            llvm::outs() << "mi: " << mi << "\n";
#endif
          }

          RegSetType spill_regs{};
          for (const auto &lr : lregs) {
            if (riscv_common::mapValContains(P2S_, lr)) { // live is a shadow
              spill_regs.emplace(lr);
            }
#ifdef DBG
            llvm::outs() << "clr: x" << lr - llvm::RISCV::X0 << "\n";
#endif // DBG
          }

          if (spill_regs.find(llvm::RISCV::X1) == spill_regs.end() &&
              TII_->isTailCall(*MI)) {
            spill_regs.emplace(
                llvm::RISCV::X1); // if the call is a `tail` we need to replace
                                  // it with a `call+ret` to allow restoration
                                  // of non-DMR context before return
          }
#ifdef DBG
          for (const auto &sr : spill_regs) {
            llvm::outs() << "sr: x" << sr - llvm::RISCV::X0 << "\n";
          }
#endif // DBG
       // insert the spill segment
          std::vector<llvm::Register> sregs(spill_regs.begin(),
                                            spill_regs.end());
          auto insert = call_iter;
          riscv_common::saveRegs(sregs, MBB, insert);
          // insert the default duplication segment, i.e., move all primaries
          // into their shadows
          for (const auto &regpair : P2S_) {
            if (riscv_common::getRegType(regpair.first) ==
                riscv_common::RegType::I) {
              moveIntoShadow(MBB, insert, regpair.first, regpair.second);

            } else {
              // FIXME: only handle Base Integer Registers for now
            }
          }

          insert = MI->getIterator();
          ++insert;
          if (TII_->isTailCall(*MI)) { // replace `tail`s with `call+ret`s
            MI->setDesc(TII_->get(llvm::RISCV::PseudoCALL));

            llvm::BuildMI(*MBB, insert, MI->getDebugLoc(),
                          TII_->get(llvm::RISCV::PseudoRET));
          }
          insert = MI->getIterator();
          ++insert;
          riscv_common::loadRegs(sregs, MBB, insert);

          insert = MI->getIterator();
          ++insert;
          for (const auto &regpair : P2S_) {
            if (riscv_common::getRegType(regpair.first) ==
                riscv_common::RegType::I) {
              llvm::BuildMI(*MBB, insert, MI->getDebugLoc(),
                            TII_->get(llvm::RISCV::BNE))
                  .addReg(regpair.first)
                  .addReg(regpair.second)
                  .addMBB(err_bb_);
            } else {
              // FIXME: only handle Base Integer Registers for now
            }
          }
        }
      } else {               // the callee is not a DMR-function
        if (caller_is_dmr) { // the caller is a DMRed function, we need to
                             // prepare non-DMR calling convention.
          llvm::outs() << "dbg: DMR-caller[" << fname_ << "]->callee["
                       << callee_func_name
                       << "] adhere to non-DMR-callee calling convention...\n";
          // live shadows involving t0-t6, a0-a7 can be corrupted by non-DMR
          // function, so we need to prepare those

          auto MBB{MI->getParent()};
          for (const auto &r : MBB->liveouts()) {
            llvm::outs() << "or: x" << r.PhysReg - llvm::RISCV::X0 << "\n";
          }
          if (TII_->isTailCall(*MI)) { // replace `tail`s with `call+ret`
            MI->addImplicitDefUseOperands(*MF_);
          }

          auto ret_regs{getRetRegs(MI)};
          auto insert{MI->getIterator()};
          ++insert;

          RegSetType spill_regs;
          for (unsigned r = llvm::RISCV::X3; r <= llvm::RISCV::X31; ++r) {
            if (!riscv_common::setmapContains(callee_saved_regs_, r)) {
              spill_regs.emplace(r);
            }
          }
          // ret-regs would be changed after func call hence dont need to stack
          // them. FIXME: Also remove a0 and a1 always when indirect call is a
          // tail
          if (riscv_common::setmapContains(ret_regs, llvm::RISCV::X10) ||
              (TII_->isTailCall(*MI))) {
            spill_regs.erase(llvm::RISCV::X10);
          }
          if (riscv_common::setmapContains(ret_regs, llvm::RISCV::X11) ||
              (TII_->isTailCall(*MI))) {
            spill_regs.erase(llvm::RISCV::X11);
          }

          if (spill_regs.find(llvm::RISCV::X1) == spill_regs.end() &&
              TII_->isTailCall(*MI)) {
            spill_regs.emplace(
                llvm::RISCV::X1); // if the call is a `tail` we need to replace
                                  // it with a `call+ret` to allow restoration
                                  // of DMR context before return, because we
                                  // could return back to a DMR-function instead
                                  // of a non-DMR one
          }

          std::vector<llvm::Register> sregs(spill_regs.begin(),
                                            spill_regs.end());

          if(use_shadow_for_stack_ops_) {
            riscv_common::saveRegs(sregs, MBB, MI->getIterator(),
                                   P2S_.at(riscv_common::kSP));

          }
          else {
            riscv_common::saveRegs(sregs, MBB, MI->getIterator());
          }
          insert = MI->getIterator();
          ++insert;

          if (TII_->isTailCall(*MI)) { // replace `tail`s with `call+ret`s
            MI->setDesc(TII_->get(llvm::RISCV::PseudoCALL));
            llvm::BuildMI(*MBB, insert, MI->getDebugLoc(),
                          TII_->get(llvm::RISCV::PseudoRET));
            ret_regs.insert(llvm::RISCV::X10);
            ret_regs.insert(
                llvm::RISCV::X11); // FIXME: We do not really know here, whether
                                   // x10 and x11 are actually used for return
          }
          insert = MI->getIterator();
          ++insert;
          // copying the return value/s to shadow reg
          llvm::outs() << "MI:" << *MI << "\n";

          for (const auto &r : ret_regs) {
            llvm::outs() << "ret_reg: x" << r - llvm::RISCV::X0 << "\n";
            moveIntoShadow(MI->getParent(), insert, r, P2S_.at(r));
          }
          insert = MI->getIterator();
          ++insert;
          if(use_shadow_for_stack_ops_) {
            riscv_common::loadRegs(sregs, MBB, insert, P2S_.at(riscv_common::kSP));
          }
          else {
            riscv_common::loadRegs(sregs, MBB, insert);
          }
        } else { // the caller is a not DMRed function, so business as usual.
          llvm::outs()
              << "dbg: both caller [" << fname_ << "]->callee["
              << callee_func_name
              << "] are not DMR: so don't care about calling convention...\n";
        }
      }
    }
  } else if (config_.sh == SelectiveHardening::SH2) {
    // not implemented yet.
  }
}

void RISCVDmr::protectCalls() {
  // first handling lib-calls:

  // handy lambda for reusability
  auto handleLibCallLC0{
      [this](llvm::MachineInstr *MI, llvm::MachineBasicBlock::iterator insert) {
        auto ret_regs{getRetRegs(MI)};

        llvm::outs() << "\tNOTE: " + getCalledFuncName(MI)
                     << " is outside SoR and hence is vulnerable\n";

        if (!llvm::cl::enable_repair &&
            config_.psuc == ProtectStrategyUserCall::UC3) {
          // even if they are dead they have to be kept alive as
          // user func call needs perfect matching b/w the 2 regfiles all the
          // time
          ret_regs.emplace(llvm::RISCV::X10);
          ret_regs.emplace(llvm::RISCV::X11);
        }

        // copying the return value/s to shadow reg
        for (const auto &r : ret_regs) {
          moveIntoShadow(MI->getParent(), insert, r, P2S_.at(r));
        }
      }};

  // live shadows involving t0-t6, a0-a7 can be corrupted by lib-calls hence
  // preserving them across func call
  for (auto MI : lib_calls_) {
    // filtering out tail calls in case they are to be duplicated
    if (config_.pslc == ProtectStrategyLibCall::LC1 && TII_->isTailCall(*MI)) {
      // TODO: stacking wont work here so need to make this a normal call
      // followed by a return
      continue;
    }

    auto ret_regs{getRetRegs(MI)};
    auto MBB{MI->getParent()};
    auto called_func_name{getCalledFuncName(MI)};
    llvm::MachineBasicBlock::iterator insert{MI->getIterator()};
    insert++;

    RegSetType regs_need_preservation{};
    for (unsigned r = llvm::RISCV::X3; r <= llvm::RISCV::X31; ++r) {
      if (!riscv_common::setmapContains(callee_saved_regs_, r)) {
        regs_need_preservation.emplace(r);
      }
    }
    // ret-regs would be changed after func call hence dont need to stack them
    if (riscv_common::setmapContains(ret_regs, llvm::RISCV::X10)) {
      regs_need_preservation.erase(llvm::RISCV::X10);
    }
    if (riscv_common::setmapContains(ret_regs, llvm::RISCV::X11)) {
      regs_need_preservation.erase(llvm::RISCV::X11);
    }

    if (llvm::cl::enable_repair) {
      regs_need_preservation.clear();
    }

    std::vector<llvm::Register> stacked_regs{regs_need_preservation.begin(),
                                             regs_need_preservation.end()};

    // TODO: stacking regs before a libcall could be dangerous when the
    //       args-struct elements preceede the no of arg regs -> rest is
    //       in stack which could be corrupted
    if (use_shadow_for_stack_ops_) {
      riscv_common::saveRegs(stacked_regs, MBB, MI->getIterator(),
                             P2S_.at(riscv_common::kSP));
      riscv_common::loadRegs(stacked_regs, MBB, insert,
                             P2S_.at(riscv_common::kSP));
    } else {
      riscv_common::saveRegs(stacked_regs, MBB, MI->getIterator());
      riscv_common::loadRegs(stacked_regs, MBB, insert);
    }

    if (config_.pslc == ProtectStrategyLibCall::LC0) {
      handleLibCallLC0(MI, insert);
    } else if (config_.pslc == ProtectStrategyLibCall::LC1) {
      auto arg_regs{getArgRegs(MI)};
      auto ret_regs{getRetRegs(MI)};
      auto MBB{MI->getParent()};
      auto DLL{MI->getDebugLoc()};
      llvm::MachineBasicBlock::iterator insert2{MI->getIterator()};
      insert2++;

      auto called_func_name{getCalledFuncName(MI)};
      // TODO: do we need to stack stuff that is live and could be corrupted by
      // func call hierarchy

      if (knownLibcalls2Duplicable_.at(called_func_name)) {
        if (ret_regs.size() == 0) {
          llvm::outs() << "\tNOTE: is it really worth duplicating "
                       << getCalledFuncName(MI) << "??\n";
        }

        // TODO: stacking regs before a libcall could be dangerous when the
        //       args-struct elements preceede the no of arg regs -> rest is
        //       in stack which could be corrupted

        // stacking the ret_regs
        // regs_to_spill.clear();
        std::vector<llvm::Register> regs_to_spill{};
        for (const auto &r : ret_regs) {
          regs_to_spill.emplace_back(r);
        }

        // stacking the arg regs
        for (const auto &r : arg_regs) {
          if (std::find(regs_to_spill.begin(), regs_to_spill.end(), r) ==
              regs_to_spill.end()) {
            regs_to_spill.emplace_back(r);
          }
        }
        if (use_shadow_for_stack_ops_) {
          riscv_common::saveRegs(regs_to_spill, MBB, insert2,
                                 P2S_.at(riscv_common::kSP));
        } else {
          riscv_common::saveRegs(regs_to_spill, MBB, insert2);
        }

        // // moving in shadow arg values into primary ones for 2nd call
        for (const auto &r : arg_regs) {
          moveIntoShadow(MBB, insert2, P2S_.at(r), r);
        }

        // inserting in the duplicated call
        MBB->insert(insert2, MF_->CloneMachineInstr(MI));

        // recovering the primary arg regs back after 2nd call
        std::vector<llvm::Register> regs_to_reload{};
        for (auto &r : regs_to_spill) {
          if (riscv_common::setmapContains(ret_regs, r)) {
            regs_to_reload.emplace_back(P2S_.at(r));
          } else {
            regs_to_reload.emplace_back(r);
          }
        }
        if (use_shadow_for_stack_ops_) {
          riscv_common::loadRegs(regs_to_reload, MBB, insert2,
                                 P2S_.at(riscv_common::kSP));
        } else {
          riscv_common::loadRegs(regs_to_reload, MBB, insert2);
        }
      } else {
        auto arg_regs{getArgRegs(MI)};
        // these calls cant be duplicated hence handling them LC2 style

        for (auto &r : arg_regs) {
          if (riscv_common::getRegType(r) == riscv_common::RegType::I) {
            llvm::BuildMI(*MBB, MI->getIterator(), MI->getDebugLoc(),
                          TII_->get(llvm::RISCV::BNE))
                .addReg(r)
                .addReg(P2S_.at(r))
                .addMBB(err_bb_);
          } else {
            syncFPRegs(MI->getParent(), MI->getIterator(), r, P2S_.at(r));
          }
        }

        handleLibCallLC0(MI, insert);
      }
    } else {
      assert(0 && "this protect-strategy for libcalls is not supported yet");
    }
  }

  // ----------
  // now handling user-func calls:
  // ----------
  if (config_.psuc == ProtectStrategyUserCall::UC0) {
    return;
  } else if (config_.psuc == ProtectStrategyUserCall::UC3) {
    if (llvm::cl::enable_repair) {
      for (auto MI : user_calls_) {
        auto arg_regs{getArgRegs(MI)};
        for (const auto &r : arg_regs) {
          if (riscv_common::getRegType(r) == riscv_common::RegType::I) {
            llvm::BuildMI(*MI->getParent(), MI->getIterator(),
                          MI->getDebugLoc(), TII_->get(llvm::RISCV::BNE))
                .addReg(r)
                .addReg(P2S_.at(r))
                .addMBB(err_bb_);
          } else {
            syncFPRegs(MI->getParent(), MI->getIterator(), r, P2S_.at(r));
          }
        }
      }

      return;
    }

    auto &entry_BB{MF_->front()};
    llvm::MachineBasicBlock::iterator insert{entry_BB.front().getIterator()};
    insert++;

    if (fname_ != "main") {
      for (unsigned r = llvm::RISCV::X0; r <= llvm::RISCV::X31; ++r) {
        if (!riscv_common::setmapContains(P2S_, r)) {
          continue;
        }
        if (r == riscv_common::kRA) {
          continue;
        }
        if (riscv_common::inCSString(llvm::cl::enable_cfcss, fname_) ||
            riscv_common::inCSString(llvm::cl::enable_rasm, fname_)) {
          if (r == llvm::RISCV::X5) {
            continue;
          }
        }

        llvm::BuildMI(entry_BB, insert, insert->getDebugLoc(),
                      TII_->get(llvm::RISCV::BNE))
            .addReg(r)
            .addReg(P2S_.at(r))
            .addMBB(err_bb_);
      }

      // TODO: compare FP reg files at start of func
      // if (uses_FPregfile_) {
      //   auto fpr_mvx_opcode{llvm::RISCV::FMV_X_W};
      //   if (isa_config_.store_opcode == llvm::RISCV::SD) {
      //     fpr_mvx_opcode = llvm::RISCV::FMV_X_D;
      //   }
      //
      //   for (unsigned r = llvm::RISCV::F0_F; r <= llvm::RISCV::F31_F; ++r)
      //   {
      //     if (P2S_.find(r) == P2S_.end()) {
      //       continue;
      //     }
      //
      //     llvm::BuildMI(entry_BB, insert, insert->getDebugLoc(),
      //                   TII_->get(fpr_mvx_opcode))
      //         .addReg(P2S_.at(riscv_common::k0))
      //         .addReg(r);
      //     llvm::BuildMI(entry_BB, insert, insert->getDebugLoc(),
      //                   TII_->get(fpr_mvx_opcode))
      //         .addReg(P2S_.at(riscv_common::kRA))
      //         .addReg(P2S_.at(r));
      //     llvm::BuildMI(entry_BB, insert, insert->getDebugLoc(),
      //                   TII_->get(llvm::RISCV::BNE))
      //         .addReg(P2S_.at(riscv_common::k0))
      //         .addReg(P2S_.at(riscv_common::kRA))
      //         .addMBB(err_bb_);
      //   }
      //
      //   llvm::BuildMI(entry_BB, insert, insert->getDebugLoc(),
      //                 TII_->get(llvm::RISCV::ADDI))
      //       .addReg(P2S_.at(riscv_common::k0))
      //       .addReg(riscv_common::k0)
      //       .addImm(0);
      // }
    } else {
      for (unsigned r = llvm::RISCV::X0; r <= llvm::RISCV::X31; ++r) {
        if (!riscv_common::setmapContains(P2S_, r)) {
          continue;
        }
        if (r == riscv_common::kRA || r == riscv_common::kSP ||
            r == riscv_common::k0) {
          // these regs are already done by duplicateInstructions()
          continue;
        }
        if (riscv_common::inCSString(llvm::cl::enable_cfcss, fname_) &&
            r == llvm::RISCV::X5) {
          continue;
        }

        llvm::BuildMI(entry_BB, insert, insert->getDebugLoc(),
                      TII_->get(llvm::RISCV::ADDI))
            .addReg(P2S_.at(r))
            .addReg(r)
            .addImm(0);
      }

      // TODO: enable this when above TODO regarding FP is fixed
      // if (uses_FPregfile_) {
      //   auto fpr_mv_opcode{llvm::RISCV::FSGNJ_S};
      //   if (isa_config_.store_opcode == llvm::RISCV::SD) {
      //     fpr_mv_opcode = llvm::RISCV::FSGNJ_D;
      //   }
      //
      //   for (unsigned r = llvm::RISCV::F0_F; r <= llvm::RISCV::F31_F; ++r)
      //   {
      //     if (P2S_.find(r) == P2S_.end()) {
      //       continue;
      //     }
      //
      //     llvm::BuildMI(entry_BB, insert, insert->getDebugLoc(),
      //                   TII_->get(fpr_mv_opcode))
      //         .addReg(P2S_.at(r))
      //         .addReg(r)
      //         .addReg(r);
      //   }
      // }
    }
  } else if (config_.psuc == ProtectStrategyUserCall::UC1) {
    for (const auto &MI : user_calls_) {
      auto arg_regs{getArgRegs(MI)};
      for (auto &r : arg_regs) {
        llvm::BuildMI(*MI->getParent(), MI->getIterator(), MI->getDebugLoc(),
                      TII_->get(llvm::RISCV::BNE))
            .addReg(r)
            .addReg(P2S_.at(r))
            .addMBB(err_bb_);
      }

      if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_)) {
        llvm::BuildMI(*MI->getParent(), std::next(MI->getIterator()),
                      MI->getDebugLoc(), TII_->get(llvm::RISCV::ADD))
            .addReg(P2S_.at(riscv_common::kSP))
            .addReg(riscv_common::kSP)
            .addImm(frame_size_);
      }
    }
  } else {
    assert(0 && "this protect-strategy for user-calls is not supported yet");
  }

  // ----------
  // now handling recursive indirect calls (jalr)
  // ----------
  for (auto &MI : indirect_calls_) {
    if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_)) {
      llvm::BuildMI(*MI->getParent(), std::next(MI->getIterator()),
                    MI->getDebugLoc(), TII_->get(llvm::RISCV::ADD))
          .addReg(P2S_.at(riscv_common::kSP))
          .addReg(riscv_common::kSP)
          .addImm(frame_size_);
    }
  }

#ifdef DBG
  llvm::outs() << "COMPAS_DBG: protectCalls() done\n";
#endif
}

void RISCVDmr::protectBranches() {
  if (config_.psb == ProtectStrategyBranch::B0) {
    return;
  }

  if (config_.psb == ProtectStrategyBranch::B2) {
    for (auto MI : branches_) {
      if (MI->isUnconditionalBranch()) {
        llvm::MachineBasicBlock::iterator insert{MI->getIterator()};
        insert++;
        llvm::BuildMI(*MI->getParent(), insert, MI->getDebugLoc(),
                      TII_->get(llvm::RISCV::JAL))
            .addReg(riscv_common::k0)
            .addMBB(err_bb_);

        // NOTE: due to nemesis it can happen that the original successor chain
        //       is being broken
        //       so if we encounter an unconditional jump to previously
        //       chained block then we have to reestablish the link
        // TODO: this workaround only works if the unconditional branch follows
        //       a conditional branch (which led to nemesis blocks)
        MI->getParent()->addSuccessor(MI->getOperand(0).getMBB());
      } else if (MI->isConditionalBranch()) {
        auto MBB{MI->getParent()};
        assert(MI->getOperand(2).isMBB() && "this branch is odd!");
        auto taken_BB{MI->getOperand(2).getMBB()};

        // fall-through path dup
        auto si{MF_->CloneMachineInstr(MI)};
        for (auto &o : si->operands()) {
          if (o.isReg()) {
            o.setReg(P2S_.at(o.getReg()));
          }
        }
        si->getOperand(2).setMBB(err_bb_);
        MBB->insertAfter(MI, si);

        // taken path dup
        auto nemesis_taken_BB{
            MF_->CreateMachineBasicBlock(MBB->getBasicBlock())};
        MF_->insert(MF_->end(), nemesis_taken_BB);
        MBB->replaceSuccessor(taken_BB, nemesis_taken_BB);
        nemesis_taken_BB->addSuccessor(taken_BB);
        nemesis_bbs_.emplace(nemesis_taken_BB);

        si = MF_->CloneMachineInstr(si);
        si->getOperand(2).setMBB(taken_BB);
        MI->getOperand(2).setMBB(nemesis_taken_BB);
        nemesis_taken_BB->insert(nemesis_taken_BB->begin(), si);
        llvm::BuildMI(*nemesis_taken_BB, nemesis_taken_BB->end(),
                      si->getDebugLoc(), TII_->get(llvm::RISCV::JAL))
            .addReg(riscv_common::k0)
            .addMBB(err_bb_);
      } else if (MI->isIndirectBranch()) {
        llvm::outs()
            << "\tWARNING: Branch protection not applicable. Is indirect MI:"
            << *MI << "\n";
      } else {
        assert(0 && "what is this branch");
      }
    }
  } else if (config_.psb == ProtectStrategyBranch::B3) { // nemesec
    for (auto MI : branches_) {
      if (MI->isUnconditionalBranch()) {
        llvm::MachineBasicBlock::iterator insert{MI->getIterator()};
        insert++;
        llvm::BuildMI(*MI->getParent(), insert, MI->getDebugLoc(),
                      TII_->get(llvm::RISCV::JAL))
            .addReg(riscv_common::k0)
            .addMBB(err_bb_);
      } else if (MI->isConditionalBranch()) {
        auto MBB{MI->getParent()};

        assert(MI->getOperand(2).isMBB() && "this branch is odd!");
        auto taken_BB{MI->getOperand(2).getMBB()};

        auto nottaken_BB{MBB->getFallThrough()};
        assert(nottaken_BB && "this branch has no fallthrough!");

        llvm::BuildMI(*MBB, MBB->end(), MI->getDebugLoc(),
                      TII_->get(llvm::RISCV::JAL))
            .addReg(riscv_common::k0)
            .addMBB(
                err_bb_); // push back an unconditional jump to error-BB to
                          // protect previous unconditional jump to "not taken"

        // fall-through path dup
        // this needs to be a new basic block and replaced with an unconditional
        // jump to it
        auto nemesec_nottaken_BB{
            MF_->CreateMachineBasicBlock()}; // MBB->getBasicBlock())};
        MF_->insert(MF_->end(), nemesec_nottaken_BB);
        auto si{MF_->CloneMachineInstr(MI)};
        for (auto &o : si->operands()) {
          if (o.isReg()) {
            o.setReg(P2S_.at(o.getReg()));
          }
        }

        MBB->ReplaceUsesOfBlockWith(
            nottaken_BB,
            nemesec_nottaken_BB); // maybe instead replaceSuccessor()
        nemesec_nottaken_BB->addSuccessor(nottaken_BB);
        nemesis_bbs_.emplace(nemesec_nottaken_BB);

        si->getOperand(2).setMBB(err_bb_);
        nemesec_nottaken_BB->push_back(si);
        llvm::MachineBasicBlock::iterator insert =
            nemesec_nottaken_BB->instr_end();
        llvm::BuildMI(*si->getParent(), insert, si->getDebugLoc(),
                      TII_->get(llvm::RISCV::JAL))
            .addReg(riscv_common::k0)
            .addMBB(nottaken_BB); // we need to jump back to fallthrough
        insert = MI->getIterator();
        llvm::BuildMI(*MI->getParent(), ++insert, MI->getDebugLoc(),
                      TII_->get(llvm::RISCV::JAL))
            .addReg(riscv_common::k0)
            .addMBB(nemesec_nottaken_BB);

        // taken path duplication
        auto nemesis_taken_BB{MF_->CreateMachineBasicBlock()};
        MF_->insert(MF_->end(), nemesis_taken_BB);
        MBB->ReplaceUsesOfBlockWith(
            taken_BB, nemesis_taken_BB); // maybe isntead replaceSuccessor()
        nemesis_taken_BB->addSuccessor(taken_BB);
        nemesis_bbs_.emplace(nemesis_taken_BB);

        si = MF_->CloneMachineInstr(si);
        si->getOperand(2).setMBB(taken_BB);
        MI->getOperand(2).setMBB(nemesis_taken_BB);
        nemesis_taken_BB->insert(nemesis_taken_BB->begin(), si);
        llvm::BuildMI(*nemesis_taken_BB, nemesis_taken_BB->end(),
                      si->getDebugLoc(), TII_->get(llvm::RISCV::JAL))
            .addReg(riscv_common::k0)
            .addMBB(err_bb_);
      } else if (MI->isIndirectBranch()) {
        llvm::outs()
            << "\tWARNING: Branch protection not applicable. Is indirect MI:"
            << *MI << "\n";
      } else {
        assert(0 && "what is this branch");
      }
    }
  } else if (config_.psb == ProtectStrategyBranch::B1) {
    for (auto MI : branches_) {
      if (MI->isConditionalBranch()) {
        for (const auto &op : MI->operands()) {
          if (op.isReg()) {
            llvm::BuildMI(*MI->getParent(), MI->getIterator(),
                          MI->getDebugLoc(), TII_->get(llvm::RISCV::BNE))
                .addReg(op.getReg())
                .addReg(P2S_.at(op.getReg()))
                .addMBB(err_bb_);
          }
        }
      }
    }
  } else {
    // assert(0 && "this protect-strategy for branches is not supported yet");
  }

#ifdef DBG
  llvm::outs() << "COMPAS_DBG: protectBranches() done\n";
#endif
}

// for now we just write '1' to special memory address (0xfff0) to tell the
// simulator that this FI is covered in a separate error-BB. Further we
// stay in this loop to avoid further functional execution
void RISCVDmr::insertErrorBB() {
  err_bb_ = MF_->CreateMachineBasicBlock();
  MF_->push_back(err_bb_);

  auto DLL{MF_->front().front().getDebugLoc()};

  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED1) {
    // storing '1' to addr : (0xfff0 = 0x10000 - 0x10):
    // lui t1, 16 -> makes t1 = 0x10000
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(llvm::RISCV::LUI))
        .addReg(llvm::RISCV::X6)
        .addImm(16);
    // addi t2, zero, 1 -> makes t2 = 1
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(llvm::RISCV::X7)
        .addReg(riscv_common::k0)
        .addImm(1);
    // sw t2, -16(t1) -> stores t2 to (t1 - 8) i.e. store 1 to 0xfff0
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(isa_config_.store_opcode))
        .addReg(llvm::RISCV::X7)
        .addReg(llvm::RISCV::X6)
        .addImm(-16);
  } else if (config_.eds == riscv_common::ErrorDetectionStrategy::ED3) {
    // storing '93' to a7, aka SYS_exit code ECALL code:
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(llvm::RISCV::X17) // a7
        .addReg(llvm::RISCV::X0)  // zero
        .addImm(93);
    // storing '-512' to a0, aka exit return value when ecall forces newlib sys
    // exit:
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(llvm::RISCV::X10) // a7
        .addReg(llvm::RISCV::X0)  // zero
        .addImm(-512);
    // invoke 'ecall'
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(llvm::RISCV::ECALL));
  }
  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED1 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED3) {

    // to encode the error-BB in order to make it a label so as to be able to
    // jump to it from anywhere in asm
    err_bb_->addSuccessor(err_bb_);
    // // keep on repeating this errBB as we dont want to execute code now
    // // J err_bb_ = JALR X0, err_bb_ because J is a pseudo-jump instr in RISCV
    // llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
    // TII_->get(llvm::RISCV::JAL))
    //     .addReg(riscv_common::k0)
    //     .addMBB(err_bb_);
  }

  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED3) {
    // keep on repeating this errBB as we dont want to execute code now
    // J err_bb_ = JALR X0, err_bb_ because J is a pseudo-jump instr in RISCV
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(llvm::RISCV::JAL))
        .addReg(riscv_common::k0)
        .addMBB(err_bb_);

  } else {
    // quit early using ebreak
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(llvm::RISCV::EBREAK));
  }
}

bool RISCVDmr::isShadowInstr(const llvm::MachineInstr *MI) const {
  if (MI->isCFIInstruction() || MI->isReturn()) {
    return false;
  }

  for (auto &o : MI->operands()) {
    if (o.isReg()) {
      if (riscv_common::setmapContains(P2S_, o.getReg())) {
        return false;
      }
    }
  }

  // filtering out sihft code:
  // instrs that are defining shadow-zero are solely for safety purposes and
  // are not functional b/c functionality wise zero reg cant get defined
  if (!MI->isConditionalBranch() && MI->getOperand(0).isReg() &&
      MI->getOperand(0).getReg() == P2S_.at(riscv_common::k0)) {
    return false;
  }

  return true;
}

llvm::Register RISCVDmr::getPrimaryFromShadow(llvm::Register rs) const {
  for (const auto &p : P2S_) {
    if (p.second == rs) {
      return p.first;
    }
  }

  assert(0);
  return 0;
}

void RISCVDmr::repair() {
  llvm::outs() << "COMPAS: Running REPAIR transformation on DMR code\n";

  std::map<llvm::MachineBasicBlock *, RegMapType> MBB2Liveins{};
  std::map<llvm::MachineBasicBlock *, bool> MBB2Visited{};
  std::map<llvm::MachineBasicBlock *, llvm::MachineBasicBlock *>
      MBB2Liveinsmodifier{};

  auto printRegMap{[this](RegMapType reg_map) {
    llvm::outs() << "live-regs = {";
    for (auto p : reg_map) {
      llvm::outs() << Reg2Name_.at(p.first) << " : " << Reg2Name_.at(p.second)
                   << ", ";
    }
    llvm::outs() << "}\n";
  }};

  // initialization
  for (auto &MBB : *MF_) {
    MBB2Liveinsmodifier[&MBB] = nullptr;
    MBB2Visited[&MBB] = false;

    for (auto &li : MBB.liveins()) {
      MBB2Liveins[&MBB][li.PhysReg] = P2S_.at(li.PhysReg);

      if (riscv_common::getRegType(li.PhysReg) == riscv_common::RegType::I) {
        continue;
      } else if (riscv_common::getRegType(li.PhysReg) ==
                 riscv_common::RegType::FS) {
        MBB2Liveins[&MBB][li.PhysReg - 32] = P2S_.at(li.PhysReg - 32);
      } else if (riscv_common::getRegType(li.PhysReg) ==
                 riscv_common::RegType::FD) {
        MBB2Liveins[&MBB][li.PhysReg + 32] = P2S_.at(li.PhysReg + 32);
      } else {
        // TODO
        assert(0);
      }
    }
    // zero, RA, SP, FP, GP are always live
    MBB2Liveins[&MBB][riscv_common::k0] = P2S_.at(riscv_common::k0);
    MBB2Liveins[&MBB][riscv_common::kSP] = P2S_.at(riscv_common::kSP);
    MBB2Liveins[&MBB][riscv_common::kRA] = P2S_.at(riscv_common::kRA);
    MBB2Liveins[&MBB][riscv_common::kFP] = P2S_.at(riscv_common::kFP);
    MBB2Liveins[&MBB][riscv_common::kGP] = P2S_.at(riscv_common::kGP);

    if (MBB.succ_empty()) {
      MBB2Liveins[&MBB][llvm::RISCV::X10] = P2S_.at(llvm::RISCV::X10);
      MBB2Liveins[&MBB][llvm::RISCV::X11] = P2S_.at(llvm::RISCV::X11);
    }

    if (MBB.pred_empty() || MBB.succ_empty()) {
      MBB2Liveinsmodifier[&MBB] = &MBB;
    }
    if (err_bb_ == &MBB) {
      MBB2Visited[&MBB] = true;
    }
  }

  // traversal and repairing instructions
  while (1) {
    for (auto &MBB : *MF_) {
      if (!MBB2Liveinsmodifier[&MBB] || MBB2Visited[&MBB]) {
        continue;
      }

      RegMapType LiveP2S{MBB2Liveins[&MBB]};

      auto getFreeShadowReg{[this,
                             &LiveP2S](llvm::Register start_reg,
                                       llvm::Register end_reg,
                                       bool for_SP = false) -> llvm::Register {
        std::default_random_engine gen{};
        std::uniform_int_distribution<unsigned> unif_dist{start_reg, end_reg};

        unsigned while_cnt{1000};
        while (while_cnt) {
          while_cnt--;

          auto r{unif_dist(gen)};
          // filtering primary regs
          if (riscv_common::setmapContains(P2S_, r) ||
              riscv_common::setmapContains(reserved_fp_primary_, r)) {
            continue;
          }
          if (for_SP && !riscv_common::setmapContains(callee_saved_regs_, r)) {
            continue;
          }

          if (!riscv_common::mapValContains(LiveP2S, r)) {
            return r;
          }
        }

        assert(for_SP);
        return LiveP2S[riscv_common::kSP];
      }};

      // printRegMap(LiveP2S);
      // MBB.dump();
      // llvm::outs() << "===\n";

      std::set<llvm::MachineInstr *> ignore_these{};
      for (auto &MI : MBB) {
        if (riscv_common::setmapContains(ignore_these, &MI)) {
          continue;
        }

        // MI.dump();
        // printRegMap(LiveP2S);
        // llvm::outs() << "---\n";

        if (isShadowInstr(&MI)) {
          // how to handle normal shadow instructions

          // replacing the use operands
          llvm::Register prev_def{0}, new_def{0}, pri_def{0};
          for (auto &op : MI.operands()) {
            if (op.isReg() && op.isUse()) {
              assert(riscv_common::setmapContains(
                  LiveP2S, getPrimaryFromShadow(op.getReg())));

              op.setReg(LiveP2S[getPrimaryFromShadow(op.getReg())]);
            }
          }

          // replacing def operand
          llvm::MachineOperand *def_op{nullptr};
          for (auto &op : MI.operands()) {
            if (op.isReg() && op.isDef()) {
              def_op = &op;
              break;
            }
          }
          if (!def_op) {
            continue;
          }

          prev_def = def_op->getReg();
          pri_def = getPrimaryFromShadow(prev_def);

          // first finding a new free shadow reg for replacing prev def
          if (riscv_common::getRegType(prev_def) == riscv_common::RegType::I) {
            new_def = getFreeShadowReg(llvm::RISCV::X0, llvm::RISCV::X31,
                                       pri_def == riscv_common::kSP);
            LiveP2S[pri_def] = new_def;
          } else if (riscv_common::getRegType(prev_def) ==
                     riscv_common::RegType::FS) {
            new_def = getFreeShadowReg(llvm::RISCV::F0_F, llvm::RISCV::F31_F);
            LiveP2S[pri_def] = new_def;
            LiveP2S[pri_def - 32] = new_def - 32;
          } else if (riscv_common::getRegType(prev_def) ==
                     riscv_common::RegType::FD) {
            new_def = getFreeShadowReg(llvm::RISCV::F0_D, llvm::RISCV::F31_D);
            LiveP2S[pri_def] = new_def;
            LiveP2S[pri_def + 32] = new_def + 32;
          } else {
            assert(0);
          }

          def_op->setReg(new_def);
        } else if (riscv_common::setmapContains(loadbacks_, &MI)) {
          // how to handle nzdc loadbacks

          for (auto &op : MI.operands()) {
            if (op.isReg() && riscv_common::mapValContains(P2S_, op.getReg())) {
              op.setReg(LiveP2S[getPrimaryFromShadow(op.getReg())]);
            }
          }
          // for FP loadbacks, have to further update the following FEQ.x
          // instruction as well
          if (MI.getOperand(0).isReg() &&
              riscv_common::getRegType(MI.getOperand(0).getReg()) !=
                  riscv_common::RegType::I) {
            assert(std::next(MI.getIterator())->getOperand(2).isReg());
            std::next(MI.getIterator())
                ->getOperand(2)
                .setReg(LiveP2S[getPrimaryFromShadow(
                    std::next(MI.getIterator())->getOperand(2).getReg())]);
            ignore_these.emplace(&*std::next(MI.getIterator()));
          }
        } else if (riscv_common::setmapContains(user_calls_, &MI) ||
                   riscv_common::setmapContains(indirect_calls_, &MI)) {
          // how to handle user func calls

          llvm::MachineBasicBlock::iterator prev_it{MI.getIterator()},
              next_it{MI.getIterator()};
          prev_it--;
          next_it++;

          // establishing FCS:
          // the user callee expects args and SP to be in default P2S_[r]
          // shadows
          auto arg_regs{getArgRegs(&MI)};
          arg_regs.emplace(riscv_common::kSP);
          arg_regs.emplace(riscv_common::kFP);
          for (auto &r : arg_regs) {
            if (P2S_.at(r) == LiveP2S[r]) {
              continue;
            }
            moveIntoShadow(&MBB, MI.getIterator(), LiveP2S[r], P2S_.at(r));
          }

          auto ret_regs{getRetRegs(&MI)};
          for (const auto &r : ret_regs) {
            if (!riscv_common::setmapContains(LiveP2S, r)) {
              llvm::Register new_def{0};
              if (riscv_common::getRegType(r) == riscv_common::RegType::I) {
                new_def = getFreeShadowReg(llvm::RISCV::X0, llvm::RISCV::X31);
                LiveP2S[r] = new_def;
              } else if (riscv_common::getRegType(r) ==
                         riscv_common::RegType::FS) {
                new_def =
                    getFreeShadowReg(llvm::RISCV::F0_F, llvm::RISCV::F31_F);
                LiveP2S[r] = new_def;
                LiveP2S[r - 32] = new_def - 32;
              } else if (riscv_common::getRegType(r) ==
                         riscv_common::RegType::FD) {
                new_def =
                    getFreeShadowReg(llvm::RISCV::F0_D, llvm::RISCV::F31_D);
                LiveP2S[r] = new_def;
                LiveP2S[r + 32] = new_def + 32;
              } else {
                // TODO
                assert(0);
              }
            }

            if (P2S_.at(r) == LiveP2S[r]) {
              continue;
            }

            // TODO: FP regs??
            llvm::BuildMI(MBB, std::next(MI.getIterator()), MI.getDebugLoc(),
                          TII_->get(llvm::RISCV::ADDI))
                .addReg(LiveP2S[r])
                .addReg(P2S_.at(r))
                .addImm(0);
            ignore_these.emplace(&*std::next(MI.getIterator()));
          }

          // stacking live shadow and primary around this user-call
          if (!TII_->isTailCall(MI)) {
            llvm::Register prev_shadow_sp{LiveP2S[riscv_common::kSP]};
            std::set<llvm::Register> regs_to_spill{};
            for (const auto &p : LiveP2S) {
              if (p.first == riscv_common::k0 || p.first == riscv_common::kRA ||
                  p.first == riscv_common::kSP ||
                  p.first == riscv_common::kGP) {
                continue;
              }

              if (!riscv_common::setmapContains(ret_regs, p.first)) {
                if (riscv_common::getRegType(p.first) !=
                        riscv_common::RegType::FS ||
                    isa_config_.store_opcode == llvm::RISCV::SW) {
                  regs_to_spill.emplace(p.first);
                  regs_to_spill.emplace(p.second);
                }
              }
            }

            if (regs_to_spill.size()) {
              LiveP2S[riscv_common::kSP] =
                  getFreeShadowReg(llvm::RISCV::X0, llvm::RISCV::X31, true);
              riscv_common::saveRegs(
                  std::vector<llvm::Register>{regs_to_spill.begin(),
                                              regs_to_spill.end()},
                  &MBB, std::next(prev_it), prev_shadow_sp);
              std::next(prev_it)->getOperand(0).setReg(
                  LiveP2S[riscv_common::kSP]);

              // scanning for 'mv default_shadow_SP = live_shadow_sp'
              // instruction and updating it in case it is not found then
              // inserting one
              llvm::MachineBasicBlock::iterator it{prev_it};
              while (1) {
                it++;

                if (it->getOpcode() == llvm::RISCV::ADDI &&
                    it->getNumOperands() == 3 && it->getOperand(0).isReg() &&
                    it->getOperand(1).isReg() && it->getOperand(2).isImm() &&
                    it->getOperand(2).getImm() == 0 &&
                    it->getOperand(0).getReg() == P2S_.at(riscv_common::kSP)) {
                  it->getOperand(1).setReg(LiveP2S[riscv_common::kSP]);
                  break;
                }

                if (it == MI.getIterator()) {
                  llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                                TII_->get(llvm::RISCV::ADDI))
                      .addReg(P2S_.at(riscv_common::kSP))
                      .addReg(LiveP2S[riscv_common::kSP])
                      .addImm(0);
                  break;
                }
              }

              LiveP2S[riscv_common::kSP] =
                  getFreeShadowReg(llvm::RISCV::X0, llvm::RISCV::X31, true);
              riscv_common::loadRegs(
                  std::vector<llvm::Register>{regs_to_spill.begin(),
                                              regs_to_spill.end()},
                  &MBB, next_it, LiveP2S[riscv_common::kSP]);
              llvm::BuildMI(MBB, std::next(MI.getIterator()), MI.getDebugLoc(),
                            TII_->get(llvm::RISCV::ADDI))
                  .addReg(LiveP2S[riscv_common::kSP])
                  .addReg(P2S_.at(riscv_common::kSP))
                  .addImm(0);

              for (it = std::next(MI.getIterator()); it != next_it; ++it) {
                for (auto &op : it->operands()) {
                  if (op.isReg() && op.getReg() == LiveP2S[riscv_common::kSP]) {
                    ignore_these.emplace(&*it);
                    break;
                  }
                }
              }

              LiveP2S[riscv_common::kSP] =
                  getFreeShadowReg(llvm::RISCV::X0, llvm::RISCV::X31, true);
              std::prev(std::prev(next_it))
                  ->getOperand(0)
                  .setReg(LiveP2S[riscv_common::kSP]);
            }
          }
        } else if (riscv_common::setmapContains(lib_calls_, &MI)) {
          // how to handle lib calls

          auto isStackAllocatedInstr{[](llvm::MachineInstr *MI) -> int {
            int status{-1};

            if (MI->getOpcode() == llvm::RISCV::ADDI &&
                MI->getNumOperands() == 3 && MI->getOperand(0).isReg() &&
                MI->getOperand(1).isReg() && MI->getOperand(2).isImm() &&
                MI->getOperand(0).getReg() == MI->getOperand(1).getReg()) {
              if (MI->getOperand(2).getImm() > 0) {
                status = 1;
              } else if (MI->getOperand(2).getImm() < 0) {
                status = 0;
              }
            }

            return status;
          }};

          // stacking live regs around this lib call
          auto ret_regs{getRetRegs(&MI)};
          for (const auto &r : ret_regs) {
            if (!riscv_common::setmapContains(LiveP2S, r)) {
              llvm::Register new_def{0};
              if (riscv_common::getRegType(r) == riscv_common::RegType::I) {
                new_def = getFreeShadowReg(llvm::RISCV::X0, llvm::RISCV::X31);
                LiveP2S[r] = new_def;
              } else if (riscv_common::getRegType(r) ==
                         riscv_common::RegType::FS) {
                new_def =
                    getFreeShadowReg(llvm::RISCV::F0_F, llvm::RISCV::F31_F);
                LiveP2S[r] = new_def;
                LiveP2S[r - 32] = new_def - 32;
              } else if (riscv_common::getRegType(r) ==
                         riscv_common::RegType::FD) {
                new_def =
                    getFreeShadowReg(llvm::RISCV::F0_D, llvm::RISCV::F31_D);
                LiveP2S[r] = new_def;
                LiveP2S[r + 32] = new_def + 32;
              } else {
                // TODO
                assert(0);
              }
            }
          }

          std::set<llvm::Register> regs_to_spill{}, regs_to_spill_2ndcall{};

          if (!TII_->isTailCall(MI)) {
            for (const auto &p : LiveP2S) {
              if (p.first == riscv_common::k0 || p.first == riscv_common::kRA ||
                  p.first == riscv_common::kSP ||
                  p.first == riscv_common::kGP) {
                continue;
              }

              if (!riscv_common::setmapContains(callee_saved_regs_, p.second)) {
                if (riscv_common::getRegType(p.first) !=
                        riscv_common::RegType::FS ||
                    isa_config_.store_opcode == llvm::RISCV::SW) {
                  regs_to_spill.emplace(p.second);
                }
              }
              if (!riscv_common::setmapContains(ret_regs, p.first)) {
                if (!riscv_common::setmapContains(callee_saved_regs_,
                                                  p.second)) {
                  if (riscv_common::getRegType(p.first) !=
                          riscv_common::RegType::FS ||
                      isa_config_.store_opcode == llvm::RISCV::SW) {
                    regs_to_spill_2ndcall.emplace(p.second);
                  }
                }
              }
            }
          }

          if (regs_to_spill.size()) {
            riscv_common::saveRegs(
                std::vector<llvm::Register>{regs_to_spill.begin(),
                                            regs_to_spill.end()},
                &MBB, MI.getIterator(), LiveP2S[riscv_common::kSP]);
            LiveP2S[riscv_common::kSP] =
                getFreeShadowReg(llvm::RISCV::X0, llvm::RISCV::X31, true);
            llvm::MachineBasicBlock::iterator it{MI.getIterator()};
            while (1) {
              it--;
              if (isStackAllocatedInstr(&*it) >= 0 &&
                  !riscv_common::setmapContains(P2S_,
                                                it->getOperand(0).getReg())) {
                it->getOperand(0).setReg(LiveP2S[riscv_common::kSP]);
                break;
              }
            }
          }

          // first focusing on lib calls that are duplicated
          if (knownLibcalls2Duplicable_.at(getCalledFuncName(&MI))) {
            llvm::MachineBasicBlock::iterator it{MI.getIterator()};

            if (regs_to_spill.size()) {
              riscv_common::loadRegs(
                  std::vector<llvm::Register>{regs_to_spill.begin(),
                                              regs_to_spill.end()},
                  &MBB, std::next(MI.getIterator()),
                  LiveP2S[riscv_common::kSP]);
              LiveP2S[riscv_common::kSP] =
                  getFreeShadowReg(llvm::RISCV::X0, llvm::RISCV::X31, true);
              while (1) {
                if (isStackAllocatedInstr(&*it) >= 0 &&
                    !riscv_common::setmapContains(P2S_,
                                                  it->getOperand(0).getReg())) {
                  it->getOperand(0).setReg(LiveP2S[riscv_common::kSP]);
                  it++; // to bypass current
                  it++; // to bypass primary stack alloc
                  break;
                }

                it++;
              }
            }

            bool secondcall_passed{false};
            unsigned stack_allocated{0};
            while (1) {
              if (it->isCall() && it != MI.getIterator()) {
                secondcall_passed = true;

                if (regs_to_spill_2ndcall.size()) {
                  riscv_common::saveRegs(
                      std::vector<llvm::Register>{regs_to_spill_2ndcall.begin(),
                                                  regs_to_spill_2ndcall.end()},
                      &MBB, it, LiveP2S[riscv_common::kSP]);
                  LiveP2S[riscv_common::kSP] =
                      getFreeShadowReg(llvm::RISCV::X0, llvm::RISCV::X31, true);
                  llvm::MachineBasicBlock::iterator it2{it};
                  while (1) {
                    it2--;
                    if (isStackAllocatedInstr(&*it2) >= 0 &&
                        !riscv_common::setmapContains(
                            P2S_, it2->getOperand(0).getReg())) {
                      it2->getOperand(0).setReg(LiveP2S[riscv_common::kSP]);
                      break;
                    }
                  }

                  riscv_common::loadRegs(
                      std::vector<llvm::Register>{regs_to_spill_2ndcall.begin(),
                                                  regs_to_spill_2ndcall.end()},
                      &MBB, std::next(it), LiveP2S[riscv_common::kSP]);
                  LiveP2S[riscv_common::kSP] =
                      getFreeShadowReg(llvm::RISCV::X0, llvm::RISCV::X31, true);
                  while (1) {
                    if (isStackAllocatedInstr(&*it) >= 0 &&
                        !riscv_common::setmapContains(
                            P2S_, it->getOperand(0).getReg())) {
                      it->getOperand(0).setReg(LiveP2S[riscv_common::kSP]);
                      it++;
                      break;
                    }

                    it++;
                  }
                }
              } else {
                // updating shadow regs as per LiveP2S
                for (auto &op : it->operands()) {
                  if (op.isReg() &&
                      riscv_common::mapValContains(P2S_, op.getReg())) {
                    op.setReg(LiveP2S[getPrimaryFromShadow(op.getReg())]);
                  }
                }

                auto stack_alloc_status{isStackAllocatedInstr(&*it)};
                if (stack_alloc_status >= 0) {
                  if (stack_alloc_status == 0) {
                    stack_allocated++;
                  } else {
                    stack_allocated--;
                  }

                  if (it->getOperand(0).getReg() ==
                      LiveP2S[riscv_common::kSP]) {
                    LiveP2S[riscv_common::kSP] = getFreeShadowReg(
                        llvm::RISCV::X0, llvm::RISCV::X31, true);
                    it->getOperand(0).setReg(LiveP2S[riscv_common::kSP]);
                  }
                }
              }

              if (secondcall_passed && !stack_allocated) {
                break;
              }

              it++;
            }

            // the already transformed instructions are to be ignored for
            // outer MIs scan
            for (auto it2{MI.getIterator()}; it2 != it; ++it2) {
              ignore_these.emplace(&*it2);
            }
          } // and now for lib calls that are not duplicated
          else {
            for (llvm::MachineBasicBlock::iterator it{MI.getIterator()};
                 it != MBB.end(); ++it) {
              if (it->isCall() && &*it != &MI) {
                break;
              }

              if (it->getOpcode() == llvm::RISCV::ADDI &&
                  it->getNumOperands() == 3 && it->getOperand(0).isReg() &&
                  it->getOperand(1).isReg() && it->getOperand(2).isImm()) {
                auto src_reg{it->getOperand(1).getReg()};
                auto dst_reg{it->getOperand(0).getReg()};
                if (it->getOperand(2).getImm() == 0 &&
                    riscv_common::setmapContains(P2S_, src_reg) &&
                    riscv_common::mapValContains(P2S_, dst_reg)) {
                  assert(riscv_common::setmapContains(LiveP2S, src_reg));

                  it->getOperand(0).setReg(LiveP2S[src_reg]);
                }
              }
            }

            if (regs_to_spill.size()) {
              llvm::MachineBasicBlock::iterator it{MI.getIterator()};
              riscv_common::loadRegs(
                  std::vector<llvm::Register>{regs_to_spill.begin(),
                                              regs_to_spill.end()},
                  &MBB, std::next(it), LiveP2S[riscv_common::kSP]);
              LiveP2S[riscv_common::kSP] =
                  getFreeShadowReg(llvm::RISCV::X0, llvm::RISCV::X31, true);
              while (1) {
                it++;

                if (isStackAllocatedInstr(&*it) >= 0 &&
                    !riscv_common::setmapContains(P2S_,
                                                  it->getOperand(0).getReg())) {
                  it->getOperand(0).setReg(LiveP2S[riscv_common::kSP]);
                  it++;
                  it++;
                  break;
                }
              }

              // the already transformed instructions are to be ignored for
              // outer MIs scan
              for (auto it2{MI.getIterator()}; it2 != it; ++it2) {
                ignore_these.emplace(&*it2);
              }
            }
          }
        } else if (MI.isReturn() && fname_ != "main") {
          // returning in user-func calls

          // TODO: for FP returns??

          for (auto &r : std::vector<llvm::Register>{
                   llvm::RISCV::X10, llvm::RISCV::X11, riscv_common::kSP}) {
            if (P2S_.at(r) == LiveP2S[r]) {
              continue;
            }

            llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                          TII_->get(llvm::RISCV::ADDI))
                .addReg(P2S_.at(r))
                .addReg(LiveP2S[r])
                .addImm(0);
          }
        } else {
          // sync checks
          if (MI.isConditionalBranch() && MI.getNumOperands() == 3 &&
              MI.getOperand(2).isMBB() && MI.getOperand(0).isReg() &&
              MI.getOperand(1).isReg() &&
              MI.getOperand(2).getMBB() == err_bb_) {
            auto first_reg{MI.getOperand(0).getReg()};
            auto second_reg{MI.getOperand(1).getReg()};
            if (first_reg != P2S_.at(riscv_common::k0) &&
                riscv_common::mapValContains(P2S_, first_reg)) {
              MI.getOperand(0).setReg(LiveP2S[getPrimaryFromShadow(first_reg)]);
            } else if (second_reg != P2S_.at(riscv_common::k0) &&
                       riscv_common::mapValContains(P2S_, second_reg)) {
              MI.getOperand(1).setReg(
                  LiveP2S[getPrimaryFromShadow(second_reg)]);
            }
          }

          if ((MI.getOpcode() == llvm::RISCV::FEQ_S ||
               MI.getOpcode() == llvm::RISCV::FEQ_D) &&
              MI.getNumOperands() == 3 && MI.getOperand(0).isReg() &&
              MI.getOperand(1).isReg() && MI.getOperand(2).isReg() &&
              MI.getOperand(0).getReg() == P2S_.at(riscv_common::k0)) {
            assert(
                riscv_common::mapValContains(P2S_, MI.getOperand(2).getReg()));
            assert(riscv_common::setmapContains(
                LiveP2S, getPrimaryFromShadow(MI.getOperand(2).getReg())));

            MI.getOperand(2).setReg(
                LiveP2S[getPrimaryFromShadow(MI.getOperand(2).getReg())]);
          }
        }
      } // end of MI scan

      if (!riscv_common::setmapContains(nemesis_bbs_, &MBB)) {
        // updating liveins of successors
        for (auto SBB : MBB.successors()) {
          for (const auto &p : LiveP2S) {
            if (p.first == riscv_common::k0 || p.second == riscv_common::kRA) {
              continue;
            }

            if (riscv_common::setmapContains(MBB2Liveins[SBB], p.first)) {
              if (!MBB2Liveinsmodifier[SBB]) {
                MBB2Liveinsmodifier[SBB] = &MBB;
              }

              if (MBB2Liveinsmodifier[SBB] == &MBB) {
                MBB2Liveins[SBB][p.first] = p.second;
              } else {
                // need to do register rotation before jumping to this SBB
                if (MBB2Liveins[SBB][p.first] != p.second) {
                  llvm::MachineBasicBlock::iterator insert{MBB.end()};
                  for (auto rit{MBB.rbegin()}; rit != MBB.rend(); ++rit) {
                    if (rit->isBranch() || rit->isCall()) {
                      for (auto &op : rit->operands()) {
                        if (op.isMBB() && op.getMBB() == SBB) {
                          insert = rit->getIterator();
                          break;
                        }
                      }

                      if (insert != MBB.end()) {
                        break;
                      }
                    }
                  }

                  moveIntoShadow(&MBB, insert, p.second,
                                 MBB2Liveins[SBB][p.first]);
                  // if (riscv_common::getRegType(p.second) ==
                  //     riscv_common::RegType::I) {
                  //   llvm::BuildMI(MBB, insert, MBB.front().getDebugLoc(),
                  //                 TII_->get(llvm::RISCV::ADDI))
                  //       .addReg(MBB2Liveins[SBB][p.first])
                  //       .addReg(p.second)
                  //       .addImm(0);
                  // } else if (riscv_common::getRegType(p.second) ==
                  //                riscv_common::RegType::FS &&
                  //            isa_config_.store_opcode == llvm::RISCV::SW) {
                  //   llvm::BuildMI(MBB, insert, MBB.front().getDebugLoc(),
                  //                 TII_->get(llvm::RISCV::FSGNJ_S))
                  //       .addReg(MBB2Liveins[SBB][p.first])
                  //       .addReg(p.second)
                  //       .addReg(p.second);
                  // } else if (riscv_common::getRegType(p.second) ==
                  //                riscv_common::RegType::FD &&
                  //            isa_config_.store_opcode == llvm::RISCV::SD) {
                  //   llvm::BuildMI(MBB, insert, MBB.front().getDebugLoc(),
                  //                 TII_->get(llvm::RISCV::FSGNJ_D))
                  //       .addReg(MBB2Liveins[SBB][p.first])
                  //       .addReg(p.second)
                  //       .addReg(p.second);
                  // } else if (riscv_common::getRegType(p.second) ==
                  //            riscv_common::RegType::FH) {
                  //   assert(0 && "TODO");
                  // }
                }
              }
            } else if (riscv_common::setmapContains(nemesis_bbs_, SBB)) {
              MBB2Liveinsmodifier[SBB] = &MBB;
              MBB2Liveins[SBB][p.first] = p.second;
            }
          }
        }
      } else {
        // for nemesisBB we create another BB for livein updates as we want to
        // do this after nemesisBB and before takenBB
        auto new_BB{MF_->CreateMachineBasicBlock(MBB.getBasicBlock())};
        MF_->insert(MBB.getIterator(), new_BB);

        llvm::MachineBasicBlock *current_succ{nullptr};
        for (auto &op : MBB.front().operands()) {
          if (op.isMBB()) {
            current_succ = op.getMBB();
            op.setMBB(new_BB);
            break;
          }
        }
        assert(current_succ);

        // TODO: can we optimize this without Jump instruction everytime!!
        llvm::BuildMI(*new_BB, new_BB->end(), MBB.front().getDebugLoc(),
                      TII_->get(llvm::RISCV::JAL))
            .addReg(riscv_common::k0)
            .addMBB(current_succ);

        MBB.replaceSuccessor(current_succ, new_BB);
        new_BB->addSuccessor(current_succ);
        MBB2Liveinsmodifier[new_BB] = &MBB;
        for (const auto &p : LiveP2S) {
          MBB2Liveins[new_BB][p.first] = p.second;
        }
      }

      // MBB.dump();
      // llvm::outs() << "repair finished ---\n";
      MBB2Visited[&MBB] = true;

      // cleanup: removing useless instrs from functionality point of view
      std::set<llvm::MachineInstr *> to_remove{};
      for (auto &MI : MBB) {
        if (MI.getOpcode() == llvm::RISCV::ADDI && MI.getNumOperands() == 3 &&
            MI.getOperand(0).isReg() && MI.getOperand(1).isReg() &&
            MI.getOperand(2).isImm() && MI.getOperand(2).getImm() == 0 &&
            MI.getOperand(0).getReg() == MI.getOperand(1).getReg()) {
          to_remove.emplace(&MI);
        }
      }
      for (auto MI : to_remove) {
        MBB.erase_instr(MI);
      }

    } // end of MBB scan

    bool keep_going{false};
    for (auto &MBB : *MF_) {
      if (!MBB2Visited[&MBB]) {
        keep_going = true;
        break;
      }
    }
    if (!keep_going) {
      break;
    }
  } // end of while(1)

  //
  //
  // DEPENDENCY RESOLUTION IN SHADOW ROTATION INSTRUCTIONS!!!
  // =========================================================
  auto isShadowRotInstr{[this](const llvm::MachineInstr *MI) {
    return (MI->getOpcode() == llvm::RISCV::ADDI && MI->getNumOperands() == 3 &&
            MI->getOperand(0).isReg() && MI->getOperand(1).isReg() &&
            MI->getOperand(2).isImm() && MI->getOperand(2).getImm() == 0 &&
            riscv_common::mapValContains(P2S_, MI->getOperand(0).getReg()) &&
            riscv_common::mapValContains(P2S_, MI->getOperand(1).getReg())) ||
           ((MI->getOpcode() == llvm::RISCV::FSGNJ_D ||
             MI->getOpcode() == llvm::RISCV::FSGNJ_S) &&
            MI->getNumOperands() == 3 && MI->getOperand(0).isReg() &&
            MI->getOperand(1).isReg() && MI->getOperand(2).isReg() &&
            riscv_common::mapValContains(P2S_, MI->getOperand(0).getReg()) &&
            riscv_common::mapValContains(P2S_, MI->getOperand(1).getReg()));
  }};

  // TODO: make sure that the dep_res_instr_ranges in below doesn't cover
  //       functional shadow MV instructions!!

  // to align live reg-maps we had to put in some register rotation operations
  // at certain points in the program
  // these instructions should be scheduled such that dependencies are
  // resolved
  std::vector<std::pair<llvm::MachineBasicBlock::iterator,
                        llvm::MachineBasicBlock::iterator>>
      dep_res_instr_ranges{};
  for (auto &MBB : *MF_) {
    llvm::MachineBasicBlock::iterator it{MBB.begin()};
    while (it != MBB.end()) {
      if (isShadowRotInstr(&*it)) {
        bool need_dep_resolution{false};
        llvm::MachineBasicBlock::iterator start{it}, end{it};
        RegSetType dst_sofar{start->getOperand(0).getReg()};

        while (1) {
          assert(it->getOperand(0).getReg() != it->getOperand(1).getReg() &&
                 "this is funny shadow rotation");
          it++;
          if (it == MBB.end()) {
            break;
          }

          if (!isShadowRotInstr(&*it)) {
            break;
          }

          if (riscv_common::setmapContains(dst_sofar,
                                           it->getOperand(1).getReg())) {
            need_dep_resolution = true;
          }
          dst_sofar.emplace(it->getOperand(0).getReg());
          end = it;
        }

        if (need_dep_resolution) {
          dep_res_instr_ranges.emplace_back(
              std::pair<llvm::MachineBasicBlock::iterator,
                        llvm::MachineBasicBlock::iterator>{start, end});
        }
      } else {
        it++;
      }
    }
  }

  auto dependencyResolved{[this](std::pair<llvm::MachineBasicBlock::iterator,
                                           llvm::MachineBasicBlock::iterator>
                                     instr_range) -> llvm::MachineInstr * {
    RegSetType dst_sofar{};
    for (auto it{instr_range.first}; it != instr_range.second; ++it) {
      if (riscv_common::setmapContains(dst_sofar, it->getOperand(1).getReg())) {
        return &*it;
      }

      if (it->getOperand(0).getReg() != P2S_.at(riscv_common::k0)) {
        dst_sofar.emplace(it->getOperand(0).getReg());
      }
    }
    return nullptr;
  }};

  for (auto &p : dep_res_instr_ranges) {
    p.second++;
    llvm::MachineBasicBlock::iterator start{p.first};
    start--;

    unsigned deadlock_counter{25};
    while (1) {
      deadlock_counter--;
      if (!deadlock_counter) {
        llvm::outs() << "\tResolving deadlock...\n";
        // assumption: we need to swap the first 2 instrs around to resolve
        // the deadlock -> dont know if this holds always!

        if (riscv_common::getRegType(p.first->getOperand(0).getReg()) ==
            riscv_common::RegType::I) {
          // using shadow of zero for swapping operation as this is anyways
          // free
          auto si{MF_->CloneMachineInstr(&*std::next(p.first))};
          si->getOperand(0).setReg(P2S_.at(riscv_common::k0));
          p.first->getParent()->insert(p.first, si);
          std::next(p.first)->getOperand(1).setReg(P2S_.at(riscv_common::k0));
          p.first = si->getIterator();
          llvm::BuildMI(*p.first->getParent(), p.second, p.first->getDebugLoc(),
                        TII_->get(llvm::RISCV::XOR))
              .addReg(P2S_.at(riscv_common::k0))
              .addReg(P2S_.at(riscv_common::k0))
              .addReg(P2S_.at(riscv_common::k0));
        } else {
          assert(0);
        }

        deadlock_counter = 25;
      }

      auto conflict_MI{dependencyResolved(p)};
      if (!conflict_MI) {
        break;
      } else {
        auto si{MF_->CloneMachineInstr(conflict_MI)};
        conflict_MI->getParent()->insertAfter(start, si);
        p.first = si->getIterator();
        conflict_MI->getParent()->erase_instr(conflict_MI);
      }
    }
  }
}
