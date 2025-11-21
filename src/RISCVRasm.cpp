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

#include "RISCVRasm.h"

#include "RISCVSubtarget.h"
#include "common.h"
#include "llvm/CodeGen/CommandFlags.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/LivePhysRegs.h"

#define N_MIN_INTRA_INSTRUCTION_COUNT 3

llvm::FunctionPass *llvm::createRISCVRasm() { return new RISCVRasm(); }

llvm::FunctionPass *llvm::createRISCVRacfed() { return new RISCVRacfed(); }

RISCVRasm::RISCVRasm() : RISCVDmr{} {}

RISCVRacfed::RISCVRacfed() : RISCVRasm{} {}

bool RISCVRasm::runOnMachineFunction(llvm::MachineFunction &MF) {
  MF_ = &MF;
  fname_ = std::string{MF_->getName()};
  TII_ = MF_->getSubtarget().getInstrInfo();

  if (!riscv_common::inCSString(llvm::cl::enable_rasm,
                                std::string{MF_->getName()})) {
    return false;
  }

  llvm::outs() << "Running RASM pass on " << MF_->getName() << "\n";

  init();
  harden();

  return true;
}

void RISCVRasm::init() {
  mbb_sigs_.clear();
  cf_err_bb_ = nullptr;
  err_bbs_.clear();
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
}

// RASM hardening scheme
void RISCVRasm::harden() {

  //////////////////////////////////////////////////////////////////////////////
  // Step 1: Assign compile time signatues and random arbitration value
  // "subRanPrevVal" to each basic block of the function.
  generate_signatures();

  //////////////////////////////////////////////////////////////////////////////
  // Step 2: Insert runtime signature arbitration and signature check in the
  // beginning of each basic block except for machine function entry basic
  // block where we just assign the runtime signature with the block's compile
  // time signature
  generate_signature_checks();

  //////////////////////////////////////////////////////////////////////////////
  // Step 3: just sets all intra block to 0 for debugging
  generate_intrablock_signature_updates();

  //////////////////////////////////////////////////////////////////////////////
  // Step 4: Calculate traversal adjustment values for non-trivial
  // instructions
  generate_traversal_adjustments();

  /*
    for (auto &MBB : *MF_) {
      // there could be err-BBs from other passes
      // the convention is if a BB keeps jumping to itself then this is also
      // an error-BB
      if (MBB.succ_size() == 1 && &MBB == *MBB.succ_begin()) {
        continue;
      }

      // special processing for some individual instrs:
      // we generate new instrs in the following loop which should not be
      // considered in future iterations. For this we use following flag
      bool ignore_this_mi{false};
      // in case we have a conditional and unconditional branch both in MBB then
      // we dont need to update signature before the final unconditional branch
      // we use the following flag to keep track of this
      bool ignore_jump{false};
      for (auto &MI : MBB) {
        if (ignore_this_mi) {
          ignore_this_mi = false;
          continue;
        }

      // in case we call another function then RTS would be corrupted
      // as we use t0 RISCV register for RTS, hence
      // preserving them across function call using the stack
      if (MI.isCall()) {
        // jumps are also considered as calls so filtering them out
        if (MI.getOperand(0).isReg() &&
            MI.getOperand(0).getReg() == llvm::RISCV::X0) {
          continue;
        }
        // filtering out tail calls
        if (TII_->isTailCall(MI)) {
          continue;
        }

        llvm::MachineBasicBlock::iterator insert{MI.getIterator()};
        insert++;

        // NOTE: stack would be used to pass args if they exceed arg regs hence
        //       we shouldn't use stack for CFC signatures

        if (MI.getOpcode() == llvm::RISCV::PseudoCALLIndirect ||
            !(riscv_common::inCSString(llvm::cl::enable_nzdc,
                                       std::string{MF_->getName()}) &&
              riscv_common::setmapContains(knownLibcalls2Duplicable_,
                                           getCalledFuncName(&MI)))) {
          // if we are in DMR func and we are going to libcall via this MI call
          // then no need to stack RTS explicitly as this is already done in DMR
          // else: we stack RTS as below

          riscv_common::saveRegs({kRTS}, &MBB, MI.getIterator());
          riscv_common::loadRegs({kRTS}, &MBB, insert);

          if (riscv_common::inCSString(llvm::cl::enable_nzdc,
                                       std::string{MF_->getName()})) {
            llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                          TII_->get(llvm::RISCV::ADDI))
                .addReg(P2S_.at(riscv_common::kSP))
                .addReg(P2S_.at(riscv_common::kSP))
                .addImm(-4);
            llvm::BuildMI(MBB, insert, MI.getDebugLoc(),
                          TII_->get(llvm::RISCV::ADDI))
                .addReg(P2S_.at(riscv_common::kSP))
                .addReg(P2S_.at(riscv_common::kSP))
                .addImm(4);
          }
        }

        // alternatively: for G, we simply move the expected value back into G
        //        llvm::BuildMI(MBB, insert, MI.getDebugLoc(),
        //                      TII_->get(llvm::RISCV::ADDI))
        //            .addReg(kRTS)
        //            .addReg(riscv_common::k0)
        //            .addImm(mbb_sigs_[&MBB].first);

        continue;
      }

        // RASM processing around the branch terminators
        if (MI.isConditionalBranch()) {
          assert(MI.getOperand(2).isMBB());
          auto SBB{MI.getOperand(2).getMBB()};
          // filtering error-handler jumps
          if (err_bbs_.find(SBB) != err_bbs_.end()) {
            // this could be the loadback check at the last
            // if thats the case then have to update RASM update
            if (SBB != cf_err_bb_ && &MBB.back() == &MI) {
              for (auto &op : MI.operands()) {
                if (op.isReg() && P2S_.find(op.getReg()) != P2S_.end()) {
                  assert(MBB.succ_size() == 1);
                  auto SBB{*std::begin(MBB.successors())};
                  auto adjust_value = mbb_sigs_.at(SBB).first +
                                      mbb_sigs_.at(SBB).second -
                                      mbb_sigs_.at(&MBB).first;
                  assert_imm(adjust_value);
                  llvm::BuildMI(MBB, std::end(MBB), MI.getDebugLoc(),
                                TII_->get(llvm::RISCV::ADDI))
                      .addReg(kRTS)
                      .addReg(kRTS)
                      .addImm(adjust_value);
                  ignore_this_mi = true;

                  break;
                }
              }
            }

            continue;
          }
          auto taken_adjust_value = mbb_sigs_.at(SBB).first +
                                    mbb_sigs_.at(SBB).second -
                                    mbb_sigs_.at(&MBB).first;
          assert_imm(taken_adjust_value);
          llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                        TII_->get(llvm::RISCV::ADDI))
              .addReg(kRTS)
              .addReg(kRTS)
              .addImm(taken_adjust_value);

          llvm::MachineBasicBlock *other_SBB{nullptr};
          for (auto SBBx : MBB.successors()) {
            if (SBBx != SBB) {
              other_SBB = SBBx;
              break;
            }
          }
          auto nottaken_adjust_value =
              -(mbb_sigs_.at(SBB).first + mbb_sigs_.at(SBB).second -
                mbb_sigs_.at(&MBB).first) +
              (mbb_sigs_.at(other_SBB).first + mbb_sigs_.at(other_SBB).second -
               mbb_sigs_.at(&MBB).first);
          assert_imm(nottaken_adjust_value);
          llvm::BuildMI(MBB, std::next(MI.getIterator()), MI.getDebugLoc(),
                        TII_->get(llvm::RISCV::ADDI))
              .addReg(kRTS)
              .addReg(kRTS)
              .addImm(nottaken_adjust_value);
          ignore_this_mi = true;
          if (MBB.back().isUnconditionalBranch()) {
            ignore_jump = true;
          } else {
            if (MBB.back().isCall() && MBB.back().getOperand(1).isMBB() &&
                err_bbs_.find(MBB.back().getOperand(1).getMBB()) !=
                    err_bbs_.end()) {
              ignore_jump = true;
            }
          }

          continue;
        }
        if (MI.isUnconditionalBranch()) {
          if (!ignore_jump) {
            assert(MI.getOperand(0).isMBB());
            auto SBB{MI.getOperand(0).getMBB()};
            auto adjust_value = mbb_sigs_.at(SBB).first +
                                mbb_sigs_.at(SBB).second -
                                mbb_sigs_.at(&MBB).first;
            assert_imm(adjust_value);
            llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                          TII_->get(llvm::RISCV::ADDI))
                .addReg(kRTS)
                .addReg(kRTS)
                .addImm(adjust_value);
          }

          continue;
        }

        // RASM processing before the return instruction
        if (MI.isReturn()) {
          short rand{unif_dist_(gen_)};
          llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                        TII_->get(llvm::RISCV::ADDI))
              .addReg(kRTS)
              .addReg(kRTS)
              .addImm(rand - mbb_sigs_.at(&MBB).first);
          llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                        TII_->get(llvm::RISCV::ADDI))
              .addReg(kC)
              .addReg(riscv_common::k0)
              .addImm(rand);
          llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                        TII_->get(llvm::RISCV::BNE))
              .addReg(kRTS)
              .addReg(kC)
              .addMBB(cf_err_bb_);
          break;
        }

        // in case this MBB has no branch/ret terminator then we have to do RASM
        // update at end of MBB
        if (&MI == &MBB.back() && MBB.succ_size()) {
          assert(MBB.succ_size() == 1);
          auto SBB{*std::begin(MBB.successors())};

          auto adjust_value = mbb_sigs_.at(SBB).first + mbb_sigs_.at(SBB).second
    - mbb_sigs_.at(&MBB).first; assert_imm(adjust_value); llvm::BuildMI(MBB,
    std::end(MBB), MI.getDebugLoc(), TII_->get(llvm::RISCV::ADDI)) .addReg(kRTS)
              .addReg(kRTS)
              .addImm(adjust_value);
          break;
        }
      }
    } */
}

// for now we just write '1' to special memory address (0xfff8) to tell the
// simulator that this FI is covered in a separate error-BB. Further we
// stay in this loop to avoid further functional execution
void RISCVRasm::insertErrorBB() {
  cf_err_bb_ = MF_->CreateMachineBasicBlock();
  MF_->push_back(cf_err_bb_);

  auto DLL{MF_->front().front().getDebugLoc()};

  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0) {
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

  } else if (config_.eds == riscv_common::ErrorDetectionStrategy::ED3) {
    // storing '93' to a7, aka SYS_exit code ECALL code:
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(llvm::RISCV::X17) // a7
        .addReg(llvm::RISCV::X0)  // zero
        .addImm(93);
    // storing '-512' to a0, aka exit return value when ecall forces newlib sys
    // exit:
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(llvm::RISCV::X10) // a7
        .addReg(llvm::RISCV::X0)  // zero
        .addImm(-256);
    // invoke 'ecall'
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::ECALL));
  }

  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED3) {

    // to encode the error-BB in order to make it a label so as to be able to
    // jump to it from anywhere in asm
    cf_err_bb_->addSuccessor(cf_err_bb_);

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

bool RISCVRasm::branches_to_errbbs(const llvm::MachineInstr *mi) {
  assert(mi->isConditionalBranch() &&
         "passed Machine Instruction is not a conditional branch!");
  assert(mi->getOperand(2).isMBB() && "passed Machine Instruction's branch "
                                      "target is not a Machine Basic Block!");
  auto branch_taken_bb{mi->getOperand(2).getMBB()};
  // filtering error-handler jumps
  if (err_bbs_.find(branch_taken_bb) != err_bbs_.end()) {
    return true;
  }
  return false;
}

void RISCVRasm::generate_signatures() {
  //////////////////////////////////////////////////////////////////////////////
  // Step 1: Assign compile time signatues and random arbitration value
  // "subRanPrevVal" to each basic block of the function.
  llvm::outs() << "RACFED S1: Assigning compile time sigs to each MBB of "
               << MF_->getName() << "\n";

  // assigning compile time sigs to each MBB
  std::set<short> sigs_sofar{}, sum_sofar{};
  for (auto &MBB : *MF_) {
    // there could be err-BBs from other passes
    // the convention is if a BB keeps jumping to itself then this is also
    // an error-BB
    if (MBB.succ_size() == 1 && &MBB == *MBB.succ_begin()) {
      err_bbs_.emplace(&MBB);
      continue;
    }

    short y = 0;
    while (1) {
      std::uniform_int_distribution<short> unif_dist{-512, 511};
      auto x{unif_dist(gen_)};
      if (sigs_sofar.find(x) == std::end(sigs_sofar)) {
        sigs_sofar.emplace(x);
        while (1) { // make sure that y, aka, subRanPrevVal is not zero
          // because it is used for a signature arbirtation
          // instruction makiung it a NOP if 0
          y = unif_dist(gen_);
          if (sum_sofar.find(x + y) == std::end(sum_sofar) && y != 0) {
            sum_sofar.emplace(x + y);
            mbb_sigs_[&MBB] = {x, y};
            break;
          }
        }
        break;
      }
    }
  }
}

void RISCVRasm::generate_signature_checks() {
  //////////////////////////////////////////////////////////////////////////////
  // Insert runtime signature arbitration and signature check in the
  // beginning of each basic block except for machine function entry basic
  // block where we just assign the runtime signature with the block's compile
  // time signature
  llvm::outs() << "Insert runtime signature arbitration and "
                  "signature check handling of traversals on "
               << MF_->getName() << "\n";
  for (auto &MBB : *MF_) {
    if (MBB.succ_size() == 1 && &MBB == *MBB.succ_begin()) {
      // filter out error handler basic blocks, here blocks that jump to
      // itself
      continue;
    }

    if (MBB.pred_empty()) {
      // for entryBB we dont check RTS
      llvm::BuildMI(MF_->front(), std::begin(MF_->front()),
                    std::begin(MF_->front())->getDebugLoc(),
                    TII_->get(llvm::RISCV::ADDI))
          .addReg(kRTS)
          .addReg(riscv_common::k0)
          .addImm(mbb_sigs_.at(&MF_->front()).first);
    } else {
      auto insert{std::begin(MBB)};
      // updating RTS
      llvm::BuildMI(MBB, insert, insert->getDebugLoc(),
                    TII_->get(llvm::RISCV::ADDI))
          .addReg(kRTS)
          .addReg(kRTS)
          .addImm(-mbb_sigs_.at(&MBB).second);
      mbb_signature_arbr_instrs_[&MBB] = &(*(std::prev(insert)));

      // comparing the RTS with compile-time sig
      llvm::BuildMI(MBB, insert, insert->getDebugLoc(),
                    TII_->get(llvm::RISCV::ADDI))
          .addReg(kC)
          .addReg(riscv_common::k0)
          .addImm(mbb_sigs_.at(&MBB).first);

      mbb_signature_check_instrs_[&MBB] = &(*(std::prev(insert)));
      llvm::BuildMI(MBB, insert, insert->getDebugLoc(),
                    TII_->get(llvm::RISCV::BNE))
          .addReg(kRTS)
          .addReg(kC)
          .addMBB(cf_err_bb_);
    }
  }
}

short RISCVRasm::calculate_adjustment(
    const llvm::MachineBasicBlock *source_bb,
    const llvm::MachineBasicBlock *target_bb) {
  short ret = mbb_sigs_.at(target_bb).first + mbb_sigs_.at(target_bb).second -
              mbb_sigs_.at(source_bb).first;

  assert_imm(ret);
  return ret;
}

void RISCVRasm::save_restore_runtime_signature(llvm::MachineInstr *call_instr) {
  // jumps are also considered as calls so filtering them out

  assert(call_instr->isCall() && "Machine instruction is not a call!");

  llvm::MachineBasicBlock::iterator insert{call_instr->getIterator()};
  insert++;

  // NOTE: stack would be used to pass args if they exceed arg regs hence
  //       we shouldn't use stack for CFC signatures
  // for G, we simply move the expected value back into G
  llvm::BuildMI(*(call_instr->getParent()), insert, call_instr->getDebugLoc(),
                TII_->get(llvm::RISCV::ADDI))
      .addReg(kRTS)
      .addReg(riscv_common::k0)
      .addImm(mbb_sigs_.at(call_instr->getParent()).first);
}

void RISCVRacfed::save_restore_runtime_signature(
    llvm::MachineInstr *call_instr) {
  // We must use stack to store the runtime signature.
  // Restoring the runtime signature from compile time values here would
  // make all runtime signature updates up to this call useless.
  // something else. The alternative to check signatures before a
  // returning call with the expected gradual, then calling+destroying
  // run time signature, after return restoring run time signature with
  // expected gradual after call would make the restore-move signature
  // instruction a possible entry for an intra-block and inter-block
  // (onto instr.) error. With the stack solution we have at least the
  // safety that the full stack push-call-pop must be intra-block
  // faulted. This is just another argument for implementing some form
  // of far-away gradually carrying signature
  // TODO: make sure that this does not interfere with function calls
  // that use stack to pass arguments. To solve this we must make sure
  // that we first push the signature before arguments such that the
  // callee on restoring parameters from stack in own scope does not pop
  // runtime instead of parameters.

  assert(call_instr->isCall() && "Machine instruction is not a call!");

  llvm::MachineBasicBlock::iterator insert{call_instr->getIterator()};
  if (!is_func_dmr(fname_)) {
    riscv_common::saveRegs({kRTS}, call_instr->getParent(), insert);
    insert++;
    riscv_common::loadRegs({kRTS}, call_instr->getParent(), insert);
  } else {
    llvm::outs() << "> DMR compliant runtime signature stacking for mi["
                 << call_instr << "]" << *call_instr << "\n";
    // in case the calling function is also a DMR we need to make sure
    // that both stack and shadow stack are used. Currently we do not
    // support DMR+RACFED calling DMR without RACFED or RASM
    riscv_common::saveRegs({kRTS}, call_instr->getParent(), insert,
                           P2S_.at(riscv_common::kSP));
    insert++;
    riscv_common::loadRegs({kRTS}, call_instr->getParent(), insert,
                           P2S_.at(riscv_common::kSP));
  }
}

short RISCVRacfed::calculate_adjustment(
    const llvm::MachineBasicBlock *source_bb,
    const llvm::MachineBasicBlock *target_bb) {
  short ret = mbb_sigs_.at(target_bb).first + mbb_sigs_.at(target_bb).second -
              (mbb_sigs_.at(source_bb).first + mbb_sum_ii_sigs_.at(source_bb));

  assert_imm(ret);
  return ret;
}

void RISCVRasm::generate_traversal_adjustments() {
  llvm::outs() << "RACFED S3: Calculate traversal adjustment values for "
                  "non-trivial instructions on "
               << MF_->getName() << "\n";
  for (auto &MBB : *MF_) {
    // there could be err-BBs from other passes
    // the convention is if a BB keeps jumping to itself then this is also
    // an error-BB
    llvm::outs() << "======================================\n"
                 << "MBB[" << &MBB << "]: " << MBB << ":\n";
    if (MBB.succ_size() == 1 && &MBB == *MBB.succ_begin()) {
      llvm::outs() << "> skipping MBB because assumed error handler BB\n";
      continue;
    }

    // special processing for some individual instrs:
    // we generate new instrs in the following loop which should not be
    // considered in future iterations. For this we use following flag
    bool ignore_this_mi{false};
    // in case we have a conditional and unconditional branch both in MBB then
    // we dont need to update signature before the final unconditional branch
    // we use the following flag to keep track of this
    bool ignore_jump{false};
    for (auto &MI : MBB) {
      if (ignore_this_mi) {
        ignore_this_mi = false;
        continue;
      }

      // in case we call another function then RTS would be corrupted
      // as we use t0 RISCV register for RTS, hence
      // preserving them across function call using the stack
      if (MI.isCall()) {
        llvm::outs() << "> call instruction found MI[" << &MI << "]: " << MI
                     << "\n";
        // jumps are also considered as calls so filtering them out
        if (MI.getOperand(0).isReg() &&
            MI.getOperand(0).getReg() == llvm::RISCV::X0) {
          continue;
        }
        // filtering out tail calls
        if (TII_->isTailCall(MI)) {
          continue;
        }

        save_restore_runtime_signature(&MI);

        continue;
      }

      // RASM processing around the branch terminators
      if (MI.isConditionalBranch()) {

        llvm::outs() << "> conditional branch instruction found MI[" << &MI
                     << "]: " << MI << "\n";

        assert(MI.getOperand(2).isMBB());
        auto SBB{MI.getOperand(2).getMBB()};
        // filtering error-handler jumps
        // if (err_bbs_.find(SBB) != err_bbs_.end()) {
        if (branches_to_errbbs(&MI)) {
          // this could be the loadback check at the last
          // if thats the case then have to update RASM update

          llvm::outs() << ">> branches to error BB\n";
          if (SBB != cf_err_bb_ &&
              &MBB.back() == &MI) { // todo what is happening here?!
            llvm::outs() << ">>> branches to error BB in last MI\n";
            for (auto &op : MI.operands()) {
              if (op.isReg() && P2S_.find(op.getReg()) != P2S_.end()) {
                assert(MBB.succ_size() == 1);
                auto SBB{*std::begin(MBB.successors())};

                auto adjust_value = calculate_adjustment(&MBB, SBB);

                llvm::outs()
                    << "Running RACFED adjust values of " << MF_->getName()
                    << ":\n"
                    << "\n  * X_t: " << mbb_sigs_.at(SBB).first
                    << "\n  * Y_t: " << mbb_sigs_.at(SBB).second
                    << "\n  * K_t: " << adjust_value
                    << "\n  * X_BB: " << mbb_sigs_.at(&MBB).first
                    << "\n  * sumII_n-2: " << mbb_sum_ii_sigs_.at(&MBB) << "\n";

                llvm::BuildMI(MBB, std::end(MBB), MI.getDebugLoc(),
                              TII_->get(llvm::RISCV::ADDI))
                    .addReg(kRTS)
                    .addReg(kRTS)
                    .addImm(adjust_value);
                ignore_this_mi = true;

                break;
              }
            }
            if (!ignore_this_mi) { // this might be a duplicated fall through
                                   // that needs adjustment
              llvm::MachineBasicBlock *other_SBB{
                  nullptr}; // aka not-taken, aka fallthrough?
              for (auto SBBx : MBB.successors()) {
                if (SBBx != SBB) {
                  other_SBB = SBBx;
                  break;
                }
              }
              auto adjust_value = calculate_adjustment(&MBB, other_SBB);

              llvm::outs() << "Running RACFED adjust values of "
                           << MF_->getName() << ":\n"
                           << "\n  * X_ft: " << mbb_sigs_.at(other_SBB).first
                           << "\n  * Y_ft: " << mbb_sigs_.at(other_SBB).second
                           << "\n  * K_ft: " << adjust_value
                           << "\n  * X_BB: " << mbb_sigs_.at(&MBB).first
                           << "\n  * sumII_n-2: " << mbb_sum_ii_sigs_.at(&MBB)
                           << "\n";

              if ((MBB.getFallThrough() == other_SBB) &&
                  (other_SBB->pred_size() == 1)) {
                llvm::outs()
                    << "other_SBB[" << other_SBB
                    << "] pred_size:" << other_SBB->pred_size() << "\n";
                llvm::outs()
                    << "MBB.getFallThrough[" << MBB.getFallThrough() << "]\n";
                // there is only one legal entry into other_SBB which is from
                // not-taken conditional of the predecessor, aka the
                // fallthrough. Now we can merge the adjustment update into
                // the arbitration with subRanPrevVal of other_SBB and save
                // one instruction
                auto merge_nottaken_adjust =
                    adjust_value - mbb_sigs_.at(other_SBB).second;
                // other_SBB->begin()->getOperand(2).setImm(merge_nottaken_adjust);
                mbb_signature_arbr_instrs_.at(other_SBB)->getOperand(2).setImm(
                    merge_nottaken_adjust);
                //}
              } else {
                // there are multiple legal entries into other_SBB, such that
                // the fallthrough adjustment has to be performed in the scope
                // of the predecessor basic block
                llvm::BuildMI(MBB, std::next(MI.getIterator()),
                              MI.getDebugLoc(), TII_->get(llvm::RISCV::ADDI))
                    .addReg(kRTS)
                    .addReg(kRTS)
                    .addImm(adjust_value);
              }
              break;
            }
          }
          continue;
        }

        // we do not have a II update for the branch instruction and its
        // predecessor instruction yet we encode it into the control flow
        // adjustment update of RASM like so taken adjust_value: K_t= (X_t
        // +Y_t)- (X_BB + sum{i=1->N-2}{µ_i}) , where X_t: compile time
        // signature of branch taken successor BB Y_t: subRanPrevVal
        // substraction check value of branch taken successor BB X_BB: compile
        // time signature of current BB N: Number of original instructions
        // (including branch instruction) in BB µ_i: random signature update
        // value of each original instruction
        llvm::outs() << "taken bb[" << SBB << "]" << *SBB << "\n";

        auto taken_adjust_value = calculate_adjustment(&MBB, SBB);

        llvm::outs() << "Running RACFED adjust values of " << MF_->getName()
                     << ":\n"
                     << "\n  * X_t: " << mbb_sigs_.at(SBB).first
                     << "\n  * Y_t: " << mbb_sigs_.at(SBB).second
                     << "\n  * K_t: " << taken_adjust_value
                     << "\n  * X_BB: " << mbb_sigs_.at(&MBB).first
                     << "\n  * sumII_n-2: " << mbb_sum_ii_sigs_.at(&MBB)
                     << "\n";

        llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                      TII_->get(llvm::RISCV::ADDI))
            .addReg(kRTS)
            .addReg(kRTS)
            .addImm(taken_adjust_value);

        llvm::MachineBasicBlock *other_SBB{
            nullptr}; // aka not-taken, aka fallthrough?
        for (auto SBBx : MBB.successors()) {
          if (SBBx != SBB) {
            other_SBB = SBBx;
            break;
          }
        }

        if (other_SBB != nullptr) {
          // we do not have a II update for the branch instruction and its
          // predecessor instruction yet we encode it into the control flow
          // adjustment update of RASM like so: because of RISC-V being
          // non-predicated we have to add the taken adjustment value into
          // account since the runtime signature was updated with it before
          // the branch instruction was executed not taken adjust_value:
          // * K_nt = (X_nt +Y_nt) - K_t - (X_BB + sum{i=1->N-2}{µ_i}) , where
          // * X_nt: compile time signature of branch not taken successor BB,
          // * Y_nt: subRanPrevVal substraction check value of branch not
          // taken successor BB,
          // * K_t: taken adjustment value,
          // * X_BB: compile time signature of current BB,
          // * N: Number of original instructions (including branch
          // instruction) in BB,
          // * µ_i: random signature update value of each original instruction
          llvm::outs() << "not taken bb[" << other_SBB << "]" << *other_SBB
                       << "\n";
          auto nottaken_adjust_value =
              calculate_adjustment(&MBB, other_SBB) - taken_adjust_value;

          llvm::outs() << "Running RACFED adjust values of " << MF_->getName()
                       << ":\n"
                       << "\n  * X_t: " << mbb_sigs_.at(SBB).first
                       << "\n  * Y_t: " << mbb_sigs_.at(SBB).second
                       << "\n  * K_t: " << taken_adjust_value
                       << "\n  * K_nt: " << nottaken_adjust_value
                       << "\n  * X_nt: " << mbb_sigs_.at(other_SBB).first
                       << "\n  * Y_nt: " << mbb_sigs_.at(other_SBB).second
                       << "\n  * X_BB: " << mbb_sigs_.at(&MBB).first
                       << "\n  * sumII_n-2: " << mbb_sum_ii_sigs_.at(&MBB)
                       << "\n";

          if ((MBB.getFallThrough() == other_SBB) &&
              (other_SBB->pred_size() == 1)) {
            llvm::outs() << "other_SBB[" << other_SBB
                         << "] pred_size:" << other_SBB->pred_size() << "\n";
            llvm::outs() << "MBB.getFallThrough[" << MBB.getFallThrough()
                         << "]\n";
            // there is only one legal entry into other_SBB which is from
            // not-taken conditional of the predecessor, aka the fallthrough.
            // Now we can merge the adjustment update into the arbitration
            // with subRanPrevVal of other_SBB and save  one instruction
            auto merge_nottaken_adjust =
                nottaken_adjust_value - mbb_sigs_.at(other_SBB).second;
            // other_SBB->begin()->getOperand(2).setImm(merge_nottaken_adjust);
            mbb_signature_arbr_instrs_.at(other_SBB)->getOperand(2).setImm(
                merge_nottaken_adjust);
            //}
          } else {
            // there are multiple legal entries into other_SBB, such that the
            // fallthrough adjustment has to be performed in the scope of the
            // predecessor basic block
            llvm::BuildMI(MBB, std::next(MI.getIterator()), MI.getDebugLoc(),
                          TII_->get(llvm::RISCV::ADDI))
                .addReg(kRTS)
                .addReg(kRTS)
                .addImm(nottaken_adjust_value);
          }
        }

        ignore_this_mi = true;
        if (MBB.back().isUnconditionalBranch()) {
          ignore_jump = true;
        } else {
          if (MBB.back().isCall() && MBB.back().getOperand(1).isMBB() &&
              err_bbs_.find(MBB.back().getOperand(1).getMBB()) !=
                  err_bbs_.end()) {
            ignore_jump = true;
          }
        }
        continue;
      }

      if (MI.isUnconditionalBranch()) {
        llvm::outs() << "> unconditional branch MI[" << &MI << "]: " << MI
                     << "\n";
        if (!ignore_jump) {
          assert(MI.getOperand(0).isMBB());
          auto SBB{MI.getOperand(0).getMBB()};

          auto adjust_value = calculate_adjustment(&MBB, SBB);

          llvm::outs() << "Running RACFED adjust values of " << MF_->getName()
                       << ":\n"
                       << "\n  * X_u: " << mbb_sigs_.at(SBB).first
                       << "\n  * Y_u: " << mbb_sigs_.at(SBB).second
                       << "\n  * K_u: " << adjust_value
                       << "\n  * X_BB: " << mbb_sigs_.at(&MBB).first
                       << "\n  * sumII_n-2: " << mbb_sum_ii_sigs_.at(&MBB)
                       << "\n";

          llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                        TII_->get(llvm::RISCV::ADDI))
              .addReg(kRTS)
              .addReg(kRTS)
              .addImm(adjust_value);
        }

        continue;
      }

      // RASM processing before the return instruction
      if (MI.isReturn()) {

        llvm::outs() << "> return instruction found MI[" << &MI << "]: " << MI
                     << "\n";
        short adjust_value = 0, rand = 0;

        do {
          std::uniform_int_distribution<short> unif_dist{
              -1024 - (mbb_sigs_.at(&MBB).first + mbb_sum_ii_sigs_.at(&MBB)),
              1023 - (mbb_sigs_.at(&MBB).first + mbb_sum_ii_sigs_.at(&MBB))};
          rand = unif_dist(gen_);
          adjust_value =
              rand - (mbb_sigs_.at(&MBB).first + mbb_sum_ii_sigs_.at(&MBB));
        } while (adjust_value < -2048 || adjust_value > 2047);

        llvm::outs() << "Running RACFED adjust values of " << MF_->getName()
                     << ":\n"
                     << "\n  * rand: " << rand << "\n  * adj: " << adjust_value
                     << "\n";

        assert_imm(adjust_value);

        llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                      TII_->get(llvm::RISCV::ADDI))
            .addReg(kRTS)
            .addReg(kRTS)
            .addImm(adjust_value);
        llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                      TII_->get(llvm::RISCV::ADDI))
            .addReg(kC)
            .addReg(riscv_common::k0)
            .addImm(rand);
        llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                      TII_->get(llvm::RISCV::BNE))
            .addReg(kRTS)
            .addReg(kC)
            .addMBB(cf_err_bb_);
        break;
      }

      // in case this MBB has no branch/ret terminator then we have to do RASM
      // update at end of MBB aka replace immediate value of last incremental
      // instruction update with arbitration subRanPrevVal
      if (&MI == &MBB.back() && MBB.succ_size()) {
        llvm::outs() << "> non return/conditional branch termination found MI["
                     << &MI << "]: " << MI << "\n";
        assert(MBB.succ_size() == 1);
        auto SBB{*std::begin(MBB.successors())};

        auto adjust_value = calculate_adjustment(&MBB, SBB);

        llvm::BuildMI(MBB, std::end(MBB), MI.getDebugLoc(),
                      TII_->get(llvm::RISCV::ADDI))
            .addReg(kRTS)
            .addReg(kRTS)
            .addImm(adjust_value);
        break;
      }
    }
  }
}

// ------------------------------------------- RACFED --------------------------

bool RISCVRacfed::runOnMachineFunction(llvm::MachineFunction &MF) {
  MF_ = &MF;
  fname_ = std::string{MF_->getName()};
  TII_ = MF_->getSubtarget().getInstrInfo();

  if (!riscv_common::inCSString(llvm::cl::enable_racfed,
                                std::string{MF_->getName()})) {
    return false;
  }

  llvm::outs() << "Running RACFED pass on " << MF_->getName() << "\n";

  init();

  llvm::outs() << "Running RACFED harden() on " << MF_->getName() << "\n";

  harden();

  return true;
}

void RISCVRacfed::init() {

  RISCVRasm::init();

  mbb_sum_ii_sigs_.clear();
  mbb_signature_arbr_instrs_.clear();
  mbb_signature_check_instrs_.clear();
  mi_random_value_.clear();
}

void RISCVRasm::generate_intrablock_signature_updates() {
  for (auto &MBB : *MF_) {
    if (MBB.succ_size() == 1 && &MBB == *MBB.succ_begin()) {
      continue;
    }
    mbb_sum_ii_sigs_[&MBB] = 0; // force to 0 -> RASM has no intra block updates
  }
}

void RISCVRacfed::generate_intrablock_signature_updates() {

  llvm::outs() << "RACFED S2: Intra-block runtime signature updates on "
               << MF_->getName() << "\n";

  for (auto &MBB : *MF_) {
    // there could be err-BBs from other passes
    // the convention is if a BB keeps jumping to itself then this is also
    // an error-BB
    if (MBB.succ_size() == 1 && &MBB == *MBB.succ_begin()) {
      continue;
    }
    llvm::outs() << "> mbb[" << &MBB << "] {X=" << mbb_sigs_.at(&MBB).first
                 << ", Y=" << mbb_sigs_.at(&MBB).second << "}: " << MBB << "\n";
    std::vector<llvm::MachineInstr *> orig_instrs;

    short sum_ii_rvs = 0;
    for (auto &MI : MBB) {
      llvm::outs() << "> mi[" << &MI << "]: " << MI
                   << "back?: " << (&MI == &(MBB.back())) << "mback["
                   << &(MBB.instr_back()) << "]" << MBB.instr_back() << "\n";

      if ((MI.getFlag(llvm::MachineInstr::FrameSetup) &&
           MI.isCFIInstruction()) || // ignore virtual frame calc instructions
          (MI.isBranch() && !MI.isConditionalBranch()) ||
          (MI.isConditionalBranch() &&
           !branches_to_errbbs(&MI)) || // ignore pre-branch updates
          (MI.isUnconditionalBranch() &&
           branches_to_errbbs(
               &MI)) || // ignore unconditional branch duplicates to error BB
                        // (pre duplicate will not have an instr increment
                        // after execution)
          (MI.isCall() && MI.getOperand(1).isMBB() &&
           err_bbs_.find(MI.getOperand(1).getMBB()) !=
               err_bbs_.end()) || // uncond. branch could also be a call
          //((&MI == &(MBB.instr_back()) ) && MI.isConditionalBranch() &&
          // branches_to_errbbs(
          //     &MI)) || // ignore DMR not taken/fallthrough duplicate
          MI.isReturn() // returns have a special random arbitration such that
                        // we do not need to perform a random update for the
                        // instruction before return
      ) {
        llvm::outs() << "\>> not considered ui: [" << &MI << "]" << MI << "\n";
        continue;
      }

      short rv = 0;
      if (MI.getIterator() != MBB.begin()) {
        // first instruction, we will either the initial
        // signature function entry or the consecutive checks
        // here
        short cs = mbb_sigs_.at(&MBB).first +
                   sum_ii_rvs; // current signature, we need to
        // predict to avoid overflows

        std::uniform_int_distribution<short> unif_dist{-1024 - cs, 1023 - cs};
        while (rv == 0) {
          rv = unif_dist(gen_);
        }

        llvm::outs() << "> gen rv [" << rv << "] for  "
                     << "mi: [" << &MI << "]" << MI << "\n"
                     << "cs was " << cs << " now is " << cs + rv << "\n";

        assert_imm(cs + rv);
      }

      orig_instrs.push_back(&MI);
      llvm::outs() << ">> ui: [" << &MI << "]" << MI << "\n";

      mi_random_value_[&MBB][&MI] = rv;

      sum_ii_rvs += rv;
    }

    mbb_sum_ii_sigs_[&MBB] = 0; // force to 0

    if (orig_instrs.size() >= N_MIN_INTRA_INSTRUCTION_COUNT) {
      // There is no point in intra block protection for basic blocks with
      // only 2 or 1 instruction since all intra block errors are also legal
      // control flow
      for (auto &mi : orig_instrs) {
        auto rv = mi_random_value_.at(&MBB).at(mi);
        if (rv == 0)
          continue;

        mbb_sum_ii_sigs_.at(&MBB) += rv;

        llvm::outs() << ">adding µi update [" << rv << "] for  "
                     << "mi: [" << mi << "]" << *mi << "\n";
        llvm::MachineBasicBlock::iterator insert{mi->getIterator()};

        llvm::BuildMI(MBB, insert, mi->getDebugLoc(),
                      TII_->get(llvm::RISCV::ADDI))
            .addReg(kRTS)
            .addReg(kRTS)
            .addImm(rv);
      }
    }
  }
}

// RACFED hardening scheme
void RISCVRacfed::harden() {
  //////////////////////////////////////////////////////////////////////////////
  // Step 1: Assign compile time signatues and random arbitration value
  // "subRanPrevVal" to each basic block of the function.
  generate_signatures();

  //////////////////////////////////////////////////////////////////////////////
  // Step 2: Now add for all original and trivial instruction the intra block
  // signature update with random value. Trivial means that the instructions
  // are neither branches nor returns. Only BBs with more than 2 trivial
  // instructions may be protected against intra block control flow errors
  generate_intrablock_signature_updates();
  //////////////////////////////////////////////////////////////////////////////
  // Step 3: Insert runtime signature arbitration and signature check in the
  // beginning of each basic block except for machine function entry basic
  // block where we just assign the runtime signature with the block's compile
  // time signature
  generate_signature_checks();

  //////////////////////////////////////////////////////////////////////////////
  // Step 4: Calculate traversal adjustment values for non-trivial
  // instructions
  generate_traversal_adjustments();
}
