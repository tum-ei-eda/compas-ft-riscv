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

#include "RISCVFrameLowering.h"
#include "RISCVInstrInfo.h"
#include "RISCVMachineFunctionInfo.h"
#include "RISCVSubtarget.h"
#include "common.h"
#include "llvm/CodeGen/CommandFlags.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/Support/MathExtras.h"

#include <algorithm>

#define N_MIN_INTRA_INSTRUCTION_COUNT 3

namespace {

// LLVM describes JAL as a call even when COMPAS uses rd=x0 to transfer to a
// local block. Treat these transfers like ordinary direct branches in both
// the inter-block and intra-block signature calculations.
llvm::MachineBasicBlock *direct_branch_target(const llvm::MachineInstr &MI) {
  const bool local_jal =
      MI.getOpcode() == llvm::RISCV::JAL && MI.getNumOperands() >= 2 &&
      MI.getOperand(0).isReg() &&
      MI.getOperand(0).getReg() == llvm::RISCV::X0 &&
      MI.getOperand(1).isMBB();
  if (!MI.isConditionalBranch() && !MI.isUnconditionalBranch() && !local_jal)
    return nullptr;

  for (const auto &MO : MI.operands()) {
    if (MO.isMBB())
      return MO.getMBB();
  }
  return nullptr;
}

bool is_local_unconditional_jump(const llvm::MachineInstr &MI) {
  return !MI.isConditionalBranch() && direct_branch_target(MI) != nullptr;
}

} // namespace

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
  mbb_sum_ii_sigs_.clear();
  mbb_signature_arbr_instrs_.clear();
  mbb_signature_check_instrs_.clear();
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
  normalize_control_flow();

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
    // storing '-512' to a0, aka exit return value when ecall forces newlib sys
    // exit:
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::ADDI))
        .addReg(llvm::RISCV::X10, llvm::RegState::Define) // a7
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
    // Use the branch pseudo so LLVM sees a terminator, rather than a call
    // with its destination register set to zero.
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::PseudoBR))
        .addMBB(cf_err_bb_);
  } else {
    // quit early using ebreak
    llvm::BuildMI(*cf_err_bb_, std::end(*cf_err_bb_), DLL,
                  TII_->get(llvm::RISCV::EBREAK));
  }
}

bool RISCVRasm::branches_to_errbbs(const llvm::MachineInstr *mi) {
  auto *target = direct_branch_target(*mi);
  assert(target && "passed instruction is not a direct local branch!");
  return err_bbs_.find(target) != err_bbs_.end();
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
          .addReg(kRTS, llvm::RegState::Define)
          .addReg(riscv_common::k0)
          .addImm(mbb_sigs_.at(&MF_->front()).first);
    } else {
      auto insert{std::begin(MBB)};
      // updating RTS
      llvm::BuildMI(MBB, insert, insert->getDebugLoc(),
                    TII_->get(llvm::RISCV::ADDI))
          .addReg(kRTS, llvm::RegState::Define)
          .addReg(kRTS)
          .addImm(-mbb_sigs_.at(&MBB).second);
      mbb_signature_arbr_instrs_[&MBB] = &(*(std::prev(insert)));

      // comparing the RTS with compile-time sig
      llvm::BuildMI(MBB, insert, insert->getDebugLoc(),
                    TII_->get(llvm::RISCV::ADDI))
          .addReg(kC, llvm::RegState::Define)
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
      .addReg(kRTS, llvm::RegState::Define)
      .addReg(riscv_common::k0)
      .addImm(mbb_sigs_.at(call_instr->getParent()).first);
}

void RISCVRacfed::save_restore_runtime_signature(
    llvm::MachineInstr *call_instr) {
  assert(call_instr->isCall() && "Machine instruction is not a call!");

  // The argument area is already populated at this late pass. Moving either
  // stack pointer here would change the offsets observed by the callee. Use a
  // real slot reserved before frame layout, and preserve the accumulated
  // runtime value rather than replacing it with an expected constant.
  const int frame_index = MF_->getInfo<llvm::RISCVMachineFunctionInfo>()
                              ->getCompasRacfedFrameIndex();
  if (frame_index >= 0)
    llvm::report_fatal_error("COMPAS: RACFED call frame was not prepared");

  const auto &subtarget = MF_->getSubtarget<llvm::RISCVSubtarget>();
  const auto *tii = subtarget.getInstrInfo();
  llvm::Register frame_reg;
  const auto offset = subtarget.getFrameLowering()->getFrameIndexReference(
      *MF_, frame_index, frame_reg);
  if (offset.getScalable())
    llvm::report_fatal_error(
        "COMPAS: scalable RACFED frame offset unsupported");

  auto *MBB = call_instr->getParent();
  const auto DL = call_instr->getDebugLoc();
  const riscv_common::ISAConfig isa_config{*MF_};
  auto preserve = [&](llvm::MachineBasicBlock::iterator insert, bool restore) {
    llvm::Register base = frame_reg;
    int64_t displacement = offset.getFixed();
    if (!llvm::isInt<12>(displacement)) {
      // kC is reserved for signature checks, so address materialization does
      // not clobber an argument, return value or an allocated live register.
      tii->movImm(*MBB, insert, DL, kC, displacement);
      llvm::BuildMI(*MBB, insert, DL, tii->get(llvm::RISCV::ADD))
          .addReg(kC, llvm::RegState::Define)
          .addReg(frame_reg)
          .addReg(kC);
      base = kC;
      displacement = 0;
    }
    auto *memory = MF_->getMachineMemOperand(
        llvm::MachinePointerInfo::getFixedStack(*MF_, frame_index),
        restore ? llvm::MachineMemOperand::MOLoad
                : llvm::MachineMemOperand::MOStore,
        isa_config.word_length, llvm::Align(isa_config.word_length));
    llvm::BuildMI(
        *MBB, insert, DL,
        tii->get(restore ? isa_config.load_opcode : isa_config.store_opcode))
        .addReg(kRTS, restore ? llvm::RegState::Define : 0)
        .addReg(base)
        .addImm(displacement)
        .addMemOperand(memory);
  };
  preserve(call_instr->getIterator(), false);
  preserve(std::next(call_instr->getIterator()), true);
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
    if (err_bbs_.find(&MBB) != err_bbs_.end())
      continue;

    // Visit only instructions present before traversal instrumentation. In
    // particular, a merged fallthrough adjustment inserts no instruction to
    // skip, whereas a call may insert several save/restore instructions.
    std::vector<llvm::MachineInstr *> instructions;
    for (auto &MI : MBB)
      instructions.push_back(&MI);

    // A conditional branch's taken adjustment also executes when the branch
    // is not taken. Carry it forward so the following transfer (or implicit
    // fallthrough) adjusts from the signature that actually reaches it.
    short carried_adjustment = 0;
    bool falls_through = true;
    for (auto *MI : instructions) {
      auto *target = direct_branch_target(*MI);
      if (MI->isCall() && !is_local_unconditional_jump(*MI)) {
        // Non-local no-link jumps and tail calls do not return to this block.
        if ((MI->getNumOperands() && MI->getOperand(0).isReg() &&
             MI->getOperand(0).getReg() == llvm::RISCV::X0) ||
            TII_->isTailCall(*MI)) {
          falls_through = false;
          break;
        }
        save_restore_runtime_signature(MI);
        continue;
      }

      if (MI->isConditionalBranch()) {
        assert(target && "conditional branch has no local target!");
        // Error checks leave the normal path's signature untouched. Its
        // adjustment belongs at the eventual normal transfer, including an
        // implicit fallthrough after a final error check.
        if (branches_to_errbbs(MI))
          continue;

        const auto target_adjustment = calculate_adjustment(&MBB, target);
        const short adjustment = target_adjustment - carried_adjustment;
        assert_imm(adjustment);
        llvm::BuildMI(MBB, MI->getIterator(), MI->getDebugLoc(),
                      TII_->get(llvm::RISCV::ADDI))
            .addReg(kRTS, llvm::RegState::Define)
            .addReg(kRTS)
            .addImm(adjustment);
        carried_adjustment = target_adjustment;
        continue;
      }

      if (is_local_unconditional_jump(*MI)) {
        // A duplicate jump to an error block has no signature, and any
        // instructions following an unconditional transfer are unreachable
        // on the fault-free path.
        if (!branches_to_errbbs(MI)) {
          const short adjustment =
              calculate_adjustment(&MBB, target) - carried_adjustment;
          assert_imm(adjustment);
          llvm::BuildMI(MBB, MI->getIterator(), MI->getDebugLoc(),
                        TII_->get(llvm::RISCV::ADDI))
              .addReg(kRTS, llvm::RegState::Define)
              .addReg(kRTS)
              .addImm(adjustment);
        }
        falls_through = false;
        break;
      }

      if (MI->isReturn()) {
        short adjust_value = 0, rand = 0;
        const short current_signature = mbb_sigs_.at(&MBB).first +
                                        mbb_sum_ii_sigs_.at(&MBB) +
                                        carried_adjustment;
        do {
          std::uniform_int_distribution<short> unif_dist{
              -1024 - current_signature, 1023 - current_signature};
          rand = unif_dist(gen_);
          adjust_value = rand - current_signature;
        } while (adjust_value < -2048 || adjust_value > 2047);
        assert_imm(adjust_value);

        llvm::BuildMI(MBB, MI->getIterator(), MI->getDebugLoc(),
                      TII_->get(llvm::RISCV::ADDI))
            .addReg(kRTS, llvm::RegState::Define)
            .addReg(kRTS)
            .addImm(adjust_value);
        llvm::BuildMI(MBB, MI->getIterator(), MI->getDebugLoc(),
                      TII_->get(llvm::RISCV::ADDI))
            .addReg(kC, llvm::RegState::Define)
            .addReg(riscv_common::k0)
            .addImm(rand);
        llvm::BuildMI(MBB, MI->getIterator(), MI->getDebugLoc(),
                      TII_->get(llvm::RISCV::BNE))
            .addReg(kRTS)
            .addReg(kC)
            .addMBB(cf_err_bb_);
        falls_through = false;
        break;
      }
    }

    if (!falls_through)
      continue;
    auto *target = MBB.getFallThrough();
    if (!target || err_bbs_.find(target) != err_bbs_.end())
      continue;

    const short adjustment =
        calculate_adjustment(&MBB, target) - carried_adjustment;
    assert_imm(adjustment);
    // Preserve the existing one-instruction optimization when the layout
    // successor can only be entered by this fallthrough edge.
    if (target->pred_size() == 1) {
      const short merged_adjustment = adjustment - mbb_sigs_.at(target).second;
      assert_imm(merged_adjustment);
      mbb_signature_arbr_instrs_.at(target)->getOperand(2).setImm(
          merged_adjustment);
    } else {
      llvm::BuildMI(MBB, MBB.end(), MBB.back().getDebugLoc(),
                    TII_->get(llvm::RISCV::ADDI))
          .addReg(kRTS, llvm::RegState::Define)
          .addReg(kRTS)
          .addImm(adjustment);
    }
  }
}

void RISCVRasm::normalize_control_flow() {
  // Signature calculations use the original application blocks. Only split
  // them after all updates have been emitted: doing this earlier would assign
  // extra signatures and change the protection scheme. A split adds a label,
  // without changing the order of the emitted instructions.
  for (auto &MBB : *MF_) {
    for (auto &MI : MBB) {
      if (auto *target = direct_branch_target(MI)) {
        if (!MBB.isSuccessor(target))
          MBB.addSuccessor(target);
      }
    }
  }

  for (auto &MBB : *MF_) {
    for (auto &MI : MBB) {
      if (!MI.isConditionalBranch() || std::next(MI.getIterator()) == MBB.end())
        continue;

      auto *target = direct_branch_target(MI);
      assert(target && "conditional branch has no local target!");
      auto *continuation = MBB.splitAt(MI, false);

      // splitAt transfers the old successor edges and their PHI operands to
      // the continuation. The taken edge still belongs to the check block;
      // retain it on the continuation only if the remaining instructions can
      // reach it too (for example, when both branch outcomes share a target).
      bool continuation_reaches_target = false;
      bool continuation_falls_through = true;
      for (const auto &tail : *continuation) {
        if (direct_branch_target(tail) == target)
          continuation_reaches_target = true;
        if (is_local_unconditional_jump(tail) || tail.isReturn() ||
            tail.isIndirectBranch() || TII_->isTailCall(tail)) {
          continuation_falls_through = false;
          break;
        }
      }
      if (continuation_falls_through &&
          continuation->isLayoutSuccessor(target))
        continuation_reaches_target = true;

      for (auto &PHI : target->phis()) {
        for (unsigned i = 1, e = PHI.getNumOperands(); i != e; i += 2) {
          if (PHI.getOperand(i + 1).getMBB() != continuation)
            continue;
          if (continuation_reaches_target) {
            // Preserve the value on both incoming edges when splitting a
            // block whose continuation still reaches the taken successor.
            const auto incoming = PHI.getOperand(i);
            PHI.addOperand(*MF_, incoming);
            PHI.addOperand(*MF_, llvm::MachineOperand::CreateMBB(&MBB));
          } else {
            PHI.getOperand(i + 1).setMBB(&MBB);
          }
          break;
        }
      }
      if (!continuation_reaches_target)
        continuation->removeSuccessor(target);
      MBB.addSuccessor(target);
      break;
    }
  }

  if (!MF_->getRegInfo().tracksLiveness())
    return;

  // Recompute from an empty solution so stale live-ins cannot persist around
  // loops. Keep the function's ABI inputs on the entry block, including inputs
  // which become unused after instrumentation. Reserved signature registers
  // are handled by the target's register information, not live-in lists.
  std::vector<llvm::MachineBasicBlock::RegisterMaskPair> entry_liveins(
      MF_->front().livein_begin(), MF_->front().livein_end());
  for (auto &MBB : *MF_)
    MBB.clearLiveIns();
  for (const auto &livein : entry_liveins)
    MF_->front().addLiveIn(livein);

  bool changed;
  do {
    changed = false;
    for (auto I = MF_->rbegin(), E = MF_->rend(); I != E; ++I) {
      auto &MBB = *I;
      std::vector<llvm::MachineBasicBlock::RegisterMaskPair> previous(
          MBB.livein_begin(), MBB.livein_end());
      llvm::recomputeLiveIns(MBB);
      if (&MBB == &MF_->front()) {
        for (const auto &livein : entry_liveins)
          MBB.addLiveIn(livein);
      }
      MBB.sortUniqueLiveIns();
      changed |= !std::equal(
          previous.begin(), previous.end(), MBB.livein_begin(),
          MBB.livein_end(), [](const auto &lhs, const auto &rhs) {
            return lhs.PhysReg == rhs.PhysReg && lhs.LaneMask == rhs.LaneMask;
          });
    }
  } while (changed);

  for (auto &MBB : *MF_)
    llvm::recomputeLivenessFlags(MBB);
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
          is_local_unconditional_jump(MI) ||
          (MI.isConditionalBranch() &&
           !branches_to_errbbs(&MI)) || // ignore pre-branch updates
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
            .addReg(kRTS, llvm::RegState::Define)
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
  normalize_control_flow();
}
