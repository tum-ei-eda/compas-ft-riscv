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

#include <algorithm>
#include <random>

#include "RISCVFrameLowering.h"
#include "RISCVInstrInfo.h"
#include "RISCVMachineFunctionInfo.h"
#include "RISCVSubtarget.h"
#include "common.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/PseudoSourceValue.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDwarf.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"

#include "MCTargetDesc/RISCVBaseInfo.h"

#define SWITCH_VOLATILE
// #define DBG

namespace {

bool isCompilerBarrier(const llvm::MachineInstr &MI) {
  if (MI.getOpcode() != llvm::TargetOpcode::INLINEASM ||
      MI.getNumOperands() < llvm::InlineAsm::MIOp_FirstOperand ||
      !MI.getOperand(llvm::InlineAsm::MIOp_AsmString).isSymbol() ||
      MI.getOperand(llvm::InlineAsm::MIOp_AsmString).getSymbolName()[0] ||
      !MI.getOperand(llvm::InlineAsm::MIOp_ExtraInfo).isImm() ||
      (MI.getOperand(llvm::InlineAsm::MIOp_ExtraInfo).getImm() &
       llvm::InlineAsm::Extra_IsAlignStack))
    return false;
  // An empty compiler barrier may carry source-location metadata, but no
  // register, memory-constraint or control-flow operands that need a shadow.
  for (unsigned index = llvm::InlineAsm::MIOp_FirstOperand;
       index != MI.getNumOperands(); ++index)
    if (!MI.getOperand(index).isMetadata())
      return false;
  return true;
}

// Post-RA constant addition using only the supplied physical destination.
// Preserve independent primary/shadow computations without virtual registers
// or a borrowed live register, including split large-frame adjustments.
llvm::MachineInstr *
addOffset(llvm::MachineBasicBlock &MBB,
          llvm::MachineBasicBlock::iterator insert,
          const llvm::TargetInstrInfo &TII, llvm::Register destination,
          llvm::Register base, int64_t offset, llvm::DebugLoc DL = {},
          llvm::MachineInstr::MIFlag flag = llvm::MachineInstr::NoFlags) {
  llvm::MachineInstr *first = nullptr;
  do {
    const int64_t maximum =
        destination == riscv_common::kSP || destination == llvm::RISCV::X9
            ? 2032
            : 2047;
    const int64_t step = std::max<int64_t>(-2048, std::min(maximum, offset));
    auto instruction =
        llvm::BuildMI(MBB, insert, DL, TII.get(llvm::RISCV::ADDI), destination)
            .addReg(base)
            .addImm(step);
    if (flag != llvm::MachineInstr::NoFlags)
      instruction.setMIFlag(flag);
    if (!first)
      first = instruction.getInstr();
    base = destination;
    offset -= step;
  } while (offset);
  return first;
}

bool isFullWidthFPRegister(llvm::Register reg,
                           const llvm::RISCVSubtarget &subtarget) {
  // Copy and preserve each physical FPR once, using its enabled FLEN rather
  // than XLEN or the width of one of its overlapping views.
  if (subtarget.hasStdExtD())
    return riscv_common::getRegType(reg) == riscv_common::RegType::FD;
  return subtarget.hasStdExtF() &&
         riscv_common::getRegType(reg) == riscv_common::RegType::FS;
}

bool mayReceiveSignatureState(llvm::Register primary) {
  // A separately compiled UC3 callee cannot know whether its caller owns
  // t0/t4 as CFP state. This caller-clobbered pair carries no ABI argument;
  // keep it out of the incoming full-bank equality contract whenever CFP
  // is enabled. Ordinary DMR data checks inside the callee still apply.
  return primary == llvm::RISCV::X5 &&
         (!llvm::cl::enable_cfcss.empty() || !llvm::cl::enable_rasm.empty() ||
          !llvm::cl::enable_racfed.empty());
}

// A shadow address can name a separate allocation. Its primary IR value,
// frame object, alias scopes and value-range facts do not describe that bank.
// Retain access semantics, including atomics, but give the access conservative
// unknown provenance in the original address space. Valid EDDI bank allocation
// preserves the effective access alignment; retain getAlign(), not the original
// base alignment whose offset is being discarded here.
void useIndependentShadowMemory(llvm::MachineFunction &MF,
                                llvm::MachineInstr &MI) {
  llvm::SmallVector<llvm::MachineMemOperand *, 2> memory;
  for (const auto *old : MI.memoperands()) {
    const auto flags = static_cast<llvm::MachineMemOperand::Flags>(
        old->getFlags() & ~(llvm::MachineMemOperand::MODereferenceable |
                            llvm::MachineMemOperand::MOInvariant));
    memory.push_back(MF.getMachineMemOperand(
        llvm::MachinePointerInfo(old->getAddrSpace()), flags,
        old->getMemoryType(), old->getAlign(), llvm::AAMDNodes(), nullptr,
        old->getSyncScopeID(), old->getSuccessOrdering(),
        old->getFailureOrdering()));
  }
  MI.setMemRefs(MF, memory);
}

bool incomingStackArgumentOffset(const llvm::MachineInstr &MI,
                                 int64_t &offset) {
  if (!MI.mayLoad())
    return false;
  const auto &frame = MI.getParent()->getParent()->getFrameInfo();
  bool found = false;
  for (const auto *memory : MI.memoperands()) {
    if (!memory->isLoad())
      continue;
    const auto *slot =
        llvm::dyn_cast_or_null<llvm::FixedStackPseudoSourceValue>(
            memory->getPseudoValue());
    if (!slot || !frame.isFixedObjectIndex(slot->getFrameIndex()) ||
        frame.getObjectOffset(slot->getFrameIndex()) < 0)
      continue;
    const int64_t argument_offset =
        frame.getObjectOffset(slot->getFrameIndex()) + memory->getOffset();
    if (found && offset != argument_offset)
      llvm::report_fatal_error(
          "COMPAS: ambiguous incoming stack argument load");
    offset = argument_offset;
    found = true;
  }
  if (found && (MI.getNumExplicitOperands() != 3 || !MI.getOperand(0).isReg() ||
                !MI.getOperand(0).isDef() || !MI.getOperand(1).isReg() ||
                !MI.getOperand(2).isImm() || MI.mayStore()))
    llvm::report_fatal_error(
        "COMPAS: unsupported incoming stack argument load");
  return found;
}

// Called after duplication so these address helpers are not duplicated again.
void rewriteIncomingStackArguments(
    llvm::MachineFunction &MF,
    const std::map<llvm::MachineInstr *, llvm::MachineInstr *> &loads,
    int64_t allocated_prefix, int64_t shadow_frame_offset,
    llvm::MachineInstr &primary_sp, llvm::MachineInstr &shadow_sp,
    llvm::Register shadow_zero, llvm::Register shadow_stack,
    llvm::Register shadow_frame) {
  if (loads.empty())
    return;

  const auto &subtarget = MF.getSubtarget<llvm::RISCVSubtarget>();
  const auto *tii = subtarget.getInstrInfo();
  const auto *info = MF.getInfo<llvm::RISCVMachineFunctionInfo>();
  const auto &frame = MF.getFrameInfo();
  const int snapshot = info->getCompasIncomingShadowSPFrameIndex();
  if (snapshot >= 0)
    llvm::report_fatal_error(
        "COMPAS: incoming shadow SP slot was not prepared");
  llvm::Register frame_reg;
  const auto snapshot_offset =
      subtarget.getFrameLowering()->getFrameIndexReference(MF, snapshot,
                                                           frame_reg);
  if (snapshot_offset.getScalable() || frame_reg != riscv_common::kFP)
    llvm::report_fatal_error(
        "COMPAS: incoming stack arguments require stable FP");
  const riscv_common::ISAConfig isa_config{MF};
  auto snapshot_memory = [&](bool load) {
    return MF.getMachineMemOperand(
        llvm::MachinePointerInfo::getFixedStack(MF, snapshot),
        load ? llvm::MachineMemOperand::MOLoad
             : llvm::MachineMemOperand::MOStore,
        isa_config.word_length, llvm::Align(isa_config.word_length));
  };
  auto reset_scratch = [&](llvm::MachineInstr &MI) {
    llvm::BuildMI(*MI.getParent(), std::next(MI.getIterator()),
                  MI.getDebugLoc(), tii->get(llvm::RISCV::ADDI), shadow_zero)
        .addReg(riscv_common::k0)
        .addImm(0);
  };
  auto address = [&](llvm::MachineInstr &MI, llvm::Register base,
                     int64_t offset) {
    if (llvm::isInt<12>(offset))
      return std::make_pair(base, offset);
    // LLVM13's movImm can allocate virtual intermediates, which is too late
    // after RA. Keep one physical scratch and leave an encodable load offset.
    do {
      const int64_t step = offset > 0 ? 2047 : -2048;
      llvm::BuildMI(*MI.getParent(), MI.getIterator(), MI.getDebugLoc(),
                    tii->get(llvm::RISCV::ADDI), shadow_zero)
          .addReg(base)
          .addImm(step);
      base = shadow_zero;
      offset -= step;
    } while (!llvm::isInt<12>(offset));
    return std::make_pair(shadow_zero, offset);
  };

  // At entry, P and S identify the caller's two outgoing argument banks.
  // EDDI changes SP to P-F-D and shadow SP to P-F, with frame separation D.
  // Save S before the live shadow SP starts addressing this frame.
  const int64_t store_offset = allocated_prefix + frame.getObjectOffset(snapshot);
  if (store_offset < 0 || !llvm::isInt<12>(store_offset))
    llvm::report_fatal_error(
        "COMPAS: unsupported incoming shadow SP slot offset");
  llvm::BuildMI(*primary_sp.getParent(), shadow_sp.getIterator(),
                primary_sp.getDebugLoc(), tii->get(isa_config.store_opcode))
      .addReg(shadow_stack)
      .addReg(riscv_common::kSP)
      .addImm(store_offset)
      .addMemOperand(snapshot_memory(false))
      .setMIFlag(llvm::MachineInstr::FrameSetup);

  for (const auto &pair : loads) {
    auto &primary = *pair.first;
    auto &shadow = *pair.second;
    int64_t argument_offset = 0;
    if (!incomingStackArgumentOffset(primary, argument_offset))
      llvm::report_fatal_error(
          "COMPAS: incoming stack argument lost its object");

    // The expanded prologue sets primary FP to P-D-VarArgsSaveSize.
    // Rebuild from the formal object's entry-SP offset, regardless of the
    // SP/FP/materialized base selected by LLVM before EDDI doubled the frame.
    const auto primary_address = address(
        primary, riscv_common::kFP,
        shadow_frame_offset + info->getVarArgsSaveSize() + argument_offset);
    primary.getOperand(1).setReg(primary_address.first);
    primary.getOperand(1).setIsKill(false);
    primary.getOperand(1).setIsUndef(false);
    primary.getOperand(2).setImm(primary_address.second);
    if (primary_address.first == shadow_zero)
      reset_scratch(primary);

    // In CGS the primary epilogue can restore FP before this shadow load.
    // Shadow FP is still live here and is D above the primary frame base.
    const auto saved_address = address(
        shadow, shadow_frame, snapshot_offset.getFixed() - shadow_frame_offset);
    llvm::BuildMI(*shadow.getParent(), shadow.getIterator(),
                  shadow.getDebugLoc(), tii->get(isa_config.load_opcode),
                  shadow_zero)
        .addReg(saved_address.first)
        .addImm(saved_address.second)
        .addMemOperand(snapshot_memory(true));
    const auto shadow_address = address(shadow, shadow_zero, argument_offset);
    shadow.getOperand(1).setReg(shadow_address.first);
    shadow.getOperand(1).setIsKill(false);
    shadow.getOperand(1).setIsUndef(false);
    shadow.getOperand(2).setImm(shadow_address.second);
    // S may name the protected caller's separate bank. Do not retain the
    // original MMO's assertion that this load aliases the primary argument.
    useIndependentShadowMemory(MF, shadow);
    reset_scratch(shadow);
  }
}

bool savesIncomingFramePointer(const llvm::MachineInstr &MI,
                               unsigned store_opcode) {
  if (MI.getOpcode() != store_opcode ||
      MI.getOperand(0).getReg() != riscv_common::kFP)
    return false;

  // CSI stores are not consistently marked FrameSetup. Match the actual
  // spill object instead, so ordinary stores of s0 retain their value checks.
  const auto &frame = MI.getParent()->getParent()->getFrameInfo();
  for (const auto &saved : frame.getCalleeSavedInfo()) {
    if (saved.getReg() != riscv_common::kFP)
      continue;
    for (const auto *memory : MI.memoperands()) {
      const auto *slot =
          llvm::dyn_cast_or_null<llvm::FixedStackPseudoSourceValue>(
              memory->getPseudoValue());
      if (slot && slot->getFrameIndex() == saved.getFrameIdx() &&
          memory->getOffset() == 0)
        return true;
    }
  }
  return false;
}

bool reachesBlock(llvm::MachineBasicBlock &MBB,
                  const llvm::MachineBasicBlock *target) {
  for (const auto &MI : MBB) {
    const bool no_link_jump = MI.getOpcode() == llvm::RISCV::JAL &&
                              MI.getNumOperands() >= 2 &&
                              MI.getOperand(0).isReg() &&
                              MI.getOperand(0).getReg() == llvm::RISCV::X0;
    if (MI.isConditionalBranch() || MI.isUnconditionalBranch() ||
        no_link_jump) {
      for (const auto &operand : MI.operands())
        if (operand.isMBB() && operand.getMBB() == target)
          return true;
      if (!MI.isConditionalBranch())
        // Later trap jumps are unreachable on this path.
        return false;
    } else if (MI.isIndirectBranch() ||
               MI.getOpcode() == llvm::TargetOpcode::INLINEASM_BR) {
      return true; // Keep an existing edge when its target cannot be resolved.
    } else if (MI.isReturn() || (MI.isBarrier() && !MI.isCall())) {
      return false;
    }
  }
  return MBB.getNextNode() == target;
}

llvm::MachineBasicBlock *splitConditionalBranch(llvm::MachineInstr &branch) {
  auto *source = branch.getParent();
  auto *taken = branch.getOperand(2).getMBB();
  auto *tail = source->splitAt(branch);
  assert(tail != source &&
         "Conditional branch has no fallthrough instructions");

  // splitAt transfers all successors to the tail, including the edge taken
  // by the conditional left in source. Retain that edge in the tail only if
  // its remaining instructions can actually reach it. False edges otherwise
  // make CFCSS generate conflicting predecessor adjustments.
  if (tail->isSuccessor(taken) && !reachesBlock(*tail, taken))
    tail->removeSuccessor(taken, true);
  if (!source->isSuccessor(taken))
    source->addSuccessor(taken);
  return tail;
}

} // namespace

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
  auto add_errorBB_once = [&]() {
    if (err_bb_ == nullptr) {
      if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0 ||
          config_.eds == riscv_common::ErrorDetectionStrategy::ED1 ||
          config_.eds == riscv_common::ErrorDetectionStrategy::ED3) {
        // insert an error-BB in MF_
        insertErrorBB();
      } else {
        assert(0 && "TODO");
      }
    }
  };
  // if this function is not to be transformed then return early
  init(); // FIXME: init() will insert errorBBs for all functions (non-DMR, DMR,
          // and DMR calling non-DMRs alike)

  auto ignore = ignoreMF();
  if (!ignore) {
    if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_))
      for (const auto &MBB : *MF_)
        for (const auto &MI : MBB)
          if (MI.isInlineAsm() && !isCompilerBarrier(MI)) {
            // Opaque templates cannot be duplicated by renaming MachineInstr
            // operands: implicit SP uses, memory effects and branches would
            // retain their original meaning. Diagnose before analyzing their
            // nonstandard operands as ordinary loads/stores or instructions.
            MI.emitError("COMPAS: inline assembly is unsupported in "
                         "EDDI-protected function '" + fname_ + "'");
            return false;
          }
    if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_) &&
        MF_->getInfo<llvm::RISCVMachineFunctionInfo>()
            ->hasCompasUnsupportedPointerArgs())
      llvm::report_fatal_error(
          "COMPAS: unsupported EDDI pointer-argument calling convention");
    add_errorBB_once();
    analyze_function();
    calc_framesize();
    analyzeStackArguments();
    duplicateInstructions();
    protectCalls();
    protectStores();
    protectLoads();
    protectBranches();
    if (llvm::cl::enable_repair) {
      repair();
    }
    protectGP();
  } else {
    analyze_function(); // FIXME
    if (calls_dmr_user_func_) {
      add_errorBB_once();
    }
    calc_framesize();
  }

  if (config_.sh != SelectiveHardening::SH0 && !user_calls_.empty()) {
    llvm::outs() << "d0: Updating function call according to selective "
                    "hardening technique\n";
    // only if we are in a non-DMRed function we now need to force an ErrorBlock
    // insertion
    updateSelectiveCalls();
  }

  if (!ignore && MF_->getFrameInfo().hasVarSizedObjects() &&
      riscv_common::inCSString(llvm::cl::enable_eddi, fname_))
    preserveDynamicStackAcrossCalls();

  return !ignore;
}

void RISCVDmr::finalizeCallingConvention() {
  const bool caller_dmr = is_func_dmr(fname_);
  const bool caller_eddi =
      riscv_common::inCSString(llvm::cl::enable_eddi, fname_);
  const auto caller_state = riscv_common::signatureRegisters(*MF_);
  const auto &subtarget = MF_->getSubtarget<llvm::RISCVSubtarget>();
  auto callName = [](const llvm::MachineInstr &MI) {
    for (const auto &operand : MI.operands()) {
      if (operand.isGlobal())
        return operand.getGlobal()->getName().str();
      if (operand.isSymbol())
        return std::string(operand.getSymbolName());
    }
    return std::string();
  };
  bool selective_wrapper = false;
  if (!caller_dmr)
    for (const auto *call : user_calls_)
      selective_wrapper |= is_func_dmr(callName(*call));
  if (!caller_dmr && !selective_wrapper)
    return;

  auto addRegister = [&](llvm::MachineInstr &MI, llvm::Register reg,
                         bool define) {
    for (const auto &operand : MI.operands())
      if (operand.isReg() && operand.getReg() == reg &&
          operand.isDef() == define)
        return;
    MI.addOperand(*MF_, llvm::MachineOperand::CreateReg(reg, define, true));
  };
  auto integerRegister = [](llvm::Register reg) {
    return riscv_common::getRegType(reg) == riscv_common::RegType::I;
  };
  auto invariant = [](llvm::Register reg) {
    return reg == riscv_common::k0 || reg == riscv_common::kSP ||
           reg == riscv_common::kGP || reg == riscv_common::kTP;
  };
  auto declareInput = [&](llvm::Register reg) {
    if (!MRI_->isReserved(reg) && !MF_->front().isLiveIn(reg))
      MF_->front().addLiveIn(reg);
  };

  // A non-EDDI boundary compares the complete GPR monitor bank. Its values
  // include otherwise unspecified architectural results of ordinary calls.
  // Declare those observations at the calls, rather than treating a value
  // clobbered earlier in the function as an additional entry live-in.
  const bool observes_bank = selective_wrapper || (caller_dmr && !caller_eddi);
  for (auto &MBB : *MF_) {
    for (auto &MI : MBB) {
      if (MI.isReturn() && !MI.isCall()) {
        std::vector<llvm::Register> results;
        for (const auto &operand : MI.operands())
          if (operand.isReg() && operand.isUse() &&
              P2S_.count(operand.getReg()))
            results.push_back(operand.getReg());
        addRegister(MI, riscv_common::kRA, false);
        if (caller_dmr) {
          for (const auto reg : results)
            addRegister(MI, P2S_.at(reg), false);
          for (const auto &pair : P2S_) {
            if (!integerRegister(pair.first))
              continue;
            if (llvm::is_contained(caller_state, pair.first) ||
                llvm::is_contained(caller_state, pair.second))
              continue;
            if (invariant(pair.first) || pair.first == riscv_common::kFP ||
                pair.first == riscv_common::kRA || !caller_eddi) {
              addRegister(MI, pair.first, false);
              addRegister(MI, pair.second, false);
              if (!caller_eddi)
                declareInput(pair.first);
            }
          }
        } else {
          // Selective-call helpers restore the ordinary caller's preserved
          // bank even where it was pristine before late instrumentation.
          for (const auto *reg = TRI_->getCalleeSavedRegs(MF_); *reg; ++reg)
            addRegister(MI, *reg, false);
        }
        continue;
      }
      if (!MI.isCall() ||
          (MI.getOpcode() == llvm::RISCV::JAL && MI.getNumOperands() &&
           MI.getOperand(0).isReg() &&
           MI.getOperand(0).getReg() == riscv_common::k0))
        continue;

      const auto callee = callName(MI);
      // Indirect calls have no runtime convention adapter. Their targets must
      // implement the caller's shadow convention, but the machine instruction
      // cannot identify whether a target instead uses the ordinary ABI. Model
      // the possible effects of both without promising extra preservation.
      const bool unknown_target = callee.empty() && caller_dmr;
      const bool callee_dmr = unknown_target ||
                              (!callee.empty() && is_func_dmr(callee));
      const bool callee_eddi =
          callee_dmr &&
          (unknown_target
               ? caller_eddi
               : riscv_common::inCSString(llvm::cl::enable_eddi, callee));
      const bool bank_boundary = callee_dmr && !callee_eddi;
      const auto arguments = getArgRegs(&MI);
      const auto results = getRetRegs(&MI);
      RegSetType uses, definitions;
      for (auto &operand : MI.operands()) {
        if (!operand.isRegMask())
          continue;
        const auto *original = operand.getRegMask();
        if (observes_bank)
          for (const auto &pair : P2S_)
            if ((integerRegister(pair.first) ||
                 (selective_wrapper &&
                  isFullWidthFPRegister(pair.first, subtarget))) &&
                !invariant(pair.first) &&
                llvm::MachineOperand::clobbersPhysReg(original, pair.first))
              definitions.insert(pair.first);
        if (!callee_dmr)
          continue;

        auto *mask = MF_->allocateRegMask();
        std::copy_n(original, (TRI_->getNumRegs() + 31) / 32, mask);
        for (const auto &pair : P2S_) {
          bool preserved =
              !llvm::MachineOperand::clobbersPhysReg(original, pair.first);
          if (integerRegister(pair.first) && invariant(pair.first))
            preserved = pair.first != riscv_common::kSP || !callee_eddi;
          if (unknown_target)
            preserved &= !llvm::MachineOperand::clobbersPhysReg(original,
                                                               pair.second);
          const auto bit = uint32_t(1) << (pair.second % 32);
          if (preserved)
            mask[pair.second / 32] |= bit;
          else
            mask[pair.second / 32] &= ~bit;
          if (integerRegister(pair.first) &&
              (invariant(pair.first) || bank_boundary) &&
              pair.first != riscv_common::kRA &&
              !mayReceiveSignatureState(pair.first)) {
            uses.insert(pair.first);
            uses.insert(pair.second);
          }
          if (bank_boundary && integerRegister(pair.first) && !preserved) {
            definitions.insert(pair.first);
            definitions.insert(pair.second);
          }
          // Later instrumentation can observe a shadow value even where an
          // ordinary target may have clobbered it. Describe that architectural
          // output, rather than preserving it in the mask or inventing an
          // entry live-in. Its replicated value still requires a compatible
          // protected target at runtime.
          if (unknown_target && !preserved &&
              (integerRegister(pair.first) ||
               isFullWidthFPRegister(pair.first, subtarget)))
            definitions.insert(pair.second);
        }
        operand.setRegMask(mask);
      }
      if (callee_dmr) {
        for (const auto reg : arguments)
          if (P2S_.count(reg))
            uses.insert(P2S_.at(reg));
        for (const auto reg : results)
          if (P2S_.count(reg))
            definitions.insert(P2S_.at(reg));
        if (!TII_->isTailCall(MI)) {
          // The callee copies the newly linked RA at entry, rather than
          // consuming the caller's old shadow RA.
          definitions.insert(P2S_.at(riscv_common::kRA));
          if (callee_eddi)
            definitions.insert(P2S_.at(riscv_common::kSP));
        }
      }
      for (const auto reg : uses)
        addRegister(MI, reg, false);
      for (const auto reg : definitions)
        addRegister(MI, reg, true);
    }
  }
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
  isa_config_ = riscv_common::ISAConfig(*MF_);
  config_.eds = riscv_common::ErrorDetectionStrategy::ED3; // TODO: should be
                                                           // exposed to CLI
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
    // setting eddi configs
    config_.pss = ProtectStrategyStore::S2;
    config_.psl = ProtectStrategyLoad::L2;
    config_.psuc = ProtectStrategyUserCall::UC1;
    config_.psb = ProtectStrategyBranch::B1;

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
  frame_address_stores_.clear();
  shadow_pcrel_symbols_.clear();
  stack_address_call_args_.clear();
  pointer_delta_updates_.clear();
  pointer_delta_entry_.clear();
  dynamic_sp_origins_.clear();
  use_shadow_for_stack_ops_ =
      !riscv_common::inCSString(llvm::cl::enable_eddi, fname_);
  frame_size_ = 0;
  shadow_frame_offset_ = 0;

#ifdef DBG
  llvm::outs() << "COMPAS_DBG: init() done\n";
#endif
}
void RISCVDmr::analyze_function() {
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
      if (isCompilerBarrier(MI))
        continue;
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
        if (!is_func_dmr(called_func_name) &&
            riscv_common::setmapContains(knownLibcalls2Duplicable_,
                                         called_func_name)) {
          lib_calls_.emplace(&MI);
          llvm::outs() << "\tNOTE: Considering " << called_func_name
                       << " as a lib-func call\n";
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

  for (auto MI : user_calls_) {
    auto callee_func_name{getCalledFuncName(MI)};
    if (is_func_dmr(callee_func_name)) {
      calls_dmr_user_func_ = true;
    } else {
      calls_nondmr_user_func_ = true;
    }
  }

#ifdef DBG
  llvm::outs() << "COMPAS_DBG: analyze_function() done\n";
#endif
}

void RISCVDmr::calc_framesize() {
  if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_))
    frame_size_ = MF_->getFrameInfo().getStackSize();
  else
    for (auto &MI : *entry_bb_) {
      if (MI.getFlag(llvm::MachineInstr::FrameSetup) &&
          MI.getOpcode() == llvm::RISCV::ADDI && MI.getNumOperands() >= 3 &&
          MI.getOperand(0).isReg() && MI.getOperand(0).isDef() &&
          MI.getOperand(0).getReg() == riscv_common::kSP &&
          MI.getOperand(1).isReg() &&
          MI.getOperand(1).getReg() == riscv_common::kSP &&
          MI.getOperand(2).isImm() && MI.getOperand(2).getImm() < 0) {
        frame_size_ = std::abs(MI.getOperand(2).getImm());
      }
    }
  shadow_frame_offset_ = frame_size_;
  if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_) &&
      MF_->getSubtarget<llvm::RISCVSubtarget>()
          .getRegisterInfo()
          ->hasStackRealignment(*MF_)) {
    const auto &frame = MF_->getFrameInfo();
    const uint64_t alignment = frame.getMaxAlign().value();
    // Aligning SP can move a frame down by A-1 bytes, while CSI and fixed
    // objects remain relative to the pre-alignment SP/FP. Leave a full guard
    // area so shadow locals cannot overlap primary CSI/fixed storage. D must
    // also be divisible by A to preserve the separation after both ANDIs.
    const uint64_t separation = llvm::alignTo(
        static_cast<uint64_t>(frame_size_) + alignment - 1, alignment);
    if (MF_->getInfo<llvm::RISCVMachineFunctionInfo>()->useSaveRestoreLibCalls(
            *MF_))
      llvm::report_fatal_error(
          "COMPAS: realigned EDDI save/restore libcalls are unsupported");
    shadow_frame_offset_ = separation;
  }

#ifdef DBG
  llvm::outs() << "COMPAS_DBG: calc_framesize() done\n";
#endif
}

void RISCVDmr::analyzeStackArguments() {
  if (config_.psuc != ProtectStrategyUserCall::UC1 ||
      !riscv_common::inCSString(llvm::cl::enable_eddi, fname_))
    return;

  // Analyze originals before inserting shadow code or call-preservation stores.
  // A runtime origin follows the value's register/private spill, independently
  // of its primary and shadow addresses. Each reaching definition supplies
  // the proven expectation; joins never measure the pair being checked.
  enum class Relation { Equal, FrameAddress, Unsupported };
  struct Value {
    Relation relation;
    PointerOrigin origin;
    uint64_t bits;
    // Separate address ownership from its delta's storage location. A VLA
    // and a call area use runtime deltas but still belong to this frame;
    // inherited/global pointer merges do not acquire that ownership.
    bool current_frame{false};

    bool operator==(const Value &other) const {
      return relation == other.relation && origin == other.origin &&
             bits == other.bits && current_frame == other.current_frame;
    }
    bool operator!=(const Value &other) const { return !(*this == other); }
  };
  using State = std::map<unsigned, Value>;
  const unsigned register_count = TRI_->getNumRegs();
  const unsigned width = isa_config_.word_length * 8;
  const uint64_t all_bits = width == 64 ? ~uint64_t{0} : 0xffffffffULL;
  const uint64_t separation = shadow_frame_offset_;
  const uint64_t unchanged_low_bits = (separation & -separation) - 1;
  const Value unknown{Relation::Unsupported, {}, all_bits};
  const bool runtime_origins = riscv_common::usesPointerProvenance(*MF_);
  const bool dynamic_frame = MF_->getFrameInfo().hasVarSizedObjects();
  const bool base_pointer = riscv_common::usesEddiBasePointer(*MF_);
  auto runtimeOrigin = [&](unsigned key) {
    const unsigned slot = key < register_count ? key - llvm::RISCV::X0
                                               : 32 + key - register_count;
    return PointerOrigin{PointerOrigin::Kind::Runtime, slot};
  };
  State entry;
  for (const auto &pair : P2S_)
    if (riscv_common::getRegType(pair.first) == riscv_common::RegType::I)
      entry.emplace(pair.first, Value{Relation::Equal, {}, all_bits});
  entry.at(riscv_common::k0).bits = 0;
  entry.at(riscv_common::kSP).relation = Relation::FrameAddress;
  entry.at(riscv_common::kSP).current_frame = true;
  for (const auto reg : MF_->getInfo<llvm::RISCVMachineFunctionInfo>()
                            ->getCompasIncomingPointerRegs())
    entry.at(reg) = {
        Relation::FrameAddress, {PointerOrigin::Kind::Incoming, reg}, all_bits};

  // Private register-allocation spill objects cannot alias source-program
  // pointers. Track exact XLEN stores/reloads; partial writes invalidate the
  // object. Escaped allocas and arbitrary memory loads retain no such promise.
  struct Spill {
    unsigned key;
    bool full_word;
  };
  std::map<int, unsigned> spill_keys;
  std::map<const llvm::MachineInstr *, Spill> spills;
  const auto &frame = MF_->getFrameInfo();
  for (const auto &MBB : *MF_)
    for (const auto &MI : MBB) {
      if (MI.memoperands().size() != 1 || (!MI.mayLoad() && !MI.mayStore()))
        continue;
      const auto *memory = *MI.memoperands_begin();
      const auto *slot =
          llvm::dyn_cast_or_null<llvm::FixedStackPseudoSourceValue>(
              memory->getPseudoValue());
      if (!slot || slot->getFrameIndex() < 0 ||
          !frame.isSpillSlotObjectIndex(slot->getFrameIndex()) ||
          frame.getObjectSize(slot->getFrameIndex()) != isa_config_.word_length)
        continue;
      auto inserted = spill_keys.emplace(
          slot->getFrameIndex(), register_count + slot->getFrameIndex());
      const unsigned key = inserted.first->second;
      entry.emplace(key, unknown);
      spills.emplace(
          &MI, Spill{key, memory->getOffset() == 0 &&
                              memory->getSize() == isa_config_.word_length});
    }

  auto value = [&](const State &state, llvm::Register reg) {
    auto found = state.find(reg);
    return found == state.end() ? Value{Relation::Equal, {}, all_bits}
                                : found->second;
  };
  std::map<const llvm::MachineInstr *, PointerDeltaUpdates> updates;
  auto transfer = [&](const llvm::MachineInstr &MI, State &state,
                      PointerDeltaUpdates *writes = nullptr) {
    if (MI.isDebugInstr())
      return;
    auto assign = [&](unsigned key, Value assigned) {
      if (writes && assigned.relation != Relation::Unsupported)
        writes->emplace(runtimeOrigin(key).index,
                        assigned.relation == Relation::Equal
                            ? PointerOrigin{PointerOrigin::Kind::Equal, 0}
                            : assigned.origin);
      if (assigned.relation == Relation::FrameAddress &&
          (assigned.origin.kind == PointerOrigin::Kind::Runtime ||
           assigned.origin.kind == PointerOrigin::Kind::Scalar ||
           assigned.origin.kind == PointerOrigin::Kind::Constant ||
           assigned.origin.kind == PointerOrigin::Kind::Context))
        assigned.origin = runtimeOrigin(key);
      state.at(key) = assigned;
    };
    if (MI.getOpcode() == llvm::RISCV::COMPAS_DYNALLOC) {
      const auto size = MI.getOperand(1).getReg();
      if (value(state, size).relation != Relation::Equal)
        llvm::report_fatal_error("COMPAS: unsupported EDDI allocation size");
      const Value allocated{Relation::FrameAddress,
                            {PointerOrigin::Kind::Scalar, size}, all_bits, true};
      assign(MI.getOperand(0).getReg(), allocated);
      assign(riscv_common::kSP, allocated);
      return;
    }
    if (MI.getOpcode() == llvm::RISCV::COMPAS_CALLDOWN ||
        MI.getOpcode() == llvm::RISCV::COMPAS_CALLUP) {
      assign(riscv_common::kSP,
             {Relation::FrameAddress,
              MI.getOpcode() == llvm::RISCV::COMPAS_CALLDOWN
                  ? PointerOrigin{PointerOrigin::Kind::Constant,
                                  static_cast<unsigned>(MI.getOperand(0).getImm())}
                  : PointerOrigin{PointerOrigin::Kind::Context, 1},
              all_bits, true});
      return;
    }
    Value result{Relation::Equal, {}, all_bits};
    int64_t argument_offset = 0;
    if (incomingStackArgumentOffset(MI, argument_offset)) {
      const auto offsets = MF_->getInfo<llvm::RISCVMachineFunctionInfo>()
                               ->getCompasIncomingStackPointerOffsets();
      const auto formal = std::find_if(
          offsets.begin(), offsets.end(), [&](int64_t offset) {
            return argument_offset >= offset &&
                   argument_offset - offset < isa_config_.word_length;
          });
      if (formal != offsets.end()) {
        if (argument_offset != *formal ||
            MI.getOpcode() != isa_config_.load_opcode)
          llvm::report_fatal_error(
              "COMPAS: EDDI stack pointer formal requires a full-word load");
        result = {Relation::FrameAddress,
                  {PointerOrigin::Kind::IncomingStack,
                   static_cast<unsigned>(formal - offsets.begin())}, all_bits};
      }
    }
    const auto spill = spills.find(&MI);
    if (MI.mayLoad() && spill != spills.end() && spill->second.full_word)
      result = state.at(spill->second.key);
    if (!MI.isCall() && !MI.mayLoad()) {
      for (const auto &operand : MI.operands())
        if (operand.isReg() && operand.isUse() &&
            value(state, operand.getReg()).relation != Relation::Equal)
          result = unknown;

      const unsigned opcode = MI.getOpcode();
      if ((opcode == llvm::TargetOpcode::COPY || opcode == llvm::RISCV::ADDI) &&
          MI.getNumOperands() >= 2 && MI.getOperand(1).isReg()) {
        const auto source = value(state, MI.getOperand(1).getReg());
        result.relation = source.relation;
        result.origin = source.origin;
        result.current_frame = source.current_frame;
        if (opcode == llvm::TargetOpcode::COPY ||
            (MI.getOperand(2).isImm() && MI.getOperand(2).getImm() == 0))
          result.bits = source.bits;
        else if (MI.getOperand(2).isImm() && source.bits == 0)
          result.bits =
              static_cast<uint64_t>(MI.getOperand(2).getImm()) & all_bits;
      } else if ((opcode == llvm::RISCV::ADD || opcode == llvm::RISCV::SUB) &&
                 MI.getNumOperands() >= 3 && MI.getOperand(1).isReg() &&
                 MI.getOperand(2).isReg()) {
        const auto left = value(state, MI.getOperand(1).getReg());
        const auto right = value(state, MI.getOperand(2).getReg());
        if (left.relation == Relation::Equal &&
            right.relation == Relation::Equal)
          result.relation = Relation::Equal;
        else if (left.relation == Relation::FrameAddress &&
                 right.relation == Relation::Equal) {
          result.relation = Relation::FrameAddress;
          result.origin = left.origin;
          result.current_frame = left.current_frame;
        } else if (opcode == llvm::RISCV::ADD &&
                   left.relation == Relation::Equal &&
                   right.relation == Relation::FrameAddress) {
          result.relation = Relation::FrameAddress;
          result.origin = right.origin;
          result.current_frame = right.current_frame;
        } else if (opcode == llvm::RISCV::SUB &&
                   left.relation == Relation::FrameAddress &&
                   right.relation == Relation::FrameAddress &&
                   left.origin == right.origin)
          result = {Relation::Equal, {}, all_bits};
      }
      if (MI.getNumOperands() >= 3 && MI.getOperand(1).isReg()) {
        const auto left = value(state, MI.getOperand(1).getReg());
        if (MI.getOperand(2).isImm()) {
          const int64_t immediate = MI.getOperand(2).getImm();
          if (opcode == llvm::RISCV::ANDI)
            result.bits =
                left.bits & static_cast<uint64_t>(immediate) & all_bits;
          else if (opcode == llvm::RISCV::SLLI && immediate >= 0 &&
                   immediate < width)
            result.bits = (left.bits << immediate) & all_bits;
          else if (opcode == llvm::RISCV::SRLI && immediate >= 0 &&
                   immediate < width)
            result.bits = left.bits >> immediate;
        } else if (opcode == llvm::RISCV::OR && MI.getOperand(2).isReg()) {
          const auto right = value(state, MI.getOperand(2).getReg());
          result.bits = left.bits | right.bits;
          // Only this frame's D is statically known. Inherited deltas must
          // not borrow its low-bit guarantee for arbitrary pointer ORs.
          if (left.relation == Relation::FrameAddress &&
              left.origin.kind == PointerOrigin::Kind::Frame &&
              right.relation == Relation::Equal &&
              !(right.bits & ~unchanged_low_bits)) {
            result.relation = Relation::FrameAddress;
            result.origin = {};
            result.current_frame = left.current_frame;
          } else if (right.relation == Relation::FrameAddress &&
                     right.origin.kind == PointerOrigin::Kind::Frame &&
                     left.relation == Relation::Equal &&
                     !(left.bits & ~unchanged_low_bits)) {
            result.relation = Relation::FrameAddress;
            result.origin = {};
            result.current_frame = right.current_frame;
          } else if (left.relation == Relation::FrameAddress &&
                     right.relation == Relation::Equal && right.bits == 0) {
            result.relation = Relation::FrameAddress;
            result.origin = left.origin;
            result.current_frame = left.current_frame;
          } else if (right.relation == Relation::FrameAddress &&
                     left.relation == Relation::Equal && left.bits == 0) {
            result.relation = Relation::FrameAddress;
            result.origin = right.origin;
            result.current_frame = right.current_frame;
          }
        }
      }
    }
    const Value stored = MI.mayStore() && spill != spills.end() &&
                                 spill->second.full_word &&
                                 MI.getNumOperands() && MI.getOperand(0).isReg()
                             ? value(state, MI.getOperand(0).getReg())
                             : unknown;
    // Read all sources before killing destinations, including reused registers.
    for (auto &item : state)
      if (item.first < register_count && MI.modifiesRegister(item.first, TRI_) &&
          !(MI.isCall() &&
            ((dynamic_frame && item.first == riscv_common::kSP) ||
             (base_pointer && item.first == riscv_common::kEddiBP))))
        assign(item.first, result);
    if (MI.mayStore() && spill != spills.end())
      assign(spill->second.key, stored);
    state.at(riscv_common::k0) = {Relation::Equal, {}, 0};
    if (!dynamic_frame || MI.getFlag(llvm::MachineInstr::FrameSetup)) {
      state.at(riscv_common::kSP).relation = Relation::FrameAddress;
      state.at(riscv_common::kSP).origin = {};
      state.at(riscv_common::kSP).current_frame = true;
    }
  };

  // An unvisited loop backedge must not erase its incoming provenance.
  std::map<const llvm::MachineBasicBlock *, State> inputs, outputs;
  bool changed;
  do {
    changed = false;
    for (const auto &MBB : *MF_) {
      if (&MBB == err_bb_)
        continue;
      State incoming;
      bool reachable = &MBB == &MF_->front();
      if (reachable)
        incoming = entry;
      for (const auto *predecessor : MBB.predecessors()) {
        auto found = outputs.find(predecessor);
        if (found == outputs.end())
          continue;
        if (!reachable) {
          incoming = found->second;
          reachable = true;
        } else {
          for (auto &item : incoming) {
            const auto &other = found->second.at(item.first);
            if (item.second.relation != other.relation ||
                item.second.origin != other.origin) {
              if (runtime_origins &&
                  item.second.relation != Relation::Unsupported &&
                  other.relation != Relation::Unsupported) {
                item.second.relation = Relation::FrameAddress;
                item.second.origin = runtimeOrigin(item.first);
              } else {
                item.second.relation = Relation::Unsupported;
                item.second.origin = {};
              }
            }
            item.second.bits |= other.bits;
            item.second.current_frame &= other.current_frame;
          }
        }
      }
      if (!reachable)
        continue;
      inputs[&MBB] = incoming;
      State outgoing = incoming;
      for (const auto &MI : MBB)
        transfer(MI, outgoing);
      auto found = outputs.find(&MBB);
      if (found == outputs.end() || found->second != outgoing) {
        outputs[&MBB] = std::move(outgoing);
        changed = true;
      }
    }
  } while (changed);

  std::map<const llvm::MachineInstr *, std::set<unsigned>> uses;
  for (auto &MBB : *MF_) {
    auto found = inputs.find(&MBB);
    if (found == inputs.end())
      continue;
    State state = found->second;
    for (auto &MI : MBB) {
      if (MI.getOpcode() == llvm::RISCV::COMPAS_DYNALLOC ||
          MI.getOpcode() == llvm::RISCV::COMPAS_CALLDOWN ||
          MI.getOpcode() == llvm::RISCV::COMPAS_CALLUP) {
        const auto stack = value(state, riscv_common::kSP);
        if (stack.relation != Relation::FrameAddress)
          llvm::report_fatal_error("COMPAS: unknown EDDI dynamic stack origin");
        dynamic_sp_origins_.emplace(&MI, stack.origin);
        if (stack.origin.kind == PointerOrigin::Kind::Runtime)
          uses[&MI].insert(stack.origin.index);
      }
      if (MI.mayStore() && MI.getNumOperands() && MI.getOperand(0).isReg()) {
        const auto data = value(state, MI.getOperand(0).getReg());
        if (data.relation == Relation::FrameAddress) {
          // Private/outgoing stores can lose their FI/PSV once the target
          // materializes a large frame address. Preserve ownership separately
          // from fixed/VLA/call-area delta locations, so materialized addresses
          // still get the pointee-origin check used for private spills.
          Value destination = unknown;
          if (MI.getNumOperands() >= 2 && MI.getOperand(1).isReg())
            destination = value(state, MI.getOperand(1).getReg());
          const bool current_frame =
              destination.relation == Relation::FrameAddress &&
              destination.current_frame;
          const bool call_slot =
              MI.getNumOperands() >= 3 && MI.getOperand(1).isReg() &&
              MI.getOperand(1).getReg() == riscv_common::kSP &&
              MI.getOperand(2).isImm() && MI.getOperand(2).getImm() >= 0 &&
              static_cast<uint64_t>(MI.getOperand(2).getImm()) +
                      isa_config_.word_length <= frame.getMaxCallFrameSize();
          if (MI.getOpcode() == isa_config_.store_opcode &&
              (current_frame || call_slot))
            frame_address_stores_.emplace(&MI, data.origin);
          for (const auto *memory : MI.memoperands()) {
            const auto *slot =
                llvm::dyn_cast_or_null<llvm::FixedStackPseudoSourceValue>(
                    memory->getPseudoValue());
            if (memory->isStore() && slot &&
                !frame.isFixedObjectIndex(slot->getFrameIndex()))
              frame_address_stores_.emplace(&MI, data.origin);
          }
        }
      }
      if (user_calls_.count(&MI)) {
        for (auto reg : getArgRegs(&MI)) {
          const auto argument = value(state, reg);
          if (argument.relation == Relation::FrameAddress)
            stack_address_call_args_[&MI][reg] = argument.origin;
          else if (argument.relation == Relation::Unsupported)
            llvm::report_fatal_error(
                llvm::Twine(
                    "COMPAS: unsupported or mixed EDDI stack argument in ") +
                fname_);
        }
      }
      // A runtime check reads the location's independently propagated delta.
      auto useOrigin = [&](PointerOrigin origin) {
        if (origin.kind == PointerOrigin::Kind::Runtime)
          uses[&MI].insert(origin.index);
      };
      const auto store = frame_address_stores_.find(&MI);
      if (store != frame_address_stores_.end())
        useOrigin(store->second);
      const auto call = stack_address_call_args_.find(&MI);
      if (call != stack_address_call_args_.end())
        for (const auto &argument : call->second)
          useOrigin(argument.second);
      transfer(MI, state, &updates[&MI]);
    }
  }

  // Backward delta liveness selects only definitions feeding a checked use.
  // In particular, do not add FP-relative writes after the epilogue restores
  // FP, or transport irrelevant scalar/architectural context through calls.
  std::map<const llvm::MachineBasicBlock *, std::set<unsigned>> live_in;
  do {
    changed = false;
    for (auto block = MF_->rbegin(); block != MF_->rend(); ++block) {
      std::set<unsigned> needed;
      for (const auto *successor : block->successors())
        needed.insert(live_in[successor].begin(), live_in[successor].end());
      for (auto MI = block->rbegin(); MI != block->rend(); ++MI) {
        const auto &writes = updates[&*MI];
        std::set<unsigned> sources;
        for (const auto &write : writes)
          if (needed.erase(write.first)) {
            pointer_delta_updates_[&*MI][write.first] = write.second;
            if (write.second.kind == PointerOrigin::Kind::Runtime)
              sources.insert(write.second.index);
          }
        needed.insert(sources.begin(), sources.end());
        needed.insert(uses[&*MI].begin(), uses[&*MI].end());
      }
      if (live_in[&*block] != needed) {
        live_in[&*block] = std::move(needed);
        changed = true;
      }
    }
  } while (changed);
  for (const auto &item : entry) {
    const unsigned slot = runtimeOrigin(item.first).index;
    if (!live_in[&MF_->front()].count(slot))
      continue;
    if (item.second.relation == Relation::Unsupported)
      llvm::report_fatal_error("COMPAS: undefined EDDI pointer provenance");
    pointer_delta_entry_.emplace(
        slot, item.second.relation == Relation::Equal
                  ? PointerOrigin{PointerOrigin::Kind::Equal, 0}
                  : item.second.origin);
  }
}

llvm::MachineInstr *
RISCVDmr::genShadowFromPrimary(const llvm::MachineInstr *MI) const {
  auto si{MF_->CloneMachineInstr(MI)};
  if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_))
    useIndependentShadowMemory(*MF_, *si);
  auto symbol = shadow_pcrel_symbols_.find(MI->getPreInstrSymbol());
  if (symbol != shadow_pcrel_symbols_.end())
    si->setPreInstrSymbol(*MF_, symbol->second);
  for (auto &o : si->operands()) {
    if (o.isReg()) {
      // Both FP computations use the architectural rounding mode. LLVM16
      // models this shared input explicitly; it has no shadow GPR/FPR.
      if (o.isImplicit() && o.isUse() && o.getReg() == llvm::RISCV::FRM)
        continue;
      assert((riscv_common::setmapContains(P2S_, o.getReg())) &&
             "reg not found in P2S_");
      o.setReg(P2S_.at(o.getReg()));
    } else if (o.isMCSymbol() &&
               o.getTargetFlags() == llvm::RISCVII::MO_PCREL_LO) {
      auto shadow = shadow_pcrel_symbols_.find(o.getMCSymbol());
      if (shadow != shadow_pcrel_symbols_.end()) {
        auto offset = o.getOffset();
        o.ChangeToMCSymbol(shadow->second, o.getTargetFlags());
        o.setOffset(offset);
      }
    }
  }
  return si;
}

void RISCVDmr::preparePCRelativeAddresses() {
  std::map<llvm::MCSymbol *, llvm::MachineInstr *> highs;
  std::map<llvm::MCSymbol *, std::vector<llvm::MachineInstr *>> lows;
  for (auto &MBB : *MF_) {
    for (auto &MI : MBB) {
      if (MI.getOpcode() == llvm::RISCV::AUIPC && MI.getPreInstrSymbol())
        highs.emplace(MI.getPreInstrSymbol(), &MI);
      for (auto &MO : MI.operands()) {
        if (!MO.isMCSymbol() ||
            MO.getTargetFlags() != llvm::RISCVII::MO_PCREL_LO)
          continue;
        // The low symbol identifies an AUIPC, not a target-address addend.
        // LLVM folds generated global+offset addends into the high operand.
        if (MI.getNumOperands() < 3 || &MO != &MI.getOperand(2) ||
            MO.getOffset() != 0 ||
            !(MI.getOpcode() == llvm::RISCV::ADDI || MI.mayLoad() ||
              MI.mayStore()))
          llvm::report_fatal_error("COMPAS: unsupported PC-relative low operand");
        lows[MO.getMCSymbol()].push_back(&MI);
      }
    }
  }

  for (const auto &pair : lows) {
    auto high = highs.find(pair.first);
    if (high == highs.end())
      llvm::report_fatal_error("COMPAS: PC-relative low has no AUIPC anchor");
    auto *HI = high->second;
    auto flags = HI->getOperand(1).getTargetFlags();
    // Address, GOT-slot, and TLS-slot formation all use an AUIPC/low pair.
    // Call relocations have different semantics and are not admitted here.
    if (flags != llvm::RISCVII::MO_PCREL_HI &&
        flags != llvm::RISCVII::MO_GOT_HI &&
        flags != llvm::RISCVII::MO_TLS_GOT_HI &&
        flags != llvm::RISCVII::MO_TLS_GD_HI)
      llvm::report_fatal_error("COMPAS: unsupported PC-relative high operand");
    auto reg = HI->getOperand(0).getReg();
    if (reg == llvm::RISCV::X0)
      llvm::report_fatal_error("COMPAS: PC-relative AUIPC defines zero");

    // Normalizing the high register is safe only while its value is used as
    // the base of this pair's lows. Check all paths up to its next definition;
    // this also handles a high shared by consumers in different blocks.
    std::set<llvm::MachineBasicBlock *> visited;
    std::set<llvm::MachineInstr *> reached_lows;
    using Position = std::pair<llvm::MachineBasicBlock *,
                               llvm::MachineBasicBlock::iterator>;
    std::vector<Position> pending{{HI->getParent(),
                                   std::next(HI->getIterator())}};
    while (!pending.empty()) {
      auto position = pending.back();
      pending.pop_back();
      bool clobbered = false;
      for (auto it = position.second; it != position.first->end(); ++it) {
        if (it->isDebugInstr())
          continue;
        if (it->readsRegister(reg, TRI_)) {
          bool paired = it->getNumOperands() >= 3 &&
                        it->getOperand(1).isReg() &&
                        it->getOperand(1).getReg() == reg &&
                        it->getOperand(2).isMCSymbol() &&
                        it->getOperand(2).getTargetFlags() ==
                            llvm::RISCVII::MO_PCREL_LO &&
                        it->getOperand(2).getMCSymbol() == pair.first;
          for (unsigned n = 0; n != it->getNumOperands(); ++n) {
            const auto &MO = it->getOperand(n);
            if (MO.isReg() && MO.isUse() && MO.getReg() == reg && n != 1)
              paired = false;
          }
          if (!paired)
            llvm::report_fatal_error(
                "COMPAS: unsupported use of PC-relative AUIPC base");
          reached_lows.insert(&*it);
        }
        if (it->modifiesRegister(reg, TRI_)) {
          clobbered = true;
          break;
        }
      }
      if (!clobbered) {
        for (auto *successor : position.first->successors())
          if (visited.insert(successor).second)
            pending.emplace_back(successor, successor->begin());
      }
    }
    for (auto *LO : pair.second)
      if (!reached_lows.count(LO))
        llvm::report_fatal_error(
            "COMPAS: unsupported PC-relative base register transfer");

    // Raw AUIPC values differ between primary and shadow instruction PCs.
    // Materialize the full address before any existing register comparisons,
    // leaving ordinary zero-offset loads/stores/ADDI consumers. Each shadow
    // materialization is relocated against its own fresh AUIPC label.
    llvm::BuildMI(*HI->getParent(), std::next(HI->getIterator()),
                  HI->getDebugLoc(), TII_->get(llvm::RISCV::ADDI), reg)
        .addReg(reg)
        .addSym(pair.first, llvm::RISCVII::MO_PCREL_LO);
    for (auto *LO : pair.second)
      LO->getOperand(2).ChangeToImmediate(0);
    shadow_pcrel_symbols_.emplace(
        pair.first, MF_->getContext().createTempSymbol("compas_pcrel_hi"));
  }
}

void RISCVDmr::duplicateInstructions() {
  preparePCRelativeAddresses();
  std::map<llvm::MachineInstr *, llvm::MachineInstr *> incoming_stack_loads;
  if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_)) {
    const auto *info = MF_->getInfo<llvm::RISCVMachineFunctionInfo>();
    for (auto &MBB : *MF_)
      for (auto &MI : MBB) {
        int64_t offset = 0;
        if (incomingStackArgumentOffset(MI, offset))
          incoming_stack_loads.emplace(&MI, nullptr);
      }
    if (info->useSaveRestoreLibCalls(*MF_))
      llvm::report_fatal_error(
          "COMPAS: EDDI save/restore libcalls are unsupported");
  }
  std::map<llvm::MachineInstr *, llvm::MachineInstr *> shadows;
  auto shadow_instruction = [&](llvm::MachineInstr &MI) {
    auto *shadow = genShadowFromPrimary(&MI);
    shadows.emplace(&MI, shadow);
    auto incoming = incoming_stack_loads.find(&MI);
    if (incoming != incoming_stack_loads.end())
      incoming->second = shadow;
    return shadow;
  };
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
        if (MI.isCFIInstruction() || MI.isDebugInstr())
          continue;
        if (isCompilerBarrier(MI) || MI.isCall() || MI.mayStore() ||
            MI.isBranch() || MI.isReturn() ||
            dynamic_sp_origins_.count(&MI)) {
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
          shadow_block.emplace_back(shadow_instruction(MI));

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
        if (MI.isCFIInstruction() || MI.isDebugInstr() || isCompilerBarrier(MI))
          continue;
        if (MI.isCall() || MI.mayStore() || MI.isBranch() || MI.isReturn() ||
            dynamic_sp_origins_.count(&MI)) {
          continue;
        } else if (MI.mayLoad() && config_.psl == ProtectStrategyLoad::L1) {
          // SWIFT uses one checked load followed by a copy, in either schedule.
          continue;
        } else {
          MBB.insert(&MI, shadow_instruction(MI));
        }
      }
    }
  } else {
    assert(0 && "this instruction-schedule for DMR is not supported yet");
  }

  llvm::BuildMI(MF_->front(), std::begin(MF_->front()),
                MF_->front().front().getDebugLoc(),
                TII_->get(llvm::RISCV::ADDI), P2S_.at(riscv_common::kRA))
      .addReg(riscv_common::kRA)
      .addImm(0);

  if (fname_ == "main") {
    llvm::BuildMI(MF_->front(), std::begin(MF_->front()),
                  MF_->front().front().getDebugLoc(),
                  TII_->get(llvm::RISCV::ADDI), P2S_.at(riscv_common::kSP))
        .addReg(riscv_common::kSP)
        .addImm(0);
    llvm::BuildMI(MF_->front(), std::begin(MF_->front()),
                  MF_->front().front().getDebugLoc(),
                  TII_->get(llvm::RISCV::ADDI), P2S_.at(riscv_common::k0))
        .addReg(riscv_common::k0)
        .addImm(0);
    llvm::BuildMI(MF_->front(), std::begin(MF_->front()),
                  MF_->front().front().getDebugLoc(),
                  TII_->get(llvm::RISCV::ADDI), P2S_.at(riscv_common::kGP))
        .addReg(riscv_common::kGP)
        .addImm(0);
  }

  // EDDI reserves an independent frame, with extra separation for realignment.
  if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_)) {
    // Leave LLVM's original split allocation/address materialization intact.
    // Reserve D below the first primary allocation and start its shadow from
    // the corresponding independently adjusted entry bank. All later original
    // setup/destruction instructions then preserve the same separation.
    llvm::MachineInstr *primary_sp = nullptr;
    int64_t allocated_prefix = frame_size_;
    for (auto &MI : *entry_bb_) {
      if (!MI.getFlag(llvm::MachineInstr::FrameSetup) ||
          !MI.modifiesRegister(riscv_common::kSP, TRI_) ||
          MI.isCFIInstruction())
        continue;
      if (MI.getOpcode() == llvm::RISCV::ADDI && MI.getNumOperands() >= 3 &&
          MI.getOperand(1).isReg() &&
          MI.getOperand(1).getReg() == riscv_common::kSP &&
          MI.getOperand(2).isImm() && MI.getOperand(2).getImm() < 0) {
        allocated_prefix = -MI.getOperand(2).getImm();
        primary_sp = &MI;
        break;
      }
      if (MI.getOpcode() == llvm::RISCV::SUB && MI.getNumOperands() >= 3 &&
          MI.getOperand(1).isReg() &&
          MI.getOperand(1).getReg() == riscv_common::kSP) {
        primary_sp = &MI;
        break;
      }
    }
    if (!primary_sp && frame_size_)
      llvm::report_fatal_error("COMPAS: unsupported EDDI frame allocation");
    if (primary_sp) {
      const auto shadow = shadows.find(primary_sp);
      if (shadow == shadows.end())
        llvm::report_fatal_error(
            "COMPAS: EDDI frame allocation was not duplicated");
      shadow->second->eraseFromParent();
      auto insert = std::next(primary_sp->getIterator());
      auto *extra_allocation =
          addOffset(*entry_bb_, insert, *TII_, riscv_common::kSP,
                    riscv_common::kSP, -shadow_frame_offset_,
                    primary_sp->getDebugLoc(), llvm::MachineInstr::FrameSetup);
      auto *shadow_sp =
          addOffset(*entry_bb_, insert, *TII_, P2S_.at(riscv_common::kSP),
                    riscv_common::kSP, shadow_frame_offset_,
                    primary_sp->getDebugLoc(), llvm::MachineInstr::FrameSetup);
      if (riscv_common::incomingPointerDeltaSlots(*MF_))
        saveIncomingPointerDeltas(shadow_sp, allocated_prefix);
      if (!incoming_stack_loads.empty()) {
        for (const auto &pair : incoming_stack_loads)
          if (!pair.second)
            llvm::report_fatal_error(
                "COMPAS: incoming stack argument was not duplicated");
        rewriteIncomingStackArguments(
            *MF_, incoming_stack_loads, allocated_prefix, shadow_frame_offset_,
            *primary_sp, *shadow_sp, P2S_.at(riscv_common::k0),
            P2S_.at(riscv_common::kSP), P2S_.at(riscv_common::kFP));
      }
      std::map<llvm::MachineInstr *, llvm::MachineInstr *> extra_deallocations;
      for (auto &MBB : *MF_)
        for (auto &MI : MBB)
          if (MI.isReturn() || TII_->isTailCall(MI))
            extra_deallocations.emplace(
                &MI, addOffset(MBB, MI.getIterator(), *TII_, riscv_common::kSP,
                               riscv_common::kSP, shadow_frame_offset_,
                               MI.getDebugLoc(), llvm::MachineInstr::FrameDestroy));
      // The physical primary frame is D below the original caller CFA.
      // CFI describes that primary frame once, independently of its shadow.
      for (auto &MBB : *MF_) {
        for (auto iterator = MBB.begin(); iterator != MBB.end();) {
          auto &MI = *iterator++;
          if (!MI.isCFIInstruction())
            continue;
          const auto original =
              MF_->getFrameInstructions().at(MI.getOperand(0).getCFIIndex());
          auto adjusted = original;
          using CFI = llvm::MCCFIInstruction;
          switch (original.getOperation()) {
          case CFI::OpDefCfaOffset:
            adjusted = CFI::cfiDefCfaOffset(original.getLabel(),
                                            original.getOffset() +
                                                shadow_frame_offset_);
            break;
          case CFI::OpDefCfa:
            adjusted =
                CFI::cfiDefCfa(original.getLabel(), original.getRegister(),
                               original.getOffset() + shadow_frame_offset_);
            break;
          case CFI::OpOffset:
            adjusted =
                CFI::createOffset(original.getLabel(), original.getRegister(),
                                  original.getOffset() - shadow_frame_offset_);
            break;
          default:
            continue;
          }
          llvm::BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(),
                        TII_->get(llvm::TargetOpcode::CFI_INSTRUCTION))
              .addCFIIndex(MF_->addFrameInst(adjusted))
              .setMIFlags(MI.getFlags());
          MI.eraseFromParent();
        }
      }
      // Describe each extra SP adjustment, including its final return state.
      // Restore the linear CFI state after each return so later lexical blocks
      // retain their original body recipe. Original epilogue CFI is otherwise
      // left to LLVM; this does not add asynchronous unwind support to it.
      using CFI = llvm::MCCFIInstruction;
      const unsigned dwarf_sp = TRI_->getDwarfRegNum(riscv_common::kSP, true);
      auto cfi = [&](llvm::MachineBasicBlock &MBB,
                     llvm::MachineBasicBlock::iterator where,
                     const CFI &instruction) {
        llvm::BuildMI(MBB, where, llvm::DebugLoc(),
                      TII_->get(llvm::TargetOpcode::CFI_INSTRUCTION))
            .addCFIIndex(MF_->addFrameInst(instruction));
      };
      cfi(*entry_bb_, extra_allocation->getIterator(),
          CFI::cfiDefCfa(nullptr, dwarf_sp, allocated_prefix));
      int64_t cfa_offset = allocated_prefix;
      for (auto iterator = extra_allocation->getIterator();
           &*iterator != shadow_sp;) {
        const auto &MI = *iterator++;
        if (MI.getOpcode() != llvm::RISCV::ADDI ||
            MI.getOperand(0).getReg() != riscv_common::kSP)
          continue;
        cfa_offset -= MI.getOperand(2).getImm();
        cfi(*entry_bb_, iterator, CFI::cfiDefCfaOffset(nullptr, cfa_offset));
      }
      for (const auto &deallocation : extra_deallocations) {
        auto &MBB = *deallocation.first->getParent();
        auto iterator = deallocation.second->getIterator();
        // LLVM13's AsmPrinter lacks the dedicated remember/restore cases.
        // Emit the standard DW_CFA bytes through its supported escape form.
        cfi(MBB, iterator,
            CFI::createEscape(nullptr, llvm::StringRef("\x0a", 1)));
        cfi(MBB, iterator,
            CFI::cfiDefCfa(nullptr, dwarf_sp, shadow_frame_offset_));
        cfa_offset = shadow_frame_offset_;
        while (&*iterator != deallocation.first) {
          const auto &MI = *iterator++;
          cfa_offset -= MI.getOperand(2).getImm();
          cfi(MBB, iterator, CFI::cfiDefCfaOffset(nullptr, cfa_offset));
        }
        cfi(MBB, std::next(deallocation.first->getIterator()),
            CFI::createEscape(nullptr, llvm::StringRef("\x0b", 1)));
      }
    }
  }

  emitPointerDeltaUpdates();
  expandDynamicStack();

#ifdef DBG
  llvm::outs() << "COMPAS_DBG: duplicateInstructions() done\n";
#endif
}

unsigned RISCVDmr::pointerContextSlot(unsigned index) const {
  const auto *info = MF_->getInfo<llvm::RISCVMachineFunctionInfo>();
  const int bank = info->getCompasPointerDeltaFrameIndex();
  const unsigned words = riscv_common::usesEddiBasePointer(*MF_) ? 5 : 3;
  if (index >= words || bank >= 0 || !MF_->getFrameInfo().hasVarSizedObjects())
    llvm::report_fatal_error("COMPAS: dynamic stack context was not prepared");
  return MF_->getFrameInfo().getObjectSize(bank) / isa_config_.word_length -
         riscv_common::incomingPointerDeltaSlots(*MF_) - words + index;
}

void RISCVDmr::expandDynamicStack() {
  const llvm::Register primary_sp = riscv_common::kSP;
  const auto shadow_sp = P2S_.at(primary_sp);
  const auto scratch = P2S_.at(riscv_common::k0);
  const unsigned stack_slot = primary_sp - llvm::RISCV::X0;
  for (const auto &allocation : dynamic_sp_origins_) {
    auto *MI = allocation.first;
    auto &MBB = *MI->getParent();
    const auto insert = MI->getIterator();
    const auto DL = MI->getDebugLoc();
    const unsigned opcode = MI->getOpcode();
    if (opcode == llvm::RISCV::COMPAS_DYNALLOC) {
      const auto destination = MI->getOperand(0).getReg();
      const auto size = MI->getOperand(1).getReg();
      const auto shadow_size = P2S_.at(size);
      const uint64_t alignment = MI->getOperand(2).getImm();
      if (!llvm::isPowerOf2_64(alignment) || alignment < 16)
        llvm::report_fatal_error("COMPAS: unsupported EDDI VLA alignment");
      llvm::BuildMI(MBB, insert, DL, TII_->get(llvm::RISCV::BNE))
          .addReg(size)
          .addReg(shadow_size)
          .addMBB(err_bb_);
      // R is independently rounded in each register bank. Allocate a fresh
      // interval of 2R below both old banks, with its shadow R above primary.
      // Older pointers retain their own expectations across later allocations.
      loadPointerDelta(&MBB, insert, allocation.second);
      llvm::BuildMI(MBB, insert, DL, TII_->get(llvm::RISCV::SUB), shadow_sp)
          .addReg(shadow_sp)
          .addReg(scratch);
      llvm::BuildMI(MBB, insert, DL, TII_->get(llvm::RISCV::SUB), shadow_sp)
          .addReg(shadow_sp)
          .addReg(shadow_size);
      for (unsigned repeat = 0; repeat < 2; ++repeat)
        llvm::BuildMI(MBB, insert, DL, TII_->get(llvm::RISCV::SUB), primary_sp)
            .addReg(primary_sp)
            .addReg(size);
      for (const auto reg : {primary_sp, shadow_sp}) {
        if (llvm::isInt<12>(-static_cast<int64_t>(alignment))) {
          llvm::BuildMI(MBB, insert, DL, TII_->get(llvm::RISCV::ANDI), reg)
              .addReg(reg)
              .addImm(-static_cast<int64_t>(alignment));
        } else {
          const unsigned shift = llvm::Log2_64(alignment);
          llvm::BuildMI(MBB, insert, DL, TII_->get(llvm::RISCV::SRLI), reg)
              .addReg(reg)
              .addImm(shift);
          llvm::BuildMI(MBB, insert, DL, TII_->get(llvm::RISCV::SLLI), reg)
              .addReg(reg)
              .addImm(shift);
        }
      }
      // Capture R before the output overwrites a possibly aliased size input.
      addOffset(MBB, insert, *TII_, scratch, size, 0, DL);
      storePointerDelta(&MBB, insert, stack_slot);
      storePointerDelta(&MBB, insert, destination - llvm::RISCV::X0);
      addOffset(MBB, insert, *TII_, destination, primary_sp, 0, DL);
      addOffset(MBB, insert, *TII_, P2S_.at(destination), shadow_sp, 0, DL);
    } else if (opcode == llvm::RISCV::COMPAS_CALLDOWN) {
      const int64_t amount = MI->getOperand(0).getImm();
      if (amount <= 0 || amount % 16)
        llvm::report_fatal_error("COMPAS: unsupported EDDI call allocation");
      addOffset(MBB, insert, *TII_, scratch, shadow_sp, 0, DL);
      storePointerDelta(&MBB, insert, pointerContextSlot(0));
      loadPointerDelta(&MBB, insert, allocation.second);
      storePointerDelta(&MBB, insert, pointerContextSlot(1));
      llvm::BuildMI(MBB, insert, DL, TII_->get(llvm::RISCV::SUB), shadow_sp)
          .addReg(shadow_sp)
          .addReg(scratch);
      addOffset(MBB, insert, *TII_, shadow_sp, shadow_sp, -amount, DL);
      addOffset(MBB, insert, *TII_, primary_sp, primary_sp, -2 * amount, DL);
      loadPointerDelta(&MBB, insert,
                       {PointerOrigin::Kind::Constant,
                        static_cast<unsigned>(amount)});
      storePointerDelta(&MBB, insert, stack_slot);
    } else {
      const int64_t amount = MI->getOperand(0).getImm();
      addOffset(MBB, insert, *TII_, primary_sp, primary_sp, 2 * amount, DL);
      loadPointerDelta(&MBB, insert, {PointerOrigin::Kind::Context, 0});
      addOffset(MBB, insert, *TII_, shadow_sp, scratch, 0, DL);
      loadPointerDelta(&MBB, insert, {PointerOrigin::Kind::Context, 1});
      storePointerDelta(&MBB, insert, stack_slot);
    }
    addOffset(MBB, insert, *TII_, scratch, riscv_common::k0, 0, DL);
    MI->eraseFromParent();
  }
  dynamic_sp_origins_.clear();
}

void RISCVDmr::preserveDynamicStackAcrossCalls() {
  // Callees can replace the monitor's SP with their own fixed-frame bank.
  // Preserve the actual caller state, independently of the checked delta.
  const auto scratch = P2S_.at(riscv_common::k0);
  const auto shadow_sp = P2S_.at(riscv_common::kSP);
  const bool base_pointer = riscv_common::usesEddiBasePointer(*MF_);
  for (auto &MBB : *MF_) {
    if (&MBB == err_bb_)
      continue;
    for (auto &MI : MBB) {
      if (!MI.isCall() || TII_->isTailCall(MI))
        continue;
      addOffset(MBB, MI.getIterator(), *TII_, scratch, shadow_sp, 0,
                MI.getDebugLoc());
      storePointerDelta(&MBB, MI.getIterator(), pointerContextSlot(2));
      if (base_pointer) {
        // BP records the aligned fixed-frame base while SP moves for VLAs.
        // Preserve each actual bank independently of its expected separation.
        addOffset(MBB, MI.getIterator(), *TII_, scratch,
                  riscv_common::kEddiBP, 0, MI.getDebugLoc());
        storePointerDelta(&MBB, MI.getIterator(), pointerContextSlot(3));
        addOffset(MBB, MI.getIterator(), *TII_, scratch,
                  P2S_.at(riscv_common::kEddiBP), 0, MI.getDebugLoc());
        storePointerDelta(&MBB, MI.getIterator(), pointerContextSlot(4));
      }
      addOffset(MBB, MI.getIterator(), *TII_, scratch, riscv_common::k0, 0);
      const auto after = std::next(MI.getIterator());
      loadPointerDelta(&MBB, after, {PointerOrigin::Kind::Context, 2});
      addOffset(MBB, after, *TII_, shadow_sp, scratch, 0, MI.getDebugLoc());
      if (base_pointer) {
        loadPointerDelta(&MBB, after, {PointerOrigin::Kind::Context, 3});
        addOffset(MBB, after, *TII_, riscv_common::kEddiBP, scratch, 0,
                  MI.getDebugLoc());
        loadPointerDelta(&MBB, after, {PointerOrigin::Kind::Context, 4});
        addOffset(MBB, after, *TII_, P2S_.at(riscv_common::kEddiBP), scratch, 0,
                  MI.getDebugLoc());
      }
      addOffset(MBB, after, *TII_, scratch, riscv_common::k0, 0);
    }
  }
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

  llvm::BuildMI(*MBB, insert, DLL, TII_->get(feq_opcode), shadow_zero)
      .addReg(r1)
      .addReg(r2);
  llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::ADDI), shadow_zero)
      .addReg(shadow_zero)
      .addImm(-1);
  llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::BNE))
      .addReg(shadow_zero)
      .addReg(riscv_common::k0)
      .addMBB(err_bb_);
}

void RISCVDmr::saveIncomingPointerDeltas(llvm::MachineInstr *before,
                                         int64_t allocated_prefix) {
  const auto *info = MF_->getInfo<llvm::RISCVMachineFunctionInfo>();
  const auto pointers = info->getCompasIncomingPointerRegs();
  const auto stack = info->getCompasIncomingStackPointerOffsets();
  const int bank = info->getCompasPointerDeltaFrameIndex();
  if (bank >= 0)
    llvm::report_fatal_error("COMPAS: pointer delta frame was not prepared");
  const auto scratch = P2S_.at(riscv_common::k0);
  auto access = [&](unsigned index, llvm::Register reg, bool load) {
    const unsigned offset = index * isa_config_.word_length;
    const int64_t displacement =
        allocated_prefix + MF_->getFrameInfo().getObjectOffset(bank) + offset;
    if (displacement < 0 || !llvm::isInt<12>(displacement))
      llvm::report_fatal_error("COMPAS: unsupported pointer delta capture");
    auto *memory = MF_->getMachineMemOperand(
        llvm::MachinePointerInfo::getFixedStack(*MF_, bank, offset),
        load ? llvm::MachineMemOperand::MOLoad
             : llvm::MachineMemOperand::MOStore,
        isa_config_.word_length, llvm::Align(isa_config_.word_length));
    llvm::BuildMI(*before->getParent(), before->getIterator(),
                  before->getDebugLoc(),
                  TII_->get(load ? isa_config_.load_opcode
                                 : isa_config_.store_opcode))
        .addReg(reg, load ? llvm::RegState::Define : 0)
        .addReg(riscv_common::kSP)
        .addImm(displacement)
        .addMemOperand(memory)
        .setMIFlag(llvm::MachineInstr::FrameSetup);
  };
  unsigned index = 0;
  for (const auto reg : pointers) {
    // The caller validates the argument pair before transfer. Keep its entry
    // separation immutable rather than deriving it again at each later check.
    llvm::BuildMI(*before->getParent(), before->getIterator(),
                  before->getDebugLoc(), TII_->get(llvm::RISCV::SUB), scratch)
        .addReg(P2S_.at(reg))
        .addReg(reg)
        .setMIFlag(llvm::MachineInstr::FrameSetup);
    access(index++, scratch, false);
  }
  if (!stack.empty()) {
    const auto shadow_ra = P2S_.at(riscv_common::kRA);
    const unsigned temporary = pointers.size() + stack.size();
    access(temporary, shadow_ra, false);
    for (const int64_t offset : stack) {
      // SP has already moved below both banks, while shadow SP still names
      // the caller's outgoing bank. Do not borrow any allocated or ABI GPR.
      addOffset(*before->getParent(), before->getIterator(), *TII_, shadow_ra,
                riscv_common::kSP,
                allocated_prefix + shadow_frame_offset_ + offset,
                before->getDebugLoc(), llvm::MachineInstr::FrameSetup);
      addOffset(*before->getParent(), before->getIterator(), *TII_, scratch,
                P2S_.at(riscv_common::kSP), offset, before->getDebugLoc(),
                llvm::MachineInstr::FrameSetup);
      llvm::MachinePointerInfo primary;
      const auto &frame = MF_->getFrameInfo();
      for (int fi = frame.getObjectIndexBegin(); fi < 0; ++fi)
        if (frame.getObjectOffset(fi) == offset &&
            frame.getObjectSize(fi) >= isa_config_.word_length) {
          primary = llvm::MachinePointerInfo::getFixedStack(*MF_, fi);
          break;
        }
      for (const auto reg : {shadow_ra, scratch}) {
        auto *memory = MF_->getMachineMemOperand(
            reg == shadow_ra ? primary : llvm::MachinePointerInfo(),
            llvm::MachineMemOperand::MOLoad, isa_config_.word_length,
            llvm::Align(isa_config_.word_length));
        llvm::BuildMI(*before->getParent(), before->getIterator(),
                      before->getDebugLoc(), TII_->get(isa_config_.load_opcode),
                      reg)
            .addReg(reg)
            .addImm(0)
            .addMemOperand(memory)
            .setMIFlag(llvm::MachineInstr::FrameSetup);
      }
      llvm::BuildMI(*before->getParent(), before->getIterator(),
                    before->getDebugLoc(), TII_->get(llvm::RISCV::SUB), scratch)
          .addReg(scratch)
          .addReg(shadow_ra)
          .setMIFlag(llvm::MachineInstr::FrameSetup);
      access(index++, scratch, false);
    }
    access(temporary, shadow_ra, true);
  }
  llvm::BuildMI(*before->getParent(), before->getIterator(),
                before->getDebugLoc(), TII_->get(llvm::RISCV::ADDI), scratch)
      .addReg(riscv_common::k0)
      .addImm(0)
      .setMIFlag(llvm::MachineInstr::FrameSetup);
}

void RISCVDmr::loadPointerDelta(llvm::MachineBasicBlock *MBB,
                                llvm::MachineBasicBlock::iterator insert,
                                PointerOrigin origin) {
  const auto scratch = P2S_.at(riscv_common::k0);
  if (origin.kind == PointerOrigin::Kind::Equal ||
      origin.kind == PointerOrigin::Kind::Frame ||
      origin.kind == PointerOrigin::Kind::Constant ||
      origin.kind == PointerOrigin::Kind::Scalar) {
    const llvm::Register base = origin.kind == PointerOrigin::Kind::Scalar
                                    ? origin.index
                                    : riscv_common::k0;
    const int64_t offset = origin.kind == PointerOrigin::Kind::Frame
                               ? shadow_frame_offset_
                           : origin.kind == PointerOrigin::Kind::Constant
                               ? origin.index
                               : 0;
    addOffset(*MBB, insert, *TII_, scratch, base, offset);
    return;
  }
  const auto *info = MF_->getInfo<llvm::RISCVMachineFunctionInfo>();
  const auto pointers = info->getCompasIncomingPointerRegs();
  const int bank = info->getCompasPointerDeltaFrameIndex();
  if (bank >= 0)
    llvm::report_fatal_error("COMPAS: pointer delta frame was not prepared");
  unsigned index;
  if (origin.kind == PointerOrigin::Kind::Incoming) {
    const auto found =
        std::find(pointers.begin(), pointers.end(), origin.index);
    if (found == pointers.end())
      llvm::report_fatal_error(
          "COMPAS: incoming pointer origin was not prepared");
    index = std::distance(pointers.begin(), found);
  } else if (origin.kind == PointerOrigin::Kind::IncomingStack) {
    if (origin.index >= info->getCompasIncomingStackPointerOffsets().size())
      llvm::report_fatal_error("COMPAS: incoming stack pointer was not prepared");
    index = pointers.size() + origin.index;
  } else {
    index = riscv_common::incomingPointerDeltaSlots(*MF_) +
            (origin.kind == PointerOrigin::Kind::Context
                 ? pointerContextSlot(origin.index)
                 : origin.index);
  }
  const unsigned offset = index * isa_config_.word_length;
  if (offset + isa_config_.word_length >
      MF_->getFrameInfo().getObjectSize(bank))
    llvm::report_fatal_error(
        "COMPAS: pointer provenance slot was not prepared");
  llvm::Register base;
  const auto slot = MF_->getSubtarget<llvm::RISCVSubtarget>()
                        .getFrameLowering()
                        ->getFrameIndexReference(*MF_, bank, base);
  if (slot.getScalable() || base != riscv_common::kFP)
    llvm::report_fatal_error("COMPAS: pointer delta frame requires stable FP");
  int64_t displacement = slot.getFixed() + offset;
  while (!llvm::isInt<12>(displacement)) {
    const int64_t step = displacement > 0 ? 2047 : -2048;
    llvm::BuildMI(*MBB, insert, llvm::DebugLoc(), TII_->get(llvm::RISCV::ADDI),
                  scratch)
        .addReg(base)
        .addImm(step);
    base = scratch;
    displacement -= step;
  }
  auto *memory = MF_->getMachineMemOperand(
      llvm::MachinePointerInfo::getFixedStack(*MF_, bank, offset),
      llvm::MachineMemOperand::MOLoad, isa_config_.word_length,
      llvm::Align(isa_config_.word_length));
  llvm::BuildMI(*MBB, insert, llvm::DebugLoc(),
                TII_->get(isa_config_.load_opcode), scratch)
      .addReg(base)
      .addImm(displacement)
      .addMemOperand(memory);
}

void RISCVDmr::storePointerDelta(llvm::MachineBasicBlock *MBB,
                                 llvm::MachineBasicBlock::iterator insert,
                                 unsigned index) {
  const auto *info = MF_->getInfo<llvm::RISCVMachineFunctionInfo>();
  const int bank = info->getCompasPointerDeltaFrameIndex();
  const unsigned offset =
      (riscv_common::incomingPointerDeltaSlots(*MF_) + index) *
      isa_config_.word_length;
  if (bank >= 0 || offset + isa_config_.word_length >
                       MF_->getFrameInfo().getObjectSize(bank))
    llvm::report_fatal_error(
        "COMPAS: pointer provenance slot was not prepared");
  llvm::Register base;
  const auto slot = MF_->getSubtarget<llvm::RISCVSubtarget>()
                        .getFrameLowering()
                        ->getFrameIndexReference(*MF_, bank, base);
  const int64_t displacement = slot.getFixed() + offset;
  if (slot.getScalable() || base != riscv_common::kFP ||
      !llvm::isInt<12>(displacement))
    llvm::report_fatal_error(
        "COMPAS: runtime pointer provenance requires encodable FP slots");
  auto *memory = MF_->getMachineMemOperand(
      llvm::MachinePointerInfo::getFixedStack(*MF_, bank, offset),
      llvm::MachineMemOperand::MOStore, isa_config_.word_length,
      llvm::Align(isa_config_.word_length));
  llvm::BuildMI(*MBB, insert, llvm::DebugLoc(),
                TII_->get(isa_config_.store_opcode))
      .addReg(P2S_.at(riscv_common::k0))
      .addReg(base)
      .addImm(displacement)
      .addMemOperand(memory);
}

void RISCVDmr::emitPointerDeltaUpdates() {
  auto emit = [&](llvm::MachineBasicBlock *MBB,
                  llvm::MachineBasicBlock::iterator insert,
                  const PointerDeltaUpdates &updates) {
    for (const auto &update : updates) {
      // In-place pointer arithmetic preserves this location's expectation.
      if (update.second.kind == PointerOrigin::Kind::Runtime &&
          update.second.index == update.first)
        continue;
      loadPointerDelta(MBB, insert, update.second);
      storePointerDelta(MBB, insert, update.first);
      llvm::BuildMI(*MBB, insert, llvm::DebugLoc(),
                    TII_->get(llvm::RISCV::ADDI), P2S_.at(riscv_common::k0))
          .addReg(riscv_common::k0)
          .addImm(0);
    }
  };
  if (!pointer_delta_entry_.empty()) {
    auto insert = entry_bb_->end();
    for (auto &MI : *entry_bb_)
      if (MI.getFlag(llvm::MachineInstr::FrameSetup) &&
          MI.getOpcode() == llvm::RISCV::ADDI && MI.getNumOperands() >= 3 &&
          MI.getOperand(0).isReg() &&
          MI.getOperand(0).getReg() == riscv_common::kFP)
        insert = std::next(MI.getIterator());
    if (insert == entry_bb_->end())
      llvm::report_fatal_error("COMPAS: pointer provenance requires FP setup");
    emit(entry_bb_, insert, pointer_delta_entry_);
  }
  for (const auto &update : pointer_delta_updates_)
    if (!dynamic_sp_origins_.count(update.first))
      emit(update.first->getParent(), std::next(update.first->getIterator()),
           update.second);
}

void RISCVDmr::checkFrameAddress(llvm::MachineInstr *MI, llvm::Register reg,
                                 PointerOrigin origin) {
  const auto scratch = P2S_.at(riscv_common::k0);
  if (origin.kind == PointerOrigin::Kind::Frame) {
    addOffset(*MI->getParent(), MI->getIterator(), *TII_, scratch, reg,
              shadow_frame_offset_, MI->getDebugLoc());
  } else {
    if (MI->isCall() && TII_->isTailCall(*MI))
      llvm::report_fatal_error(
          "COMPAS: forwarded EDDI pointers require a returning call");
    loadPointerDelta(MI->getParent(), MI->getIterator(), origin);
    llvm::BuildMI(*MI->getParent(), MI->getIterator(), MI->getDebugLoc(),
                  TII_->get(llvm::RISCV::ADD), scratch)
        .addReg(reg)
        .addReg(scratch);
  }
  llvm::BuildMI(*MI->getParent(), MI->getIterator(), MI->getDebugLoc(),
                TII_->get(llvm::RISCV::BNE))
      .addReg(scratch)
      .addReg(P2S_.at(reg))
      .addMBB(err_bb_);
  llvm::BuildMI(*MI->getParent(), MI->getIterator(), MI->getDebugLoc(),
                TII_->get(llvm::RISCV::ADDI), scratch)
      .addReg(riscv_common::k0)
      .addImm(0);
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
           MI->getOperand(0).isSymbol())) { //[joh]: inline fence.i also
                                            // maystore #ifdef DBG
        llvm::outs()
            << "WARNING:" << *MI
            << "RISCVDmr::protectStores(): skip inline assembly and volatiles"
               "instructions -- needs fix\n";
// #end
#ifdef SWITCH_VOLATILE
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
#endif // ifdef SWITCH_VOLATILE
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

        // [joh]: change MI prim to shadow (data* -> addr*)
        bool src_is_zero = MI->getOperand(0).getReg() == riscv_common::k0;
        if (src_is_zero) {
          MI->getOperand(0).setReg(shadow_zero);
          MI->getOperand(1).setReg(P2S_.at(addr_reg));
        }

        auto si{MF_->CloneMachineInstr(MI)};
        if (!src_is_zero) {
          si->getOperand(1).setReg(P2S_.at(addr_reg));
        } else {
          // [joh]: load back from primary addr
          si->getOperand(1).setReg(addr_reg);
        }
        si->setDesc(TII_->get(LBStore2Load_.at(opcode)));
        // The clone is now a load, with a defined result and an independent
        // memory access through the other register bank. Store operand flags
        // and primary-pointer alias metadata do not describe this access.
        if (si->getOperand(0).isUse())
          si->getOperand(0).setIsKill(false);
        si->getOperand(0).setIsDef(true);
        si->getOperand(0).setIsDead(false);
        si->getOperand(0).setIsUndef(false);
        llvm::SmallVector<llvm::MachineMemOperand *, 2> memory;
        for (const auto *operand : MI->memoperands())
          memory.push_back(MF_->getMachineMemOperand(
              llvm::MachinePointerInfo(), llvm::MachineMemOperand::MOLoad,
              operand->getSize(), operand->getAlign()));
        si->setMemRefs(*MF_, memory);
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

            auto mi_builder{llvm::BuildMI(*MBB, insert, DLL,
                                          TII_->get(llvm::RISCV::XOR),
                                          shadow_zero)
                                .addReg(shadow_zero)
                                .addReg(P2S_.at(data_reg))};
            loadbacks_.emplace(mi_builder.getInstr());
            llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::SLLI),
                          shadow_zero)
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
        // An incoming s0 is opaque caller context. Its shadow can point into
        // the caller's separate frame, whose size is unknown here. Preserve
        // both values verbatim; equality is only valid for ordinary data.
        auto address = frame_address_stores_.find(MI);
        if (address != frame_address_stores_.end())
          checkFrameAddress(MI, data_operand, address->second);
        else if (!savesIncomingFramePointer(*MI, isa_config_.store_opcode))
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
      useIndependentShadowMemory(*MF_, *si);
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
    auto isRelocatedLoadImmRISCV = [](const llvm::MachineInstr &MI) -> bool {
      auto isRISCVRelocatedOffsetMO =
          [](const llvm::MachineOperand &MO) -> bool {
        if (!(MO.isGlobal() || MO.isSymbol() || MO.isCPI() ||
              MO.isBlockAddress() || MO.isJTI()))
          return false;

        unsigned TF = MO.getTargetFlags();

        // %lo(sym)(base)
        if (TF == llvm::RISCVII::MO_LO)
          return true;

        // Other common RISC-V relocations: %pcrel_hi(sym), %pcrel_lo(label)
        if (TF == llvm::RISCVII::MO_PCREL_HI ||
            TF == llvm::RISCVII::MO_PCREL_LO)
          return true;

        return false;
      };
      // For real loads/stores, op2 is the offset. (Pseudo-instructions may
      // differ.)
      if (MI.getNumOperands() < 3)
        return false;

      const llvm::MachineOperand &Off = MI.getOperand(2);
      return isRISCVRelocatedOffsetMO(Off);
    };

    for (const auto &MI : loads_) {
      if (isRelocatedLoadImmRISCV(*MI)) {
        for (const auto &op : MI->operands()) {
          if (op.isReg() && op.isDef()) {
            // trivial. Duplicating loads is better, but duplicated relocate
            // automatically regresses to same GP reg instead of shadow(GP)...
            moveIntoShadow(MI->getParent(), std::next(MI->getIterator()),
                           op.getReg(), P2S_.at(op.getReg()));
            // MI->getParent()->insertAfter(MI, genShadowFromPrimary(MI));
            break;
          }
        }
        continue;
      }
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
    llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::ADDI), rs)
        .addReg(rp)
        .addImm(0);
  } else if (riscv_common::getRegType(rp) == riscv_common::RegType::FS) {
    llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::FSGNJ_S), rs)
        .addReg(rp)
        .addReg(rp);
  } else if (riscv_common::getRegType(rp) == riscv_common::RegType::FD) {
    llvm::BuildMI(*MBB, insert, DLL, TII_->get(llvm::RISCV::FSGNJ_D), rs)
        .addReg(rp)
        .addReg(rp);
  } else if (riscv_common::getRegType(rp) == riscv_common::RegType::FH) {
    assert(0 && "TODO");
  }
}

bool RISCVDmr::is_func_dmr(const std::string &func_name) {
  return (riscv_common::inCSString(llvm::cl::enable_nzdc, func_name) ||
          riscv_common::inCSString(llvm::cl::enable_nzdc_nemesis, func_name) ||
          riscv_common::inCSString(llvm::cl::enable_nzdc_nemesec, func_name) ||
          riscv_common::inCSString(llvm::cl::enable_swift, func_name) ||
          riscv_common::inCSString(llvm::cl::enable_eddi, func_name))
             ? true
             : false;
}

void RISCVDmr::updateSelectiveCalls() {

  if (config_.sh == SelectiveHardening::SH0) {

  } else if (config_.sh == SelectiveHardening::SH1) {
    for (auto MI : user_calls_) {
      auto callee_func_name{getCalledFuncName(MI)};
      auto callee_is_dmr = is_func_dmr(callee_func_name);
      auto caller_is_dmr = is_func_dmr(fname_);
      const auto caller_state = riscv_common::signatureRegisters(*MF_);
      const auto callee_state =
          riscv_common::signatureRegisters(callee_func_name);
      auto signature_pair = [&](const auto &pair) {
        return llvm::is_contained(caller_state, pair.first) ||
               llvm::is_contained(caller_state, pair.second) ||
               llvm::is_contained(callee_state, pair.first) ||
               llvm::is_contained(callee_state, pair.second);
      };

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
          // The later CFP pass preserves the caller's actual state. Do not
          // overwrite it with an outer DMR snapshot after the CFP restore.
          // Callee-only state can still hold ordinary live caller context.
          for (const auto reg : caller_state)
            spill_regs.erase(reg);
#ifdef DBG
          for (const auto &sr : spill_regs) {
            llvm::outs() << "sr: x" << sr - llvm::RISCV::X0 << "\n";
          }
#endif // DBG
       // insert the spill segment
          std::vector<llvm::Register> sregs(spill_regs.begin(),
                                            spill_regs.end());
          auto insert = call_iter;
          // Outgoing stack arguments already occupy their ABI offsets here.
          // A returning call must preserve the caller without moving SP.
          // Late tail conversion still needs its legacy post-epilogue path.
          const bool fixed_call_frame = !TII_->isTailCall(*MI);
          if (fixed_call_frame)
            riscv_common::saveCallRegs(sregs, MBB, insert);
          else
            riscv_common::saveRegs(sregs, MBB, insert);
          // insert the default duplication segment, i.e., move all primaries
          // into their shadows
          for (const auto &regpair : P2S_) {
            if (signature_pair(regpair))
              continue;
            if (riscv_common::getRegType(regpair.first) ==
                    riscv_common::RegType::I ||
                isFullWidthFPRegister(
                    regpair.first, MF_->getSubtarget<llvm::RISCVSubtarget>())) {
              // Selective-call setup observes the complete monitor bank,
              // including architectural values not used by the source IR.
              // Declare those inputs explicitly instead of inferring them
              // from arbitrary undefined uses during liveness repair.
              if (!MRI_->isReserved(regpair.first) &&
                  !MF_->front().isLiveIn(regpair.first))
                MF_->front().addLiveIn(regpair.first);
              moveIntoShadow(MBB, insert, regpair.first, regpair.second);
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
          if (fixed_call_frame)
            riscv_common::loadCallRegs(sregs, MBB, insert);
          else
            riscv_common::loadRegs(sregs, MBB, insert);

          insert = MI->getIterator();
          ++insert;
          const auto ret_regs = getRetRegs(MI);
          const bool eddi_callee =
              riscv_common::inCSString(llvm::cl::enable_eddi, callee_func_name);
          for (const auto &regpair : P2S_) {
            if (signature_pair(regpair))
              continue;
            if (riscv_common::getRegType(regpair.first) ==
                riscv_common::RegType::I) {
              // An EDDI callee may leave distinct frame pointers in discarded
              // caller-clobbered temporaries. Only ABI-defined outputs can be
              // checked for equality here. Retain checks of return values,
              // the return address, architectural invariants, and all state
              // preserved by the call mask (which need not list zero or SP).
              bool clobbered = false;
              for (const auto &operand : MI->operands())
                if (operand.isRegMask() &&
                    operand.clobbersPhysReg(regpair.first))
                  clobbered = true;
              if (fixed_call_frame && eddi_callee && clobbered &&
                  regpair.first != riscv_common::k0 &&
                  regpair.first != riscv_common::kSP &&
                  regpair.first != riscv_common::kGP &&
                  regpair.first != riscv_common::kTP &&
                  regpair.first != riscv_common::kRA &&
                  !ret_regs.count(regpair.first))
                continue;
              llvm::BuildMI(*MBB, insert, MI->getDebugLoc(),
                            TII_->get(llvm::RISCV::BNE))
                  .addReg(regpair.first)
                  .addReg(regpair.second)
                  .addMBB(err_bb_);
            } else {
              // FIXME: only handle Base Integer Registers for now
            }
          }
          // Only ABI return values remain meaningful in caller-clobbered
          // primary FPRs. Use the actual return alias: a binary32 value can
          // be NaN-boxed in a wider physical register.
          for (const auto reg : ret_regs)
            if (riscv_common::getRegType(reg) != riscv_common::RegType::I)
              syncFPRegs(MBB, insert, reg, P2S_.at(reg));
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
          // The original compiler preserves live primaries across this
          // ordinary ABI call. Preserve their shadows when the call mask
          // permits clobbering the physical register's full enabled FLEN.
          for (const auto &pair : P2S_) {
            if (!isFullWidthFPRegister(
                    pair.first, MF_->getSubtarget<llvm::RISCVSubtarget>()))
              continue;
            for (const auto &operand : MI->operands())
              if (operand.isRegMask() && operand.clobbersPhysReg(pair.second)) {
                spill_regs.emplace(pair.second);
                break;
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

          // The CFP pass preserves its actual runtime state immediately
          // around the call. An outer DMR restore must not overwrite it.
          for (const auto reg : riscv_common::signatureRegisters(*MF_))
            spill_regs.erase(reg);

          std::vector<llvm::Register> sregs(spill_regs.begin(),
                                            spill_regs.end());

          const bool fixed_call_frame = !TII_->isTailCall(*MI);
          if (fixed_call_frame) {
            riscv_common::saveCallRegs(sregs, MBB, MI->getIterator());
          } else if (use_shadow_for_stack_ops_) {
            riscv_common::saveRegs(sregs, MBB, MI->getIterator(),
                                   P2S_.at(riscv_common::kSP));

          } else {
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
          if (fixed_call_frame) {
            riscv_common::loadCallRegs(sregs, MBB, insert);
          } else if (use_shadow_for_stack_ops_) {
            riscv_common::loadRegs(sregs, MBB, insert,
                                   P2S_.at(riscv_common::kSP));
          } else {
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

  // Both calls use the original outgoing ABI area. Keep the caller snapshot
  // separate from the first call's results; neither snapshot may move SP.
  for (auto *MI : lib_calls_) {
    if (config_.pslc == ProtectStrategyLibCall::LC1 && TII_->isTailCall(*MI))
      continue; // Late tail preservation remains a separate calling contract.

    const auto ret_regs = getRetRegs(MI);
    const auto arg_regs = getArgRegs(MI);
    auto *MBB = MI->getParent();
    const auto after = std::next(MI->getIterator());
    const auto callee = getCalledFuncName(MI);
    const auto &subtarget = MF_->getSubtarget<llvm::RISCVSubtarget>();
    const bool eddi = riscv_common::inCSString(llvm::cl::enable_eddi, fname_);
    auto clobbered = [&](llvm::Register reg) {
      for (const auto &operand : MI->operands())
        if (operand.isRegMask() && operand.clobbersPhysReg(reg))
          return true;
      return false;
    };

    RegSetType preserved;
    if (!eddi)
      // Complete-bank boundary checks also observe discarded primary GPRs.
      for (unsigned reg = llvm::RISCV::X3; reg <= llvm::RISCV::X31; ++reg)
        if (!callee_saved_regs_.count(reg))
          preserved.insert(reg);
    for (const auto &pair : P2S_)
      if ((riscv_common::getRegType(pair.first) == riscv_common::RegType::I ||
           isFullWidthFPRegister(pair.first, subtarget)) &&
          clobbered(pair.second))
        preserved.insert(pair.second);
    // The compiler already preserves live primaries around an ordinary ABI
    // call. Only its actual result registers must survive the outer reload.
    for (auto iterator = preserved.begin(); iterator != preserved.end();) {
      bool result = false;
      for (const auto reg : ret_regs)
        result |= TRI_->regsOverlap(*iterator, reg);
      if (result)
        iterator = preserved.erase(iterator);
      else
        ++iterator;
    }
    if (llvm::cl::enable_repair)
      preserved.clear();
    for (const auto reg : riscv_common::signatureRegisters(*MF_))
      preserved.erase(reg);
    const std::vector<llvm::Register> caller_regs(preserved.begin(),
                                                  preserved.end());
    riscv_common::saveCallRegs(caller_regs, MBB, MI->getIterator());

    if (config_.pslc == ProtectStrategyLibCall::LC0 ||
        (config_.pslc == ProtectStrategyLibCall::LC1 &&
         !knownLibcalls2Duplicable_.at(callee))) {
      if (config_.pslc != ProtectStrategyLibCall::LC0)
        for (const auto reg : arg_regs) {
          if (riscv_common::getRegType(reg) == riscv_common::RegType::I)
            llvm::BuildMI(*MBB, MI->getIterator(), MI->getDebugLoc(),
                          TII_->get(llvm::RISCV::BNE))
                .addReg(reg)
                .addReg(P2S_.at(reg))
                .addMBB(err_bb_);
          else
            syncFPRegs(MBB, MI->getIterator(), reg, P2S_.at(reg));
        }
      riscv_common::loadCallRegs(caller_regs, MBB, after);
      handleLibCallLC0(MI, after);
      continue;
    }
    if (config_.pslc != ProtectStrategyLibCall::LC1)
      llvm::report_fatal_error("COMPAS: unsupported libcall strategy");

    // Ordinary calls leave non-result arguments undefined in their regmask.
    // Save only defined results, using exactly the same layout when reloading.
    const std::vector<llvm::Register> results(ret_regs.begin(), ret_regs.end());
    riscv_common::saveCallRegs(results, MBB, after,
                              riscv_common::CallFrameBank::Libcall);
    // The first call can clobber shadow arguments, especially caller-clobbered
    // FPRs. Recover their pre-call values before making the duplicate call.
    riscv_common::loadCallRegs(caller_regs, MBB, after);
    for (const auto reg : arg_regs)
      moveIntoShadow(MBB, after, P2S_.at(reg), reg);
    MBB->insert(after, MF_->CloneMachineInstr(MI));
    riscv_common::loadCallRegs(caller_regs, MBB, after);
    // Retain the original result in primary and the independent result in
    // shadow. Copy the duplicate before reloading the first call's result.
    for (const auto reg : ret_regs)
      moveIntoShadow(MBB, after, reg, P2S_.at(reg));
    riscv_common::loadCallRegs(results, MBB, after,
                              riscv_common::CallFrameBank::Libcall);
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
        if (mayReceiveSignatureState(r))
          continue;

        // UC3 checks the incoming monitor bank even for registers which are
        // not ordinary arguments. These are intentional convention inputs.
        if (!MRI_->isReserved(r) && !MF_->front().isLiveIn(r))
          MF_->front().addLiveIn(r);
        llvm::BuildMI(entry_BB, insert, insert->getDebugLoc(),
                      TII_->get(llvm::RISCV::BNE))
            .addReg(r)
            .addReg(P2S_.at(r))
            .addMBB(err_bb_);
      }

      // TODO: compare FP reg files at start of func
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
                      TII_->get(llvm::RISCV::ADDI), P2S_.at(r))
            .addReg(r)
            .addImm(0);
      }

      // TODO: initialize the FP shadow bank when FP entry checks are added.
    }
  } else if (config_.psuc == ProtectStrategyUserCall::UC1) {

    for (const auto &MI : user_calls_) {
      auto arg_regs{getArgRegs(MI)};

      for (llvm::Register reg : arg_regs) {
        if (riscv_common::getRegType(reg) != riscv_common::RegType::I) {
          syncFPRegs(MI->getParent(), MI->getIterator(), reg, P2S_.at(reg));
          continue;
        }
        auto stack_args = stack_address_call_args_.find(MI);
        if (stack_args != stack_address_call_args_.end() &&
            stack_args->second.count(reg)) {
          checkFrameAddress(MI, reg, stack_args->second.at(reg));
        } else {
          llvm::BuildMI(*MI->getParent(), MI->getIterator(), MI->getDebugLoc(),
                        TII_->get(llvm::RISCV::BNE))
              .addReg(reg)
              .addReg(P2S_.at(reg))
              .addMBB(err_bb_);
        }
      }

      if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_) &&
          !MF_->getFrameInfo().hasVarSizedObjects()) {
        addOffset(*MI->getParent(), std::next(MI->getIterator()), *TII_,
                  P2S_.at(riscv_common::kSP), riscv_common::kSP,
                  shadow_frame_offset_, MI->getDebugLoc());
      }
    }
  } else {
    assert(0 && "this protect-strategy for user-calls is not supported yet");
  }

  // ----------
  // now handling recursive indirect calls (jalr)
  // ----------
  for (auto &MI : indirect_calls_) {
    if (riscv_common::inCSString(llvm::cl::enable_eddi, fname_) &&
        !MF_->getFrameInfo().hasVarSizedObjects()) {
      addOffset(*MI->getParent(), std::next(MI->getIterator()), *TII_,
                P2S_.at(riscv_common::kSP), riscv_common::kSP,
                shadow_frame_offset_, MI->getDebugLoc());
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
                      TII_->get(llvm::RISCV::PseudoBR))
            .addMBB(err_bb_);

        // NOTE: due to nemesis it can happen that the original successor chain
        //       is being broken
        //       so if we encounter an unconditional jump to previously
        //       chained block then we have to reestablish the link
        // TODO: this workaround only works if the unconditional branch follows
        //       a conditional branch (which led to nemesis blocks)
        if (!MI->getParent()->isSuccessor(MI->getOperand(0).getMBB()))
          MI->getParent()->addSuccessor(MI->getOperand(0).getMBB());
      } else if (MI->isConditionalBranch()) {
        auto MBB{MI->getParent()};
        assert(MI->getOperand(2).isMBB() && "this branch is odd!");
        auto taken_BB{MI->getOperand(2).getMBB()};

        if (err_bb_ == taken_BB) {
          continue; // do not duplicate error existing dmr checks implemented
                    // with conditional branching
        }

        llvm::MachineInstr *si;

        // fall-through path dup

        llvm::MachineBasicBlock *nottaken_BB = MBB->getFallThrough();
        if (nottaken_BB == nullptr) {
          // no fallthrough found. Most likely we have a
          // "b<cond> <>, taken \\ j nottaken" situation here, where the
          // unconditional is part of the MBB, i.e. LLVM IR did not terminate BB
          // with conditional branch. Solution: splice BB here at conditional!
          llvm::outs() << "No fallthrough successor found for MBB[" << MBB
                       << "]: " << *MBB << "\n";
          nottaken_BB = splitConditionalBranch(*MI);
        }
        assert(nottaken_BB != nullptr && taken_BB != nullptr &&
               "Conditional branch is odd!");

        llvm::outs() //<< "split MBB into \n"
            << "\n* not-taken[" << nottaken_BB << "]:" << *nottaken_BB
            << "\n* taken[" << taken_BB << "]:" << *taken_BB << " of MBB["
            << MBB << "]: " << *MBB << "\n";

        auto nemesis_nottaken_BB{MF_->CreateMachineBasicBlock()};

        llvm::MachineFunction::iterator mbb;
        for (mbb = MF_->begin(); mbb != MF_->end(); ++mbb) {
          if (&(*mbb) == nottaken_BB)
            break;
        }
        MF_->insert(mbb, nemesis_nottaken_BB);

        si = MF_->CloneMachineInstr(MI);
        for (auto &o : si->operands()) {
          if (o.isReg()) {
            o.setReg(P2S_.at(o.getReg()));
          }
        }

        if (MBB->isSuccessor(nottaken_BB)) {
          MBB->replaceSuccessor(nottaken_BB, nemesis_nottaken_BB);
          // MBB->ReplaceUsesOfBlockWith(nottaken_BB, nemesis_nottaken_BB);
        } else {
          llvm::outs() << "not taken[" << nottaken_BB << "]:" << *nottaken_BB
                       << "not a successor of MBB[" << MBB << "]: " << *MBB
                       << "\n";
          assert(false && "Not a sucessor!");
        }

        nemesis_nottaken_BB->addSuccessor(nottaken_BB);
        nemesis_bbs_.emplace(nemesis_nottaken_BB);

        si->getOperand(2).setMBB(err_bb_);
        nemesis_nottaken_BB->push_back(si);

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
                      si->getDebugLoc(), TII_->get(llvm::RISCV::PseudoBR))
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
                      TII_->get(llvm::RISCV::PseudoBR))
            .addMBB(err_bb_);
      } else if (MI->isConditionalBranch()) {
        auto MBB{MI->getParent()};

        assert(MI->getOperand(2).isMBB() && "this branch is odd!");
        auto taken_BB{MI->getOperand(2).getMBB()};

        auto nottaken_BB{MBB->getFallThrough()};
        if (nottaken_BB == nullptr) {
          // no fallthrough found. Most likely we have a
          // "b<cond> <>, taken \\ j nottaken" situation here, where the
          // unconditional is part of the MBB, i.e. LLVM IR did not terminate BB
          // with conditional branch. Solution: splice BB here at conditional!
          llvm::outs() << "No fallthrough successor found for MBB[" << MBB
                       << "]: " << *MBB << "\n";
          nottaken_BB = splitConditionalBranch(*MI);
        }
        assert(nottaken_BB && "this branch has no fallthrough!");

        llvm::BuildMI(*MBB, MBB->end(), MI->getDebugLoc(),
                      TII_->get(llvm::RISCV::PseudoBR))
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
                      TII_->get(llvm::RISCV::PseudoBR))
            .addMBB(nottaken_BB); // we need to jump back to fallthrough
        insert = MI->getIterator();
        llvm::BuildMI(*MI->getParent(), ++insert, MI->getDebugLoc(),
                      TII_->get(llvm::RISCV::PseudoBR))
            .addMBB(nemesec_nottaken_BB);

        // taken path duplication
        auto nemesis_taken_BB{MF_->CreateMachineBasicBlock()};
        MF_->insert(MF_->end(), nemesis_taken_BB);
        MBB->ReplaceUsesOfBlockWith(
            taken_BB, nemesis_taken_BB); // maybe instead replaceSuccessor()
        nemesis_taken_BB->addSuccessor(taken_BB);
        nemesis_bbs_.emplace(nemesis_taken_BB);

        si = MF_->CloneMachineInstr(si);
        si->getOperand(2).setMBB(taken_BB);
        MI->getOperand(2).setMBB(nemesis_taken_BB);
        nemesis_taken_BB->insert(nemesis_taken_BB->begin(), si);
        llvm::BuildMI(*nemesis_taken_BB, nemesis_taken_BB->end(),
                      si->getDebugLoc(), TII_->get(llvm::RISCV::PseudoBR))
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

  const auto DLL = MF_->front().empty() ? llvm::DebugLoc()
                                        : MF_->front().front().getDebugLoc();

  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED1) {
    // storing '1' to addr : (0xfff0 = 0x10000 - 0x10):
    // lui t1, 16 -> makes t1 = 0x10000
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(llvm::RISCV::LUI), llvm::RISCV::X6)
        .addImm(16);
    // addi t2, zero, 1 -> makes t2 = 1
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(llvm::RISCV::ADDI), llvm::RISCV::X7)
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
                  TII_->get(llvm::RISCV::ADDI), llvm::RISCV::X17) // a7
        .addReg(llvm::RISCV::X0)                                  // zero
        .addImm(93);
    // storing '-512' to a0, aka exit return value when ecall forces newlib sys
    // exit:
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(llvm::RISCV::ADDI), llvm::RISCV::X10) // a0
        .addReg(llvm::RISCV::X0)                                  // zero
        .addImm(-512);
    // invoke 'ecall'
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(llvm::RISCV::ECALL))
        .addReg(llvm::RISCV::X17, llvm::RegState::Implicit)
        .addReg(llvm::RISCV::X10, llvm::RegState::Implicit);
  }
  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED1 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED3) {

    // to encode the error-BB in order to make it a label so as to be able to
    // jump to it from anywhere in asm
    err_bb_->addSuccessor(err_bb_);
  }

  if (config_.eds == riscv_common::ErrorDetectionStrategy::ED0 ||
      config_.eds == riscv_common::ErrorDetectionStrategy::ED3) {
    // keep on repeating this errBB as we dont want to execute code now
    llvm::BuildMI(*err_bb_, std::end(*err_bb_), DLL,
                  TII_->get(llvm::RISCV::PseudoBR))
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
                          TII_->get(llvm::RISCV::ADDI), LiveP2S[r])
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
                                TII_->get(llvm::RISCV::ADDI),
                                P2S_.at(riscv_common::kSP))
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
                            TII_->get(llvm::RISCV::ADDI),
                            LiveP2S[riscv_common::kSP])
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
                          TII_->get(llvm::RISCV::ADDI), P2S_.at(r))
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
                      TII_->get(llvm::RISCV::PseudoBR))
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
                        TII_->get(llvm::RISCV::XOR), P2S_.at(riscv_common::k0))
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
