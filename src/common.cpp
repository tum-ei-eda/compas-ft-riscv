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
#include <map>
#include <set>
#include <sstream>

#include "RISCVFrameLowering.h"
#include "RISCVInstrInfo.h"
#include "RISCVMachineFunctionInfo.h"
#include "RISCVSubtarget.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"

namespace {

void remove_operand(llvm::MachineInstr &MI, unsigned index) {
#if LLVM_VERSION_MAJOR < 15
  MI.RemoveOperand(index);
#else
  MI.removeOperand(index);
#endif
}

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

void riscv_common::normalizeControlFlow(llvm::MachineFunction &MF) {
  if (MF.empty())
    return;
  const auto *tii = MF.getSubtarget().getInstrInfo();

  // Preserve PHI values through splits by remembering the original incoming
  // block of every new continuation. The normal post-RA pipeline has no PHIs,
  // but the standalone factories can also be used in machine-IR pipelines.
  struct PhiInputs {
    llvm::MachineInstr *phi;
    std::map<llvm::MachineBasicBlock *, llvm::MachineOperand> values;
  };
  std::vector<PhiInputs> phis;
  std::map<llvm::MachineBasicBlock *, llvm::MachineBasicBlock *> origins;
  std::map<llvm::MachineBasicBlock *, std::vector<llvm::MachineBasicBlock *>>
      original_successors;
  for (auto &MBB : MF) {
    origins.emplace(&MBB, &MBB);
    original_successors.emplace(&MBB, std::vector<llvm::MachineBasicBlock *>(
                                          MBB.succ_begin(), MBB.succ_end()));
    for (auto &phi : MBB.phis()) {
      PhiInputs inputs{&phi, {}};
      for (unsigned i = 1; i + 1 < phi.getNumOperands(); i += 2)
        inputs.values.emplace(phi.getOperand(i + 1).getMBB(),
                              phi.getOperand(i));
      phis.push_back(std::move(inputs));
    }
    for (auto &MI : MBB) {
      // A no-link local transfer is a branch, not a call. Keep the original
      // instruction's symbols and flags while using LLVM's branch descriptor.
      if (MI.getOpcode() == llvm::RISCV::JAL && MI.getNumOperands() >= 2 &&
          MI.getOperand(0).isReg() && MI.getOperand(0).getReg() == k0 &&
          MI.getOperand(1).isMBB()) {
        MI.setDesc(tii->get(llvm::RISCV::PseudoBR));
        remove_operand(MI, 0);
      }
    }
  }

  // A label changes no emitted instruction order. Split after each terminator
  // so checks have ordinary fallthrough blocks. Also retain instructions after
  // barriers: unreachable trap jumps deliberately detect skipped branches.
  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      if ((!MI.isTerminator() && !MI.isBarrier()) ||
          std::next(MI.getIterator()) == MBB.end())
        continue;
      auto *continuation = MBB.splitAt(MI, false);
      origins.emplace(continuation, origins.at(&MBB));
      break;
    }
  }

  // Reconstruct nominal edges rather than inheriting duplicate or unreachable
  // edges from instrumentation. Preserve existing destinations for indirect
  // branches, inlineasm_br and exceptional control flow.
  for (auto &MBB : MF) {
    std::set<llvm::MachineBasicBlock *> targets;
    const auto &old_targets = original_successors.at(origins.at(&MBB));
    for (auto *successor : old_targets)
      if (successor->isEHPad())
        targets.insert(successor);

    bool falls_through = true;
    for (const auto &MI : MBB) {
      if (MI.isIndirectBranch() ||
          MI.getOpcode() == llvm::TargetOpcode::INLINEASM_BR)
        targets.insert(old_targets.begin(), old_targets.end());
      if (MI.isBranch() || MI.getOpcode() == llvm::TargetOpcode::INLINEASM_BR)
        for (const auto &operand : MI.operands())
          if (operand.isMBB())
            targets.insert(operand.getMBB());
      if (MI.isBarrier() || MI.isReturn() || tii->isTailCall(MI)) {
        falls_through = false;
        break;
      }
    }
    if (falls_through && MBB.getNextNode())
      targets.insert(MBB.getNextNode());

    while (!MBB.succ_empty())
      MBB.removeSuccessor(MBB.succ_begin());
    for (auto *target : targets)
      MBB.addSuccessor(target);
    MBB.normalizeSuccProbs();
  }

  for (auto &inputs : phis) {
    auto &phi = *inputs.phi;
    while (phi.getNumOperands() > 1)
      remove_operand(phi, phi.getNumOperands() - 1);
    for (auto *predecessor : phi.getParent()->predecessors()) {
      const auto value = inputs.values.find(origins.at(predecessor));
      if (value == inputs.values.end())
        llvm::report_fatal_error("COMPAS: cannot repair PHI after CFG split");
      phi.addOperand(MF, value->second);
      phi.addOperand(MF, llvm::MachineOperand::CreateMBB(predecessor));
    }
  }

  if (!MF.getRegInfo().tracksLiveness())
    return;

  // Solve from an empty state to eliminate stale loop live-ins. Entry keeps
  // only its declared ABI and monitor inputs: inferring new function inputs
  // from uses here would conceal genuinely missing register definitions.
  std::vector<llvm::MachineBasicBlock::RegisterMaskPair> entry_liveins(
      MF.front().livein_begin(), MF.front().livein_end());
  for (auto &MBB : MF)
    MBB.clearLiveIns();
  for (const auto &livein : entry_liveins)
    MF.front().addLiveIn(livein);

  bool changed;
  do {
    changed = false;
    for (auto I = MF.rbegin(), E = MF.rend(); I != E; ++I) {
      auto &MBB = *I;
      std::vector<llvm::MachineBasicBlock::RegisterMaskPair> previous(
          MBB.livein_begin(), MBB.livein_end());
      llvm::recomputeLiveIns(MBB);
      if (&MBB == &MF.front()) {
        MBB.clearLiveIns();
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

  for (auto &MBB : MF)
    llvm::recomputeLivenessFlags(MBB);
}

bool riscv_common::isDmrFunction(const std::string &name) {
  return inCSString(llvm::cl::enable_eddi, name) ||
         inCSString(llvm::cl::enable_swift, name) ||
         inCSString(llvm::cl::enable_nzdc, name) ||
         inCSString(llvm::cl::enable_nzdc_nemesis, name) ||
         inCSString(llvm::cl::enable_nzdc_nemesec, name);
}

bool riscv_common::usesPointerProvenance(const llvm::MachineFunction &MF) {
  if (!inCSString(llvm::cl::enable_eddi, std::string{MF.getName()}))
    return false;
  if (MF.getFrameInfo().hasVarSizedObjects())
    return true;

  // Machine blocks and spill objects can change during register allocation.
  // Use the unchanged IR to choose a conservative candidate before reserving
  // FP, then make the same choice when allocating its fixed bank after RA.
  const auto &function = MF.getFunction();
  bool has_call = false;
  bool can_merge = false;
  for (const auto &block : function)
    for (const auto &instruction : block) {
      can_merge |= instruction.getType()->isPointerTy() &&
                   (llvm::isa<llvm::PHINode>(instruction) ||
                    llvm::isa<llvm::SelectInst>(instruction));
      if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
        const auto *callee = call->getCalledFunction();
        if (!call->isInlineAsm() && (!callee || !callee->isIntrinsic()))
          has_call = true;
      }
    }
  return has_call && can_merge;
}

unsigned
riscv_common::pointerProvenanceSlots(const llvm::MachineFunction &MF) {
  if (!usesPointerProvenance(MF))
    return 0;
  // Register slots use architectural x0..x31 numbering. Spill metadata uses
  // 32 + FI, including holes in the frame-index space. Fixed objects have
  // negative indices and the immutable incoming-pointer prefix is separate.
  return 32 + std::max(0, MF.getFrameInfo().getObjectIndexEnd()) +
         (MF.getFrameInfo().hasVarSizedObjects() ? 3 : 0);
}

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

namespace {

void access_call_regs(const std::vector<llvm::Register> &regs,
                      llvm::MachineBasicBlock *MBB,
                      llvm::MachineBasicBlock::iterator insert, bool restore) {
  if (regs.empty())
    return;

  auto &MF = *MBB->getParent();
  const int frame_index = MF.getInfo<llvm::RISCVMachineFunctionInfo>()
                              ->getCompasDmrCallFrameIndex();
  if (frame_index >= 0)
    llvm::report_fatal_error("COMPAS: DMR call frame was not prepared");
  const auto frame = spill_frame(regs, MF);
  if (frame.size > MF.getFrameInfo().getObjectSize(frame_index))
    llvm::report_fatal_error("COMPAS: DMR call frame is too small");

  const auto &subtarget = MF.getSubtarget<llvm::RISCVSubtarget>();
  const auto *tii = subtarget.getInstrInfo();
  const auto DL = MBB->front().getDebugLoc();
  const riscv_common::ISAConfig isa_config{MF};
  llvm::Register frame_reg;
  const auto offset = subtarget.getFrameLowering()->getFrameIndexReference(
      MF, frame_index, frame_reg);
  if (offset.getScalable() || frame_reg != riscv_common::kFP)
    llvm::report_fatal_error("COMPAS: DMR call frame requires a stable FP");
  const int64_t displacement = offset.getFixed();
  const bool large_offset =
      !llvm::isInt<12>(displacement) ||
      !llvm::isInt<12>(displacement + frame.slots.back().offset);

  auto access = [&](const SpillSlot &slot, llvm::Register value,
                    llvm::Register base, int64_t base_offset) {
    const unsigned memory_width =
        riscv_common::getRegType(slot.reg) == riscv_common::RegType::FS
            ? 4
            : slot.width;
    auto *memory = MF.getMachineMemOperand(
        llvm::MachinePointerInfo::getFixedStack(MF, frame_index, slot.offset),
        restore ? llvm::MachineMemOperand::MOLoad
                : llvm::MachineMemOperand::MOStore,
        memory_width, llvm::Align(memory_width));
    llvm::BuildMI(*MBB, insert, DL,
                  tii->get(restore ? slot.load_opcode : slot.store_opcode))
        .addReg(value, restore ? llvm::RegState::Define : 0)
        .addReg(base)
        .addImm(base_offset + slot.offset)
        .addMemOperand(memory);
  };
  if (!large_offset) {
    for (const auto &slot : frame.slots)
      access(slot, slot.reg, frame_reg, displacement);
    return;
  }

  // Normally fixed objects remain close to FP even in large or realigned
  // frames. An unusually large existing fixed area can still require address
  // materialization. Borrow registers that none of the signature passes own,
  // preserving their values and restoring SP before the actual call.
  const llvm::Register address{llvm::RISCV::X27};
  const llvm::Register buffer{llvm::RISCV::X7};
  const std::vector<llvm::Register> temporaries{address, buffer};
  const auto temporary_frame = spill_frame(temporaries, MF);
  riscv_common::saveRegs(temporaries, MBB, insert);
  tii->movImm(*MBB, insert, DL, address, displacement);
  llvm::BuildMI(*MBB, insert, DL, tii->get(llvm::RISCV::ADD), address)
      .addReg(frame_reg)
      .addReg(address);

  auto reload_temporary = [&](llvm::Register value, unsigned index) {
    llvm::BuildMI(*MBB, insert, DL, tii->get(isa_config.load_opcode), value)
        .addReg(riscv_common::kSP)
        .addImm(temporary_frame.slots[index].offset);
  };
  if (!restore) {
    for (const auto &slot : frame.slots) {
      llvm::Register value = slot.reg;
      if (value == address || value == buffer) {
        reload_temporary(buffer, value == address ? 0 : 1);
        value = buffer;
      }
      access(slot, value, address, 0);
    }
    riscv_common::loadRegs(temporaries, MBB, insert);
    return;
  }

  bool restore_address = false, restore_buffer = false;
  for (const auto &slot : frame.slots) {
    if (slot.reg == address) {
      restore_address = true;
      continue; // Reload the address register after its final use.
    }
    restore_buffer |= slot.reg == buffer;
    access(slot, slot.reg, address, 0);
  }
  if (!restore_buffer)
    reload_temporary(buffer, 1);
  if (restore_address) {
    const auto slot = std::find_if(
        frame.slots.begin(), frame.slots.end(),
        [&](const SpillSlot &saved) { return saved.reg == address; });
    access(*slot, address, address, 0);
  } else {
    reload_temporary(address, 0);
  }
  llvm::BuildMI(*MBB, insert, DL, tii->get(llvm::RISCV::ADDI),
                riscv_common::kSP)
      .addReg(riscv_common::kSP)
      .addImm(temporary_frame.size);
}

} // namespace

void riscv_common::saveCallRegs(const std::vector<llvm::Register> &regs,
                                llvm::MachineBasicBlock *MBB,
                                llvm::MachineBasicBlock::iterator insert) {
  access_call_regs(regs, MBB, insert, false);
}

void riscv_common::loadCallRegs(const std::vector<llvm::Register> &regs,
                                llvm::MachineBasicBlock *MBB,
                                llvm::MachineBasicBlock::iterator insert) {
  access_call_regs(regs, MBB, insert, true);
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
