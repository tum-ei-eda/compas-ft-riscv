/*
 * Copyright 2026 Chair of EDA, Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "RISCV.h"
#include "RISCVInstrInfo.h"
#include "RISCVMachineFunctionInfo.h"
#include "RISCVSubtarget.h"
#include "common.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/PseudoSourceValue.h"
#include "llvm/Support/MathExtras.h"

#include <algorithm>

namespace {

bool needs_signature_frame(const llvm::MachineFunction &MF) {
  if (riscv_common::signatureRegisters(MF).empty())
    return false;

  for (const auto &MBB : MF)
    for (const auto &MI : MBB)
      // DMR can turn tails into returning calls. Ignore frame setup libcalls
      // introduced by PEI, which were absent when FP had to be reserved.
      if (MI.isCall() && !MI.getFlag(llvm::MachineInstr::FrameSetup))
        return true;
  return false;
}

bool needs_dmr_frame(const llvm::MachineFunction &MF) {
  const bool caller_dmr =
      riscv_common::isDmrFunction(std::string{MF.getName()});
  const bool base_pointer =
      riscv_common::usesDmrBasePointer(MF) &&
      !riscv_common::inCSString(llvm::cl::enable_eddi,
                                std::string{MF.getName()});
  const auto *tii = MF.getSubtarget<llvm::RISCVSubtarget>().getInstrInfo();
  for (const auto &MBB : MF)
    for (const auto &MI : MBB) {
      // LowerCall retains returning calls at selective boundaries before this
      // pass. Compatible tail calls do not need a selective caller snapshot.
      if (!MI.isCall() || MI.getFlag(llvm::MachineInstr::FrameSetup) ||
          tii->isTailCall(MI) || !MI.getNumOperands())
        continue;
      // REPAIR's live shadow locations differ from the canonical ABI bank.
      // Every returning call can overwrite them, including protected callees
      // and indirect targets which do not cross a selective boundary.
      if (caller_dmr && llvm::cl::enable_repair)
        return true;
      // The caller-owned BP pair must survive protected and ordinary calls,
      // including indirect calls whose target convention is unknown here.
      if (base_pointer)
        return true;
      const auto &callee = MI.getOperand(0);
      if (!callee.isGlobal() && !callee.isSymbol())
        continue;
      const std::string callee_name =
          callee.isGlobal() ? std::string{callee.getGlobal()->getName()}
                            : std::string{callee.getSymbolName()};
      if (caller_dmr != riscv_common::isDmrFunction(callee_name))
        return true;
    }
  return false;
}

bool needs_incoming_shadow_sp(const llvm::MachineFunction &MF) {
  if (!riscv_common::inCSString(llvm::cl::enable_eddi,
                                std::string{MF.getName()}))
    return false;

  const auto &frame = MF.getFrameInfo();
  for (const auto &MBB : MF)
    for (const auto &MI : MBB) {
      if (!MI.mayLoad())
        continue;
      for (const auto *memory : MI.memoperands()) {
        if (!memory->isLoad())
          continue;
        const auto *slot =
            llvm::dyn_cast_or_null<llvm::FixedStackPseudoSourceValue>(
                memory->getPseudoValue());
        // Formal stack arguments live at or above incoming SP. Negative
        // fixed objects also include register-varargs saves and CSI slots.
        if (slot && frame.isFixedObjectIndex(slot->getFrameIndex()) &&
            frame.getObjectOffset(slot->getFrameIndex()) >= 0)
          return true;
      }
    }
  return false;
}

bool needs_pointer_deltas(const llvm::MachineFunction &MF) {
  return riscv_common::inCSString(llvm::cl::enable_eddi,
                                  std::string{MF.getName()}) &&
         (riscv_common::incomingPointerDeltaSlots(MF) ||
          riscv_common::usesPointerProvenance(MF));
}

unsigned dmr_frame_size(const llvm::MachineFunction &MF) {
  const auto &subtarget = MF.getSubtarget<llvm::RISCVSubtarget>();
  const unsigned word_size = subtarget.is64Bit() ? 8 : 4;
  // SCC1 preserves live shadow registers; SCC2 preserves caller-clobbered
  // shadows around an ordinary ABI call. A narrower ABI can clobber the full
  // hardware FP view even when it preserves a subregister. Allow sixteen
  // physical FP slots and deduplicate aliases as spill_frame does.
  unsigned size =
      (riscv_common::isDmrFunction(std::string{MF.getName()}) ? 18 : 16) *
      word_size;
  if (subtarget.hasStdExtF())
    size += 16 * std::max(word_size, subtarget.hasStdExtD() ? 8u : 4u);
  // A protected caller can duplicate a libcall. Its outer monitor snapshot
  // and the first call's ABI arguments/results must remain independent.
  const unsigned repair_size = riscv_common::repairCallFrameSize(MF);
  return llvm::alignTo(size, 16) +
         (riscv_common::isDmrFunction(std::string{MF.getName()})
              ? riscv_common::kLibcallResultFrameSize
              : 0) +
         (riscv_common::usesDmrBasePointer(MF) &&
                  !riscv_common::inCSString(llvm::cl::enable_eddi,
                                            std::string{MF.getName()})
              ? riscv_common::kBasePointerCallFrameSize
              : 0) +
         repair_size +
         (repair_size ? 2 * riscv_common::kRepairResultFrameSize : 0);
}

class RISCVPrepareCallFrame : public llvm::MachineFunctionPass {
public:
  static char ID;

  RISCVPrepareCallFrame() : MachineFunctionPass(ID) {}

  llvm::StringRef getPassName() const override {
    return "Prepare COMPAS call preservation frame";
  }

  bool runOnMachineFunction(llvm::MachineFunction &MF) override {
    if (!needs_signature_frame(MF) && !needs_dmr_frame(MF) &&
        !needs_incoming_shadow_sp(MF) && !needs_pointer_deltas(MF))
      return false;
    auto &frame = MF.getFrameInfo();
    if (frame.isFrameAddressTaken())
      return false;
    // Reserve a stable base before register allocation. Signature state,
    // selective-call context and EDDI's incoming pointer state receive fixed
    // slots after CSI assignment.
    frame.setFrameAddressIsTaken(true);
    return true;
  }

  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override {
    AU.setPreservesCFG();
    MachineFunctionPass::getAnalysisUsage(AU);
  }
};

char RISCVPrepareCallFrame::ID = 0;

} // namespace

llvm::FunctionPass *llvm::createRISCVPrepareCallFrame() {
  return new RISCVPrepareCallFrame();
}

void llvm::reserveRISCVCompasCallFrame(llvm::MachineFunction &MF) {
  auto *info = MF.getInfo<llvm::RISCVMachineFunctionInfo>();
  const bool signature_frame =
      info->getCompasSignatureFrameIndex() >= 0 && needs_signature_frame(MF);
  const bool dmr_frame =
      info->getCompasDmrCallFrameIndex() >= 0 && needs_dmr_frame(MF);
  const bool incoming_shadow_sp =
      info->getCompasIncomingShadowSPFrameIndex() >= 0 &&
      needs_incoming_shadow_sp(MF);
  const bool pointer_deltas =
      info->getCompasPointerDeltaFrameIndex() >= 0 && needs_pointer_deltas(MF);
  if (!signature_frame && !dmr_frame && !incoming_shadow_sp && !pointer_deltas)
    return;

  auto &frame = MF.getFrameInfo();
  const unsigned word_size =
      MF.getSubtarget<llvm::RISCVSubtarget>().is64Bit() ? 8 : 4;
  uint64_t reserved = 0;
  for (int index = frame.getObjectIndexBegin(); index < 0; ++index) {
    const int64_t offset = frame.getObjectOffset(index);
    if (offset < 0)
      reserved = std::max(reserved, static_cast<uint64_t>(-offset));
  }
  // Save/restore libcalls use implicit CSI slots below incoming SP. Their size
  // is only recorded in emitPrologue, so derive it from the assigned indices.
  if (info->useSaveRestoreLibCalls(MF)) {
    uint64_t libcall_bytes = 0;
    for (const auto &saved : frame.getCalleeSavedInfo())
      if (saved.getFrameIdx() < 0)
        libcall_bytes =
            std::max(libcall_bytes,
                     static_cast<uint64_t>(-saved.getFrameIdx()) * word_size);
    reserved = std::max(reserved, llvm::alignTo(libcall_bytes, 16));
  }
  // Fixed objects remain FP-relative even when a realigned frame would address
  // ordinary local objects through SP. PEI includes this area in its layout.
  auto reserve = [&](unsigned slot_size, unsigned alignment) {
    reserved = llvm::alignTo(reserved + slot_size, alignment);
    return frame.CreateFixedObject(slot_size, -static_cast<int64_t>(reserved),
                                   false);
  };
  if (signature_frame)
    // CFCSS propagates both G and D; RASM/RACFED preserve one XLEN word.
    info->setCompasSignatureFrameIndex(
        reserve(word_size * riscv_common::signatureRegisters(MF).size(),
                word_size));
  if (dmr_frame) {
    const unsigned alignment =
        MF.getSubtarget<llvm::RISCVSubtarget>().hasStdExtD()
            ? std::max(word_size, 8u)
            : word_size;
    info->setCompasDmrCallFrameIndex(reserve(dmr_frame_size(MF), alignment));
  }
  if (incoming_shadow_sp)
    // Keep the caller's argument bank distinct from this callee's shadow
    // frame, even when nested calls overwrite the live shadow SP.
    info->setCompasIncomingShadowSPFrameIndex(reserve(word_size, word_size));
  if (pointer_deltas)
    // Each formal pointer can address a different caller bank. Preserve one
    // independent shadow-minus-primary relation for each register/stack formal,
    // a capture scratch word, then mutable per-location expectations.
    info->setCompasPointerDeltaFrameIndex(reserve(
        word_size * (riscv_common::incomingPointerDeltaSlots(MF) +
                     riscv_common::pointerProvenanceSlots(MF)),
        word_size));
}
