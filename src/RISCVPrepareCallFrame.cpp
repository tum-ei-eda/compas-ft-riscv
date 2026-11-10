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
#include "RISCVMachineFunctionInfo.h"
#include "RISCVSubtarget.h"
#include "common.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/Support/MathExtras.h"

#include <algorithm>

namespace {

bool needs_call_frame(const llvm::MachineFunction &MF) {
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

class RISCVPrepareCallFrame : public llvm::MachineFunctionPass {
public:
  static char ID;

  RISCVPrepareCallFrame() : MachineFunctionPass(ID) {}

  llvm::StringRef getPassName() const override {
    return "Prepare COMPAS call preservation frame";
  }

  bool runOnMachineFunction(llvm::MachineFunction &MF) override {
    if (!needs_call_frame(MF))
      return false;
    auto &frame = MF.getFrameInfo();
    if (frame.isFrameAddressTaken())
      return false;
    // Late DMR instrumentation can move SP around calls. Reserve FP before
    // register allocation; its fixed slot is allocated after CSI assignment.
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
  if (info->getCompasSignatureFrameIndex() < 0 || !needs_call_frame(MF))
    return;

  auto &frame = MF.getFrameInfo();
  const unsigned word_size =
      MF.getSubtarget<llvm::RISCVSubtarget>().is64Bit() ? 8 : 4;
  // CFCSS propagates both the runtime signature G and the adjustment D. RASM
  // and RACFED need only their single runtime-signature register preserved.
  const unsigned slot_size =
      word_size * riscv_common::signatureRegisters(MF).size();
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
        libcall_bytes = std::max(
            libcall_bytes,
            static_cast<uint64_t>(-saved.getFrameIdx()) * word_size);
    reserved = std::max(reserved, llvm::alignTo(libcall_bytes, 16));
  }
  // Fixed objects remain FP-relative even when a realigned frame would address
  // ordinary local objects through SP. PEI includes this area in its layout.
  const int64_t offset =
      -static_cast<int64_t>(llvm::alignTo(reserved + slot_size, word_size));
  info->setCompasSignatureFrameIndex(
      frame.CreateFixedObject(slot_size, offset, false));
}
