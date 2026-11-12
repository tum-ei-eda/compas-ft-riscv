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

#include "RISCVCfcss.h"
#include "RISCVDmr.h"
#include "RISCVRasm.h"
#include "common.h"

namespace {

class RISCVCompasHardening : public llvm::MachineFunctionPass {
public:
  static inline char ID{0};

  RISCVCompasHardening() : llvm::MachineFunctionPass(ID) {}

  llvm::StringRef getPassName() const override { return "COMPAS hardening"; }

  bool runOnMachineFunction(llvm::MachineFunction &MF) override {
    if (llvm::cl::enable_eddi.empty() && llvm::cl::enable_swift.empty() &&
        llvm::cl::enable_nzdc.empty() &&
        llvm::cl::enable_nzdc_nemesis.empty() &&
        llvm::cl::enable_nzdc_nemesec.empty() &&
        llvm::cl::enable_cfcss.empty() && llvm::cl::enable_rasm.empty() &&
        llvm::cl::enable_racfed.empty())
      return false;

    // These phases share the original signature regions. Splitting checks
    // between them would give their continuation blocks extra signatures.
    // Verify the completed transformation as one machine-function pass.
    dmr_.runOnMachineFunction(MF);
    cfcss_.runOnMachineFunction(MF);
    rasm_.runOnMachineFunction(MF);
    racfed_.runOnMachineFunction(MF);
    // Describe shadow arguments and results only after the phases have
    // finished inspecting the original ABI operands.
    dmr_.finalizeCallingConvention();
    riscv_common::normalizeControlFlow(MF);
    return true;
  }

private:
  RISCVDmr dmr_;
  RISCVCfcss cfcss_;
  RISCVRasm rasm_;
  RISCVRacfed racfed_;
};

} // namespace

llvm::FunctionPass *llvm::createRISCVCompasHardening() {
  return new RISCVCompasHardening();
}
