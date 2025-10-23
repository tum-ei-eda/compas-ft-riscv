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

#pragma once

#include <random>

#include "RISCV.h"
#include "RISCVDmr.h"
#include "common.h"

class RISCVRasm : public RISCVDmr {
public:
  // constructor
  RISCVRasm();
  // override the transformation function
  bool runOnMachineFunction(llvm::MachineFunction &) override;

  static unsigned get_runtime_signature_reg(void) { return kRTS; }

protected:
  void assert_imm(short val) {
    const short lower = -(1 << (12 - 1));
    const short upper = (1 << (12 - 1)) - 1;
    assert(val >= lower && val <= upper &&
           "immediate value excesses expressable value [-2048, 2047]");
  }
  // RTS register
  static const unsigned kRTS{llvm::RISCV::X5};
  // check register
  const unsigned kC{P2S_.at(kRTS)};
  // pointer to err-bb that is introdcued in this pass
  llvm::MachineBasicBlock *cf_err_bb_{nullptr};
  // map each MBB to its signatures
  std::map<const llvm::MachineBasicBlock *, std::pair<short, short>>
      mbb_sigs_{};
  // for random number generation using uniform distribution
  std::default_random_engine gen_{};
  std::uniform_int_distribution<short> unif_dist_{-500, 500};
  // for convenience
  std::set<llvm::MachineBasicBlock *> err_bbs_{};

  // for initialization purposes
  virtual void init() override;
  // this applies the RASM transformation on each BB
  virtual void harden();
  // inserts an error-handler BB to the machine function so that in case of
  // error detection we end up in this block
  void insertErrorBB() override;

  virtual short calculate_adjustment(const llvm::MachineBasicBlock *source_bb,
                                     const llvm::MachineBasicBlock *target_bb);
  virtual void save_restore_runtime_signature(llvm::MachineInstr *call_instr);

  bool branches_to_errbbs(const llvm::MachineInstr *mi);

  void generate_signatures();
  virtual void generate_intrablock_signature_updates();
  void generate_signature_checks();
  void generate_traversal_adjustments();

  // map containing the signature check instruction for each MBB
  std::map<const llvm::MachineBasicBlock *, llvm::MachineInstr *>
      mbb_signature_check_instrs_{};
  // map containing the runtime signature random arbitration (S-=subRanPrevVal)
  // instruction for each MBB
  std::map<const llvm::MachineBasicBlock *, llvm::MachineInstr *>
      mbb_signature_arbr_instrs_{};
  // map each MBB to its sum of all intra-block instruction updates
  std::map<const llvm::MachineBasicBlock *, short> mbb_sum_ii_sigs_{};
};

class RISCVRacfed : public RISCVRasm {
public:
  // constructor
  RISCVRacfed();
  // override the transformation function
  bool runOnMachineFunction(llvm::MachineFunction &) override;

protected:
  virtual short
  calculate_adjustment(const llvm::MachineBasicBlock *source_bb,
                       const llvm::MachineBasicBlock *target_bb) override;

  virtual void
  save_restore_runtime_signature(llvm::MachineInstr *call_instr) override;

  virtual void generate_intrablock_signature_updates() override;

private:
  // map each MBB to its sum of all intra-block instruction updates
  std::map<const llvm::MachineBasicBlock *,
           std::map<const llvm::MachineInstr *, short>>
      mi_random_value_{};
  // for initialization purposes
  virtual void init() override;
  // this applies the RASM transformation on each BB
  virtual void harden() override;
};
