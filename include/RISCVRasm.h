/*
 * Copyright [2021] [Chair of EDA, Technical University of Munich]
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

 private:
  // RTS register
  const unsigned kRTS{llvm::RISCV::X5};
  // check register
  const unsigned kC{P2S_.at(kRTS)};
  // pointer to err-bb that is introdcued in this pass
  llvm::MachineBasicBlock *cf_err_bb_{nullptr};
  // map each MBB to its signatures
  std::map<llvm::MachineBasicBlock *, std::pair<short, short>> mbb_sigs_{};
  // for random number generation using uniform distribution
  std::default_random_engine gen_{};
  std::uniform_int_distribution<short> unif_dist_{-500, 500};
  // for convenience
  std::set<llvm::MachineBasicBlock *> err_bbs_{};

  // for initialization purposes
  void init();
  // this applies the RASM transformation on each BB
  void harden();
  // inserts an error-handler BB to the machine function so that in case of
  // error detection we end up in this block
  void insertErrorBB() override;
};
