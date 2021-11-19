/*
 * Copyright [2020] [Technical University of Munich]
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

#include <set>

#include "RISCV.h"
#include "RISCVDmr.h"
#include "common.h"

class RISCVCfcss : public RISCVDmr {
 public:
  // constructor
  RISCVCfcss();
  // override the transformation function
  bool runOnMachineFunction(llvm::MachineFunction &) override;

 private:
  struct MBBInfo {
    unsigned s{0};
    unsigned d{0};
    bool is_fanin{false};
    unsigned s_i1{0};
    std::set<llvm::MachineBasicBlock *> predecessors{};
  };

  // G register in paper
  const unsigned kG{llvm::RISCV::X5};
  // D register in paper
  const unsigned kD{P2S_.at(kG)};
  // pointer to error-bb that is introdcued in this pass.
  llvm::MachineBasicBlock *cf_err_bb_{nullptr};
  // map each MBB to its info
  std::map<llvm::MachineBasicBlock *, MBBInfo> mbb_info_{};

  // for initialization purposes
  void init();
  // this applies the CFCSS transformation on each BB
  void harden();
  // inserts an error-handler BB to the machine function so that in case of
  // error detection we end up in this block
  void insertErrorBB() override;
  // utility function to test if a passed in MBB has both succ as fanin-nodes
  bool hasMultipleFaninSBB(llvm::MachineBasicBlock *);
};
