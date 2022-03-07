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

#include "RISCV.h"
#include "common.h"
#include "llvm/CodeGen/MachineFunctionPass.h"

class RISCVDmr : public llvm::MachineFunctionPass {
 public:
  using RegSetType = std::set<llvm::Register>;
  using RegMapType = std::map<llvm::Register, llvm::Register>;

  // pass registration in llvm system
  static inline char ID{0};

  // constructor
  RISCVDmr();
  // override the transformation function
  bool runOnMachineFunction(llvm::MachineFunction &) override;

 protected:
  // for convenience
  llvm::MachineFunction *MF_{nullptr};
  const llvm::TargetInstrInfo *TII_{nullptr};
  const llvm::MachineRegisterInfo *MRI_{nullptr};

  // CGS: coarse grain scheduling of master and shadow instructions
  // FGS: fine grain scheduling of master and shadow instructions
  enum class InstructionSchedule { CGS, FGS };
  // S1: check addr and data copies before single store (aka SWIFT store)
  // S2: check data copies before two stores (aka EDDI store)
  // S3: loadback via dup addr and check with dup data (aka NZDC loadback)
  // S0: dont protect
  enum class ProtectStrategyStore { S0, S1, S2, S3 };
  // L1: check address before single load and then use copy (aka SIHFT load)
  // L2: the duplicated load uses shadow memory space (aka EDDI load)
  // L0: dont protect
  enum class ProtectStrategyLoad { L0, L1, L2 };
  // UCI: check args before func call and check return values before return (aka
  //      EDDI/SWIFT func-call check)
  // UC2: deprecated - DON'T USE!!
  // UC3: check complete primary and shadow reg-files with each other at
  //      the start of callee (aka NZDC func-call check)
  // UC4: duplicate call in both primary and shadow threads
  // UC0: dont protect
  enum class ProtectStrategyUserCall { UC0, UC1, UC2, UC3, UC4 };
  // LC2 : sync function params before non-duplicated lib call
  // LC1 : duplicate call in both primary and shadow threads
  // LC0 : dont protect
  enum class ProtectStrategyLibCall { LC0, LC1, LC2 };
  // B1: check branch operands before branch (aka EDDI/SWIFT branch check)
  // B2: duplicate branch (aka NEMESIS)
  // B3: duplicate branch and force negative offsets to harden fallthroughs (aka NEMESEC)
  // B0: dont protect
  enum class ProtectStrategyBranch { B0, B1, B2, B3 };
  // TODO: maybe group all protect strategies into one concept

  // grouping above strategies/configs in a single container
  struct DMRConfig {
    InstructionSchedule is{InstructionSchedule::CGS};
    ProtectStrategyStore pss{ProtectStrategyStore::S0};
    ProtectStrategyLoad psl{ProtectStrategyLoad::L0};
    ProtectStrategyUserCall psuc{ProtectStrategyUserCall::UC0};
    ProtectStrategyLibCall pslc{ProtectStrategyLibCall::LC0};
    ProtectStrategyBranch psb{ProtectStrategyBranch::B0};
    riscv_common::ErrorDetectionStrategy eds{
        riscv_common::ErrorDetectionStrategy::ED0};
  };

  // // for live-reg-analysis we define IN, OUT, USE, DEF sets for each MBB
  // struct MBBInfo {
  //   RegSetType INr{};
  //   RegSetType OUTr{};
  //   RegSetType USEr{};
  //   RegSetType DEFr{};
  // };

  // all dmr related configs in one container
  DMRConfig config_{};
  // config based on target ISA
  riscv_common::ISAConfig isa_config_{};
  // // MBBInfo handle
  // std::map<llvm::MachineBasicBlock *, MBBInfo> mbb_info_{};
  // mapping between primary and shadow registers
  const RegMapType P2S_{{llvm::RISCV::X0, llvm::RISCV::X27},   // zero  : s11
                        {llvm::RISCV::X1, llvm::RISCV::X7},    // ra    : t2
                        {llvm::RISCV::X2, llvm::RISCV::X9},    // sp    : s1
                        {llvm::RISCV::X3, llvm::RISCV::X22},   // gp    : s6
                        {llvm::RISCV::X4, llvm::RISCV::X28},   // tp    : t3
                        {llvm::RISCV::X5, llvm::RISCV::X29},   // t0    : t4
                        {llvm::RISCV::X6, llvm::RISCV::X30},   // t1    : t5
                        {llvm::RISCV::X8, llvm::RISCV::X31},   // s0/fp : t6
                        {llvm::RISCV::X10, llvm::RISCV::X24},  // a0    : s8
                        {llvm::RISCV::X11, llvm::RISCV::X25},  // a1    : s9
                        {llvm::RISCV::X12, llvm::RISCV::X26},  // a2    : s10
                        {llvm::RISCV::X13, llvm::RISCV::X21},  // a3    : s5
                        {llvm::RISCV::X14, llvm::RISCV::X20},  // a4    : s4
                        {llvm::RISCV::X15, llvm::RISCV::X23},  // a5    : s7
                        {llvm::RISCV::X16, llvm::RISCV::X19},  // a6    : s3
                        {llvm::RISCV::X17, llvm::RISCV::X18},  // a7    : s2

                        {llvm::RISCV::F0_F, llvm::RISCV::F7_F},
                        {llvm::RISCV::F1_F, llvm::RISCV::F9_F},
                        {llvm::RISCV::F2_F, llvm::RISCV::F18_F},
                        {llvm::RISCV::F3_F, llvm::RISCV::F19_F},
                        {llvm::RISCV::F4_F, llvm::RISCV::F20_F},
                        {llvm::RISCV::F5_F, llvm::RISCV::F21_F},
                        {llvm::RISCV::F6_F, llvm::RISCV::F22_F},
                        // {llvm::RISCV::F8_F, llvm::RISCV::F23_F},
                        {llvm::RISCV::F10_F, llvm::RISCV::F24_F},
                        {llvm::RISCV::F11_F, llvm::RISCV::F25_F},
                        {llvm::RISCV::F12_F, llvm::RISCV::F26_F},
                        {llvm::RISCV::F13_F, llvm::RISCV::F27_F},
                        {llvm::RISCV::F14_F, llvm::RISCV::F28_F},
                        {llvm::RISCV::F15_F, llvm::RISCV::F29_F},
                        {llvm::RISCV::F16_F, llvm::RISCV::F30_F},
                        {llvm::RISCV::F17_F, llvm::RISCV::F31_F},

                        {llvm::RISCV::F0_D, llvm::RISCV::F7_D},
                        {llvm::RISCV::F1_D, llvm::RISCV::F9_D},
                        {llvm::RISCV::F2_D, llvm::RISCV::F18_D},
                        {llvm::RISCV::F3_D, llvm::RISCV::F19_D},
                        {llvm::RISCV::F4_D, llvm::RISCV::F20_D},
                        {llvm::RISCV::F5_D, llvm::RISCV::F21_D},
                        {llvm::RISCV::F6_D, llvm::RISCV::F22_D},
                        // {llvm::RISCV::F8_D, llvm::RISCV::F23_D},
                        {llvm::RISCV::F10_D, llvm::RISCV::F24_D},
                        {llvm::RISCV::F11_D, llvm::RISCV::F25_D},
                        {llvm::RISCV::F12_D, llvm::RISCV::F26_D},
                        {llvm::RISCV::F13_D, llvm::RISCV::F27_D},
                        {llvm::RISCV::F14_D, llvm::RISCV::F28_D},
                        {llvm::RISCV::F15_D, llvm::RISCV::F29_D},
                        {llvm::RISCV::F16_D, llvm::RISCV::F30_D},
                        {llvm::RISCV::F17_D, llvm::RISCV::F31_D},

                        {llvm::RISCV::F0_H, llvm::RISCV::F7_H},
                        {llvm::RISCV::F1_H, llvm::RISCV::F9_H},
                        {llvm::RISCV::F2_H, llvm::RISCV::F18_H},
                        {llvm::RISCV::F3_H, llvm::RISCV::F19_H},
                        {llvm::RISCV::F4_H, llvm::RISCV::F20_H},
                        {llvm::RISCV::F5_H, llvm::RISCV::F21_H},
                        {llvm::RISCV::F6_H, llvm::RISCV::F22_H},
                        // {llvm::RISCV::F8_H, llvm::RISCV::F23_H},
                        {llvm::RISCV::F10_H, llvm::RISCV::F24_H},
                        {llvm::RISCV::F11_H, llvm::RISCV::F25_H},
                        {llvm::RISCV::F12_H, llvm::RISCV::F26_H},
                        {llvm::RISCV::F13_H, llvm::RISCV::F27_H},
                        {llvm::RISCV::F14_H, llvm::RISCV::F28_H},
                        {llvm::RISCV::F15_H, llvm::RISCV::F29_H},
                        {llvm::RISCV::F16_H, llvm::RISCV::F30_H},
                        {llvm::RISCV::F17_H, llvm::RISCV::F31_H}};
  const std::map<llvm::Register, std::string> Reg2Name_{
      {llvm::RISCV::X0, "zero"},      {llvm::RISCV::X1, "ra"},
      {llvm::RISCV::X2, "sp"},        {llvm::RISCV::X3, "gp"},
      {llvm::RISCV::X4, "tp"},        {llvm::RISCV::X5, "t0"},
      {llvm::RISCV::X6, "t1"},        {llvm::RISCV::X7, "t2"},
      {llvm::RISCV::X8, "s0"},        {llvm::RISCV::X9, "s1"},
      {llvm::RISCV::X10, "a0"},       {llvm::RISCV::X11, "a1"},
      {llvm::RISCV::X12, "a2"},       {llvm::RISCV::X13, "a3"},
      {llvm::RISCV::X14, "a4"},       {llvm::RISCV::X15, "a5"},
      {llvm::RISCV::X16, "a6"},       {llvm::RISCV::X17, "a7"},
      {llvm::RISCV::X18, "s2"},       {llvm::RISCV::X19, "s3"},
      {llvm::RISCV::X20, "s4"},       {llvm::RISCV::X21, "s5"},
      {llvm::RISCV::X22, "s6"},       {llvm::RISCV::X23, "s7"},
      {llvm::RISCV::X24, "s8"},       {llvm::RISCV::X25, "s9"},
      {llvm::RISCV::X26, "s10"},      {llvm::RISCV::X27, "s11"},
      {llvm::RISCV::X28, "t3"},       {llvm::RISCV::X29, "t4"},
      {llvm::RISCV::X30, "t5"},       {llvm::RISCV::X31, "t6"},
      {llvm::RISCV::F0_F, "ft0"},     {llvm::RISCV::F1_F, "ft1"},
      {llvm::RISCV::F2_F, "ft2"},     {llvm::RISCV::F3_F, "ft3"},
      {llvm::RISCV::F4_F, "ft4"},     {llvm::RISCV::F5_F, "ft5"},
      {llvm::RISCV::F6_F, "ft6"},     {llvm::RISCV::F7_F, "ft7"},
      {llvm::RISCV::F8_F, "fs0"},     {llvm::RISCV::F9_F, "fs1"},
      {llvm::RISCV::F10_F, "fa0"},    {llvm::RISCV::F11_F, "fa1"},
      {llvm::RISCV::F12_F, "fa2"},    {llvm::RISCV::F13_F, "fa3"},
      {llvm::RISCV::F14_F, "fa4"},    {llvm::RISCV::F15_F, "fa5"},
      {llvm::RISCV::F16_F, "fa6"},    {llvm::RISCV::F17_F, "fa7"},
      {llvm::RISCV::F18_F, "fs2"},    {llvm::RISCV::F19_F, "fs3"},
      {llvm::RISCV::F20_F, "fs4"},    {llvm::RISCV::F21_F, "fs5"},
      {llvm::RISCV::F22_F, "fs6"},    {llvm::RISCV::F23_F, "fs7"},
      {llvm::RISCV::F24_F, "fs8"},    {llvm::RISCV::F25_F, "fs9"},
      {llvm::RISCV::F26_F, "fs10"},   {llvm::RISCV::F27_F, "fs11"},
      {llvm::RISCV::F28_F, "ft8"},    {llvm::RISCV::F29_F, "ft9"},
      {llvm::RISCV::F30_F, "ft10"},   {llvm::RISCV::F31_F, "ft11"},
      {llvm::RISCV::F0_D, "ft0_d"},   {llvm::RISCV::F1_D, "ft1_d"},
      {llvm::RISCV::F2_D, "ft2_d"},   {llvm::RISCV::F3_D, "ft3_d"},
      {llvm::RISCV::F4_D, "ft4_d"},   {llvm::RISCV::F5_D, "ft5_d"},
      {llvm::RISCV::F6_D, "ft6_d"},   {llvm::RISCV::F7_D, "ft7_d"},
      {llvm::RISCV::F8_D, "fs0_d"},   {llvm::RISCV::F9_D, "fs1_d"},
      {llvm::RISCV::F10_D, "fa0_d"},  {llvm::RISCV::F11_D, "fa1_d"},
      {llvm::RISCV::F12_D, "fa2_d"},  {llvm::RISCV::F13_D, "fa3_d"},
      {llvm::RISCV::F14_D, "fa4_d"},  {llvm::RISCV::F15_D, "fa5_d"},
      {llvm::RISCV::F16_D, "fa6_d"},  {llvm::RISCV::F17_D, "fa7_d"},
      {llvm::RISCV::F18_D, "fs2_d"},  {llvm::RISCV::F19_D, "fs3_d"},
      {llvm::RISCV::F20_D, "fs4_d"},  {llvm::RISCV::F21_D, "fs5_d"},
      {llvm::RISCV::F22_D, "fs6_d"},  {llvm::RISCV::F23_D, "fs7_d"},
      {llvm::RISCV::F24_D, "fs8_d"},  {llvm::RISCV::F25_D, "fs9_d"},
      {llvm::RISCV::F26_D, "fs10_d"}, {llvm::RISCV::F27_D, "fs11_d"},
      {llvm::RISCV::F28_D, "ft8_d"},  {llvm::RISCV::F29_D, "ft9_d"},
      {llvm::RISCV::F30_D, "ft10_d"}, {llvm::RISCV::F31_D, "ft11_d"}};
  // libcalls (C library or compiler) are collected here to later identify
  // a call as user-func call or lib call
  // we define user-func calls as the ones which our DMR pass can transform
  const std::map<std::string, bool> knownLibcalls2Duplicable_{
      {"printf", false},       {"strlen", true},       {"srand", false},
      {"rand", false},         {"cos", true},          {"sin", true},
      {"puts", false},         {"putchar", false},     {"exit", false},
      {"__extendsfdf2", true}, {"__truncdfsf2", true}, {"__floatunsidf", true},
      {"__divdf3", true},      {"__muldf3", true},     {"__adddf3", true},
      {"__subdf3", true},      {"__modsi3", true},     {"__floatsisf", true},
      {"__floatunsisf", true}, {"__mulsf3", true},     {"strncmp", true},
      {"__mulsi3", true},      {"memset", true},       {"memcpy", true},
      {"memcmp", true},        {"atan", true},         {"__extenddftf2", true},
      {"__multf3", true},      {"__addtf3", true},     {"__divtf3", true},
      {"__subtf3", true},      {"__trunctfdf2", true}, {"pow", true},
      {"__lttf2", true},       {"acos", true},         {"sqrt", true},
      {"__floatsidf", true},   {"__ltdf2", true},      {"__ledf2", true},
      {"__gtdf2", true},       {"__nedf2", true},      {"__udivsi3", true}};
  const std::map<unsigned, unsigned> LBStore2Load_{
      {llvm::RISCV::SW, llvm::RISCV::LW},
      {llvm::RISCV::SD, llvm::RISCV::LD},
      {llvm::RISCV::SH, llvm::RISCV::LHU},
      {llvm::RISCV::SB, llvm::RISCV::LBU},
      {llvm::RISCV::SC_W, llvm::RISCV::LW},
      {llvm::RISCV::SC_D, llvm::RISCV::LD},
      {llvm::RISCV::FSW, llvm::RISCV::FLW},
      {llvm::RISCV::FSD, llvm::RISCV::FLD}};
  const std::set<llvm::Register> callee_saved_regs_{
      llvm::RISCV::X8,    llvm::RISCV::X9,    llvm::RISCV::X18,
      llvm::RISCV::X19,   llvm::RISCV::X20,   llvm::RISCV::X21,
      llvm::RISCV::X22,   llvm::RISCV::X23,   llvm::RISCV::X24,
      llvm::RISCV::X25,   llvm::RISCV::X26,   llvm::RISCV::X27,
      llvm::RISCV::F8_F,  llvm::RISCV::F9_F,  llvm::RISCV::F18_F,
      llvm::RISCV::F19_F, llvm::RISCV::F20_F, llvm::RISCV::F21_F,
      llvm::RISCV::F22_F, llvm::RISCV::F23_F, llvm::RISCV::F24_F,
      llvm::RISCV::F25_F, llvm::RISCV::F26_F, llvm::RISCV::F27_F,
      llvm::RISCV::F8_D,  llvm::RISCV::F9_D,  llvm::RISCV::F18_D,
      llvm::RISCV::F19_D, llvm::RISCV::F20_D, llvm::RISCV::F21_D,
      llvm::RISCV::F22_D, llvm::RISCV::F23_D, llvm::RISCV::F24_D,
      llvm::RISCV::F25_D, llvm::RISCV::F26_D, llvm::RISCV::F27_D,
      llvm::RISCV::F8_H,  llvm::RISCV::F9_H,  llvm::RISCV::F18_H,
      llvm::RISCV::F19_H, llvm::RISCV::F20_H, llvm::RISCV::F21_H,
      llvm::RISCV::F22_H, llvm::RISCV::F23_H, llvm::RISCV::F24_H,
      llvm::RISCV::F25_H, llvm::RISCV::F26_H, llvm::RISCV::F27_H};
  // pointer to error-BB that is introduced in this pass
  llvm::MachineBasicBlock *err_bb_{nullptr};
  // for convenience, we collect special instruction points in containers
  std::set<llvm::MachineInstr *> stores_{};
  // std::set<llvm::MachineInstr *> stores_to_protect_{};
  std::set<llvm::MachineInstr *> user_calls_{};
  std::set<llvm::MachineInstr *> lib_calls_{};
  std::set<llvm::MachineInstr *> branches_{};
  std::set<llvm::MachineInstr *> loads_{};
  std::set<llvm::MachineInstr *> shadow_loads_{};
  std::set<llvm::MachineBasicBlock *> exit_bbs_{};
  llvm::MachineBasicBlock *entry_bb_{nullptr};
  bool uses_FPregfile_{false};
  const std::set<llvm::Register> reserved_fp_primary_{
      llvm::RISCV::F8_F, llvm::RISCV::F8_D, llvm::RISCV::F8_H};
  std::set<llvm::MachineBasicBlock *> nemesis_bbs_{};
  std::set<llvm::MachineInstr *> loadbacks_{};
  std::set<llvm::MachineInstr *> indirect_calls_{};
  std::string fname_{};
  bool use_shadow_for_stack_ops_{true};
  int frame_size_{0};

  void init();
  void duplicateInstructions();
  void protectStores();
  void protectLoads();
  void protectCalls();
  void protectBranches();
  void protectGP();
  void repair();
  bool ignoreMF();
  // TODO: hide some of the following??
  llvm::MachineInstr *genShadowFromPrimary(const llvm::MachineInstr *) const;
  virtual void insertErrorBB();
  RegSetType getArgRegs(const llvm::MachineInstr *) const;
  RegSetType getRetRegs(const llvm::MachineInstr *) const;
  std::string getCalledFuncName(const llvm::MachineInstr *) const;
  bool isShadowInstr(const llvm::MachineInstr *) const;
  llvm::Register getPrimaryFromShadow(llvm::Register) const;
  // TODO: llvm::MachineInstr* should be const in following moveIntoShadow()
  void moveIntoShadow(llvm::MachineBasicBlock *,
                      llvm::MachineBasicBlock::iterator, llvm::Register,
                      llvm::Register);
  void syncFPRegs(llvm::MachineBasicBlock *, llvm::MachineBasicBlock::iterator,
                  llvm::Register, llvm::Register);
};

// NOTE: ft0_{h,f,d} with its shadow are available for FP DMR purposes as they
//       are not used for FP computation
