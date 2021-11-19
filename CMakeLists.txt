cmake_minimum_required(VERSION 3.13)

project(Sihft)

add_llvm_library(Sihft
  STATIC
    src/common.cpp
    src/RISCVCfcss.cpp
    src/RISCVRasm.cpp
    src/RISCVDmr.cpp
)
target_include_directories(Sihft
  PRIVATE
    include/
    ${CMAKE_SOURCE_DIR}/lib/Target/RISCV/
    ${CMAKE_BINARY_DIR}/lib/Target/RISCV/
)
