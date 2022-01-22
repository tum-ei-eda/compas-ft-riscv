# compas-ft-riscv
COMPAS: Compiler-assisted Software-implemented Hardware Fault Tolerance implemented in LLVM passes for the RISC-V backend

Repo to house SIHFT passes for LLVM to create COMPAS, a compiler that adds fault tolerance on instruction level for RISCV 32/64 targets.
COMPAS is implemented such that it can be used as patch for the RISC-V LLVM toolchain.

## User Guide
Detailed instructions on compiler installation and usage can be found in `doc/manual`. We provide the manual as pdf.

<!--
After cloning the repo, generate the user manual in `doc/manual` using latex compiler. For example, we used [`latexmk`](https://mg.readthedocs.io/latexmk.html) utitlity to generate the manual pdf in some build location using
```shell
$ latexmk -pdf doc/manual/main.tex -outdir=build/
```
-->

The manual provides details on how to install LLVM compiler with our SIHFT passes. Further, the manual provides usage instructions on how to harden a given C/C++ project using SIHFT transformations.

## Licensing and Copyright
See the separate LICENSE file to determine your rights and responsibilities for using these code modules

## Version History

### Version 1.0 
The supported SIHFT passes are:

Data flow protection:
- [x] EDDI
- [x] SWIFT
- [x] NZDC
- [x] NEMESIS
- [x] REPAIR

Control flow protection:
- [x] CFCSS
- [x] RASM

## Literature
EDDI: https://ieeexplore.ieee.org/document/994913  
SWIFT: https://ieeexplore.ieee.org/document/1402092  
NZDC: https://ieeexplore.ieee.org/document/7544291  
NEMESIS: https://ieeexplore.ieee.org/document/8203792  

CFCSS: https://ieeexplore.ieee.org/document/994926  
RASM: https://ieeexplore.ieee.org/document/8067656

REPAIR: https://dl.acm.org/doi/abs/10.1145/3477001
