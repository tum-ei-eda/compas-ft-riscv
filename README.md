# compas-ft-riscv
COMPAS: Compiler-assisted Software-implemented Hardware Fault Tolerance implemented in LLVM passes for the RISC-V backend

Repo to house SIHFT passes for LLVM to create COMPAS, a compiler that adds fault tolerance on instruction level for RISCV 32/64 targets.
COMPAS is implemented such that it can be used as patch for the RISC-V LLVM toolchain.

## Citation
If you want to cite this work, please use the following papers.

<details>
<summary>Publications</summary>
<p>

```
@inproceedings{compas2022,
  author={Sharif, Uzair and Mueller-Gritschneder, Daniel and Schlichtmann, Ulf},
  booktitle={2022 11th Mediterranean Conference on Embedded Computing (MECO)}, 
  title={COMPAS: Compiler-assisted Software-implemented Hardware Fault Tolerance for RISC-V}, 
  year={2022},
  volume={},
  number={},
  pages={1-4},
  doi={10.1109/MECO55406.2022.9797144}}

@inproceedings{compasec2023,
  author = {Geier, Johannes and Auer, Lukas and Mueller-Gritschneder, Daniel and Sharif, Uzair and Schlichtmann, Ulf},
  title = {CompaSeC: A Compiler-Assisted Security Countermeasure to Address Instruction Skip Fault Attacks on RISC-V},
  year = {2023},
  isbn = {9781450397834},
  publisher = {Association for Computing Machinery},
  address = {New York, NY, USA},
  url = {https://doi.org/10.1145/3566097.3567925},
  doi = {10.1145/3566097.3567925},
  booktitle = {Proceedings of the 28th Asia and South Pacific Design Automation Conference},
  pages = {676–682},
  numpages = {7},
  keywords = {RISC-V, compiler, fault injection attack, redundancy},
  location = {Tokyo, Japan},
  series = {ASPDAC '23}
}
```

</p>
</details>

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
- [x] RACFED

## Literature
EDDI: https://ieeexplore.ieee.org/document/994913  
SWIFT: https://ieeexplore.ieee.org/document/1402092  
NZDC: https://ieeexplore.ieee.org/document/7544291  
NEMESIS: https://ieeexplore.ieee.org/document/8203792  

CFCSS: https://ieeexplore.ieee.org/document/994926  
RASM: https://ieeexplore.ieee.org/document/8067656  
RACFED: https://doi.org/10.1007/978-3-319-99130-6_15  

REPAIR: https://dl.acm.org/doi/abs/10.1145/3477001
