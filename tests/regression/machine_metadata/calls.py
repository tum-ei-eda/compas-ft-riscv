"""Structural checks and independent verifier probes for indirect-call metadata."""

import re

import runner


GPR_SHADOWS = {0: 27, 1: 7, 2: 9, 3: 22, 4: 28, 5: 29, 6: 30,
               8: 31, 10: 24, 11: 25, 12: 26, 13: 21, 14: 20,
               15: 23, 16: 19, 17: 18}
FPR_SHADOWS = {0: 7, 1: 9, 2: 18, 3: 19, 4: 20, 5: 21, 6: 22,
               10: 24, 11: 25, 12: 26, 13: 27, 14: 28, 15: 29,
               16: 30, 17: 31}


def _shadow(register):
    if register.startswith("x"):
        index = int(register[1:])
        return "x" + str(GPR_SHADOWS[index]) if index in GPR_SHADOWS else None
    match = re.fullmatch(r"f(\d+)_(h|f|d)", register)
    if match and int(match[1]) in FPR_SHADOWS:
        return f"f{FPR_SHADOWS[int(match[1])]}_{match[2]}"
    return None


def _calls(mir):
    result = {}
    for document in mir.split("---\n"):
        name = re.search(r"^name: +([\w.]+)$", document, re.MULTILINE)
        if name:
            instructions = [line for line in document.splitlines()
                            if re.search(r"\bPseudoCALLIndirect\b", line)]
            if instructions:
                result[name[1]] = instructions
    return result


def _registers(instruction, define):
    if define:
        pattern = r"\bimplicit-def(?: dead)? \$(\w+)"
    else:
        pattern = r"\bimplicit(?: killed)? \$(\w+)"
    return set(re.findall(pattern, instruction))


def _mask(instruction):
    match = re.search(r"CustomRegMask\(([^)]*)\)", instruction)
    if not match:
        raise runner.TestError("indirect call did not receive a custom shadow regmask")
    return set(re.findall(r"\$(\w+)", match[1]))


def check(before_mir, after_mir, mode, arch, abi):
    """Check real call operands and preserved sets, independent of the compiler."""
    del arch  # Both XLENs use the same physical-register calling convention.
    original = _calls(before_mir)
    hardened = _calls(after_mir)
    if not original or set(original) != set(hardened):
        raise runner.TestError("indirect-call fixture disappeared or changed functions")
    count = 0
    arguments = 0
    results = 0
    fp_arguments = 0
    fp_results = 0
    ordinary_preserved = {1, 3, 4, 8, 9, *range(18, 28)}
    expected_preserved = {1, 3, 4, 8, 22, 27}
    if mode != "EDDI":
        expected_preserved.add(9)
    for name, calls in original.items():
        if len(calls) != len(hardened[name]):
            raise runner.TestError(f"indirect-call count changed in {name}")
        for before, after in zip(calls, hardened[name]):
            uses = _registers(after, False)
            # The dispatch register is an explicit use. The finalizer avoids
            # adding a redundant implicit bank use for that same register.
            uses.update(re.findall(r"\$(\w+)", after.split("CustomRegMask", 1)[0]))
            definitions = _registers(after, True)
            for register in _registers(before, False):
                shadow = _shadow(register)
                if shadow:
                    if shadow not in uses:
                        raise runner.TestError(f"{name}: missing shadow argument ${shadow}")
                    arguments += 1
                    fp_arguments += register.startswith("f")
            for register in _registers(before, True) - {"x1", "x2"}:
                if re.search(r"\bimplicit-def dead \$" + register + r"\b", before):
                    continue
                shadow = _shadow(register)
                if shadow:
                    if shadow not in definitions:
                        raise runner.TestError(f"{name}: missing shadow result ${shadow}")
                    results += 1
                    fp_results += register.startswith("f")
            required_uses = {"x0", "x2", "x3", "x4", "x9", "x22", "x27", "x28"}
            if mode != "EDDI":
                # The existing non-EDDI boundary observes the GPR bank. Leave
                # t0/t4 out here because a CFP pass may own that pair.
                for primary in (6, 8, *range(10, 18)):
                    required_uses.update((f"x{primary}", f"x{GPR_SHADOWS[primary]}"))
            if required_uses - uses:
                raise runner.TestError(f"{name}: missing convention inputs {sorted(required_uses - uses)}")
            if "x7" not in definitions or (mode == "EDDI" and "x9" not in definitions):
                raise runner.TestError(f"{name}: missing shadow RA/SP outputs")
            preserved = _mask(after)
            actual_preserved = {int(register[1:]) for register in preserved
                                if re.fullmatch(r"x\d+", register)}
            # x0 is represented differently in the LLVM13 and LLVM16 masks.
            if actual_preserved - {0} != expected_preserved:
                raise runner.TestError(f"{name}: unknown-target GPR mask has unexpected preservation: "
                                       f"{sorted(actual_preserved)}")
            if not actual_preserved - {0} <= ordinary_preserved:
                raise runner.TestError(f"{name}: unknown target gained ordinary-ABI preserved bits")
            if abi.endswith("d"):
                for register in preserved:
                    match = re.fullmatch(r"f(\d+)_(h|f|d)", register)
                    if match and int(match[1]) not in (8, 23):
                        raise runner.TestError(f"{name}: unknown target spuriously preserves ${register}")
            count += 1
    if not arguments or not results:
        raise runner.TestError("indirect fixture did not expose argument and result metadata")
    if abi.endswith("d") and (not fp_arguments or not fp_results):
        raise runner.TestError("hard-float fixture did not expose FP arguments and results")
    return dict(indirect_calls=count, shadow_arguments=arguments,
                shadow_results=results, fp_shadow_arguments=fp_arguments,
                fp_shadow_results=fp_results)


def mask_probes(after_mir, mode, arch):
    """Consume the emitted mask with no COMPAS reservations or shadow defs.

    A genuine register definition precedes the call, and a real use follows
    it. The verifier must reject that use exactly when the mask clobbers it.
    These probes isolate the mask from implicit call outputs and live-in repair.
    """
    instructions = [call for calls in _calls(after_mir).values() for call in calls]
    if not instructions:
        raise runner.TestError("no indirect call is available for regmask probes")
    mask = re.search(r"CustomRegMask\([^)]*\)", instructions[0])
    if not mask:
        raise runner.TestError("no custom indirect-call regmask is available")
    bits = arch[2:]
    probes = []
    registers = [("x22", True), ("x27", True),
                 ("x24", False), ("x28", False),
                 ("x31", False), ("x9", mode != "EDDI")]
    if "f8_d" in _mask(instructions[0]):
        registers.extend((("f8_d", True), ("f8_f", True),
                          ("f24_d", False), ("f24_f", False)))
    for register, preserved in registers:
        if register.startswith("x"):
            setup = f"${register} = ADDI $x0, 19"
            consume = f"$x10 = ADDI ${register}, 0"
        else:
            double = register.endswith("_d")
            setup = (f"${register} = FCVT_D_W $x0" if double
                     else f"${register} = FMV_W_X $x0")
            opcode = "FSGNJ_D" if double else "FSGNJ_S"
            view = "d" if double else "f"
            consume = (f"$f0_{view} = {opcode} ${register}, ${register}\n"
                       "    $x10 = ADDI $x0, 0")
        mir = f'''--- |
  target triple = "riscv{bits}-unknown-elf"
  define i{bits} @mask_probe() {{ ret i{bits} 0 }}
...
---
name: mask_probe
tracksRegLiveness: true
body: |
  bb.0:
    {setup}
    PseudoCALLIndirect undef $x6, {mask[0]}, implicit-def dead $x1, implicit $x2
    {consume}
    PseudoRET implicit $x10
...
'''
        probes.append((register, mir, not preserved))
    return probes
