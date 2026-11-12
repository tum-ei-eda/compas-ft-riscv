#!/usr/bin/env python3
"""Check RSM instruction classes using entry guards and matched computations."""

import argparse
import json
from pathlib import Path
import re


# COMPAS's integer primary/shadow ABI. Signature comparisons use t0/t4.
PRIMARY_TO_SHADOW = {
    "zero": "s11", "ra": "t2", "sp": "s1", "gp": "s6", "tp": "t3",
    "t0": "t4", "t1": "t5", "s0": "t6", "a0": "s8", "a1": "s9",
    "a2": "s10", "a3": "s5", "a4": "s4", "a5": "s7", "a6": "s3",
    "a7": "s2",
}
SHADOW_TO_PRIMARY = {shadow: primary for primary, shadow in PRIMARY_TO_SHADOW.items()}
ENTRY_PAIRS = [(primary, shadow) for primary, shadow in PRIMARY_TO_SHADOW.items()
               if primary not in ("ra", "t0")]
CONDITIONAL = {"beq", "bne", "blt", "bge", "bltu", "bgeu"}
ARITHMETIC = {"add", "addw", "addi", "addiw", "slli", "slliw", "xor", "xori", "mul", "mulw"}


def assembly_functions(paths):
    functions = {}
    for path in paths:
        current = None
        for number, raw in enumerate(Path(path).read_text().splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            match = re.match(r"([A-Za-z_][A-Za-z_0-9]*):$", line)
            if match:
                current = functions.setdefault(match.group(1), [])
                continue
            if line.startswith(".Lfunc_end") or line.startswith(".size"):
                current = None
            if current is None or not line or line.startswith(".") or line.endswith(":"):
                continue
            opcode, _, operands = line.partition("\t")
            if not operands:
                split = line.split(None, 1)
                opcode, operands = split[0], split[1] if len(split) == 2 else ""
            current.append((opcode.strip(), [item.strip() for item in operands.split(",")],
                            f"{path}:{number}"))
    return functions


def condition(instruction):
    opcode, operands, _ = instruction
    if opcode in CONDITIONAL and len(operands) == 3:
        return opcode, operands[0], operands[1]
    if opcode in ("beqz", "bnez", "bltz", "bgez") and len(operands) == 2:
        return {"beqz": "beq", "bnez": "bne", "bltz": "blt", "bgez": "bge"}[opcode], operands[0], "zero"
    if opcode in ("bgtz", "blez") and len(operands) == 2:
        return {"bgtz": "blt", "blez": "bge"}[opcode], "zero", operands[0]
    if opcode in ("bgt", "ble", "bgtu", "bleu") and len(operands) == 3:
        return {"bgt": "blt", "ble": "bge", "bgtu": "bltu", "bleu": "bgeu"}[opcode], operands[1], operands[0]
    return None


def signature_check(instruction):
    branch = condition(instruction)
    return branch is not None and branch[0] in ("beq", "bne") and set(branch[1:]) == {"t0", "t4"}


def signature_update(instruction):
    opcode, operands, _ = instruction
    return ((opcode == "addi" and len(operands) == 3 and operands[:2] == ["t0", "t0"])
            or (opcode == "mv" and operands == ["t0", "t0"]))


def instruction_classes(value):
    classes = {"orig", "dmr", "balance"} if value == "all" else set(value.split("+"))
    if not classes or not classes.issubset({"orig", "dmr", "balance"}):
        raise ValueError(f"invalid RSM instruction classes: {value}")
    return classes


def selected_classes(function, request):
    selected = None
    for entry in request.get("cfp_functions", request.get("functions", [])):
        name, separator, mask = entry.partition(":")
        if name in (function, "-1"):
            selected = instruction_classes(mask if separator else request["instructions"])
    return selected


def guarded(instructions, position):
    # A signature comparison must execute after the preceding control transfer
    # and before this duplicated branch. Labels and arithmetic do not affect it.
    for instruction in reversed(instructions[:position]):
        if signature_check(instruction):
            return True
        opcode = instruction[0]
        if condition(instruction) or opcode in ("j", "jr", "jal", "jalr", "ret", "call", "tail"):
            return False
    return False


def check(request):
    mode, cfp = request["mode"], request["cfp"]
    required = {"layering_entry", "layering_branches"}
    if mode not in ("NZDC+NEMESIS", "NZDC+NEMESEC") or cfp not in ("RASM", "RACFED"):
        return {"status": "SKIP", "detail": "requires NEMESIS/NEMESEC with RASM/RACFED", "checks": []}
    dmr_functions = set(request.get("functions", []))
    masks = {name: selected_classes(name, request) for name in required}
    if ("-1" not in dmr_functions and not required.issubset(dmr_functions)) or any(mask is None for mask in masks.values()):
        return {"status": "SKIP", "detail": "fixture functions were not selected for both protections", "checks": []}
    functions = assembly_functions(request["assemblies"])
    checks = []

    def require(ok, description, **evidence):
        checks.append({"status": "PASS" if ok else "FAIL", "detail": description, **evidence})

    if not required.issubset(functions):
        return {"status": "FAIL", "detail": "assembly is missing fixture functions", "checks": []}
    entry = functions["layering_entry"]
    balance = []
    next_pair = 0
    for index, instruction in enumerate(entry):
        branch = condition(instruction)
        if next_pair < len(ENTRY_PAIRS) and branch == ("bne", *ENTRY_PAIRS[next_pair]):
            balance.append(index)
            next_pair += 1
    require(len(balance) == 14, "minimal leaf retains all fourteen entry balance checks", found=len(balance))
    if len(balance) == 14:
        guarded_gaps = [any(signature_check(instruction) for instruction in entry[left + 1:right])
                        for left, right in zip(balance, balance[1:])]
        require(all(guarded_gaps) if "balance" in masks["layering_entry"] else not any(guarded_gaps),
                "entry balance coverage matches the selected instruction classes", classes=sorted(masks["layering_entry"]),
                guarded_gaps=guarded_gaps)

    body = functions["layering_branches"]
    primary = {branch for instruction in body if (branch := condition(instruction))
               and all(reg in PRIMARY_TO_SHADOW and reg != "t0" for reg in branch[1:])}
    duplicates = []
    for index, instruction in enumerate(body):
        branch = condition(instruction)
        if branch is None or not any(reg in SHADOW_TO_PRIMARY for reg in branch[1:]):
            continue
        if not all(reg in SHADOW_TO_PRIMARY or reg == "zero" for reg in branch[1:]):
            continue
        mapped = (branch[0], *(SHADOW_TO_PRIMARY.get(reg, reg) for reg in branch[1:]))
        if mapped in primary:
            duplicates.append((index, guarded(body, index)))
    require(bool(duplicates), "branch fixture retains paired primary/shadow conditional branches", found=len(duplicates))
    if duplicates:
        coverage = [covered for _, covered in duplicates]
        require(all(coverage) if "dmr" in masks["layering_branches"] else not any(coverage),
                "duplicated branch coverage matches the selected instruction classes", classes=sorted(masks["layering_branches"]),
                guarded_duplicates=coverage)

    if cfp == "RACFED":
        # The branch-free fixture has one ordinary return. Error-handler
        # constants after it use addi on LLVM13 and li on LLVM16; neither is
        # application arithmetic or an eligible signature update.
        normal_end = next((index for index, instruction in enumerate(entry)
                           if instruction[0] == "ret"), len(entry))
        data_registers = {"t1", *(f"a{index}" for index in range(8))}
        for category, registers in (("orig", data_registers),
                                    ("dmr", {PRIMARY_TO_SHADOW[reg] for reg in data_registers})):
            compute = [index for index, instruction in enumerate(entry[:normal_end])
                       if instruction[0] in ARITHMETIC and instruction[1]
                       and instruction[1][0] in registers]
            require(len(compute) >= 2, f"minimal leaf retains {category} arithmetic", found=len(compute))
            if len(compute) >= 2:
                # Ignore the last operation: the transition at the end of a
                # region can need structural arithmetic even for excluded UI.
                updates = [signature_update(entry[index + 1]) for index in compute[:-1]]
                require(all(updates) if category in masks["layering_entry"] else not any(updates),
                        f"RACFED per-instruction updates match the {category} selection",
                        classes=sorted(masks["layering_entry"]), updates=updates)

    failures = [item for item in checks if item["status"] == "FAIL"]
    return {"status": "FAIL" if failures else "PASS",
            "detail": "; ".join(item["detail"] for item in failures) if failures else "instruction-class structure matched",
            "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check(json.loads(args.request.read_text()))
    except (KeyError, OSError, ValueError) as error:
        result = {"status": "FAIL", "detail": str(error), "checks": []}
    print(json.dumps(result))
    raise SystemExit(1 if result["status"] == "FAIL" else 0)


if __name__ == "__main__":
    main()
