"""Prepare and inspect actual machine memory operands at the hardening boundary."""

from collections import Counter
import re


FUNCTIONS = ("metadata_memory", "metadata_stack")
P2S = dict(zip((0, 1, 2, 3, 4, 5, 6, 8, 10, 11, 12, 13, 14, 15, 16, 17),
               (27, 7, 9, 22, 28, 29, 30, 31, 24, 25, 26, 21, 20, 23, 19, 18)))
LOADS = {"LB", "LBU", "LH", "LHU", "LW", "LWU", "LD"}
STORES = {"SB", "SH", "SW", "SD"}
PROVENANCE = re.compile(r"\b(?:from|into|on|basealign|dereferenceable|invariant)\b|!\w")


def documents(text):
    return [document for document in text.split("---\n")
            if any(re.search(r"^name: +" + name + r"$", document, re.MULTILINE)
                   for name in FUNCTIONS)]


def accesses(text):
    """Yield scalar load/store instructions without interpreting register flags."""
    for document in documents(text):
        function = re.search(r"^name: +(\w+)$", document, re.MULTILINE)[1]
        for line in document.splitlines():
            if " :: " not in line:
                continue
            instruction, memory = line.split(" :: ", 1)
            opcode = re.search(r"\b(" + "|".join(sorted(LOADS | STORES)) + r")\b", instruction)
            if not opcode:
                continue
            registers = re.findall(r"\$x(\d+)\b", instruction)
            if not registers:
                raise ValueError("memory fixture has no physical data register: " + line)
            yield dict(function=function, opcode=opcode[0], data=int(registers[0]),
                       instruction=instruction, memory=memory)


def prepare(text, arch):
    """Attach rich, rooted metadata to real fixture accesses before hardening.

    Machine-level decoration keeps optimizations from removing the contract
    being tested. The named metadata roots make node identities serializable
    across both LLVM 13 and 16. Runtime instructions and register flags stay as
    emitted by the normal compiler pipeline.
    """
    del arch  # Scalar MMO widths are obtained from the compiler's actual MIR.
    constant_names = set(re.findall(
        r"^\s+%([-a-zA-Z$._0-9]+) = getelementptr .*@metadata_constant\b", text, re.MULTILINE))
    first = max((int(number) for number in re.findall(r"!(\d+)", text)), default=-1) + 1
    node = lambda index: "!" + str(first + index)
    definitions = [
        f'{node(0)} = !{{!"COMPAS metadata type"}}',
        f'{node(1)} = !{{!"COMPAS metadata scalar", {node(0)}, i64 0}}',
        f'{node(2)} = !{{{node(1)}, {node(1)}, i64 0}}',
        f'{node(3)} = distinct !{{{node(3)}, !"COMPAS alias domain"}}',
        f'{node(4)} = distinct !{{{node(4)}, {node(3)}, !"COMPAS scope"}}',
        f'{node(5)} = !{{{node(4)}}}',
        f'{node(6)} = distinct !{{{node(6)}, {node(3)}, !"COMPAS other scope"}}',
        f'{node(7)} = !{{{node(6)}}}',
        f'{node(8)} = !{{i32 0, i32 2147483647}}',
        f'{node(9)} = !{{i64 0, i64 9223372036854775807}}',
    ]
    roots = ", ".join(node(index) for index in range(len(definitions)))
    definitions.insert(0, f"!compas_memory_fixture = !{{{roots}}}")
    module_end = text.index("\n...\n")
    text = text[:module_end] + "\n" + "\n".join("  " + line for line in definitions) + text[module_end:]
    parts = text.split("---\n")
    decorated = 0
    for index, document in enumerate(parts):
        if not any(re.search(r"^name: +" + name + r"$", document, re.MULTILINE)
                   for name in FUNCTIONS):
            continue
        lines = []
        for line in document.splitlines():
            if " :: " not in line:
                lines.append(line)
                continue
            instruction, memory = line.split(" :: ", 1)
            # Exclude CSI/private preservation accesses. They describe real
            # frame objects and are checked separately by the machine verifier.
            constant_access = ("@metadata_constant" in memory or
                               any(re.search(r"%ir\." + re.escape(name) + r"\b", memory)
                                   for name in constant_names))
            selected = ("volatile " in memory or constant_access
                        or "@metadata_atomic" in memory or "@metadata_plain" in memory
                        or "%fixed-stack." in memory)
            if not selected or not any(re.search(r"\b" + opcode + r"\b", instruction)
                                       for opcode in LOADS | STORES):
                lines.append(line)
                continue
            if not (memory.startswith("(") and memory.endswith(")")) or "), (" in memory:
                raise ValueError("metadata fixture expects one scalar MMO: " + line)
            memory = re.sub(r", !(?:tbaa|alias\.scope|noalias|range) !\d+", "", memory)
            # Describe the aligned global's field through its root plus an
            # offset. This is equivalent to the compiler's GEP-valued MMO,
            # and exposes getBaseAlign() != getAlign() to the shadow rewrite.
            global_offset = re.search(r"@metadata_global \+ (4|8)\b", instruction)
            if global_offset and re.search(r"(?:from|into) `[^`]*@metadata_global[^`]*`", memory):
                memory = re.sub(r"(from|into) `[^`]*@metadata_global[^`]*`",
                                r"\1 @metadata_global + " + global_offset[1], memory)
                memory = re.sub(r", (?:align|basealign) \d+", "", memory)
                memory = memory[:-1] + ", basealign 64)"
            if "non-temporal " not in memory:
                memory = memory.replace("(", "(non-temporal ", 1)
            if "load " in memory and "dereferenceable " not in memory:
                memory = memory.replace("load ", "dereferenceable load ", 1)
            if constant_access and "invariant " not in memory:
                memory = memory.replace("load ", "invariant load ", 1)
            if "@metadata_atomic" in memory and "syncscope(" not in memory:
                memory = re.sub(r"\b(load|store) ", r'\1 syncscope("singlethread") ', memory, count=1)
            tags = f", !tbaa {node(2)}, !alias.scope {node(5)}, !noalias {node(7)}"
            if "load " in memory:
                width = re.search(r"\(s(32|64)\)", memory)
                if width:
                    tags += ", !range " + node(8 if width[1] == "32" else 9)
            memory = memory[:-1] + tags + ")"
            lines.append(instruction + " :: " + memory)
            decorated += 1
        parts[index] = "\n".join(lines) + "\n"
    if decorated < 8:
        raise ValueError(f"memory fixture exposed only {decorated} metadata accesses")
    return "---\n".join(parts)


def normalize(memory):
    # LLVM's serialization can renumber rooted metadata definitions.
    return re.sub(r"!\d+", "!NODE", memory)


def contract(memory):
    """Access facts which remain valid after primary provenance is discarded."""
    scalar = re.search(r"\(s(\d+)\)", memory)
    if not scalar:
        raise ValueError("expected scalar MMO type: " + memory)
    width = int(scalar[1])
    alignment = re.search(r"(?:^|, )align (\d+)", memory)
    # MIR omits effective alignment when it equals the access size.
    alignment = int(alignment[1]) if alignment else (width + 7) // 8
    address_space = re.search(r"\baddrspace (\d+)", memory)
    access = memory[1:scalar.start()]
    access = re.sub(r"\b(?:dereferenceable|invariant) +", "", access)
    return (access.strip(), width, alignment,
            int(address_space[1]) if address_space else 0)


def check(before, after, arch):
    del arch
    original = [item for item in accesses(before)
                if "!alias.scope" in item["memory"] or "%stack." in item["memory"]]
    final = list(accesses(after))
    primaries = Counter((item["function"], item["opcode"], item["data"], normalize(item["memory"]))
                        for item in final)
    shadows = Counter((item["function"], item["opcode"], item["data"], contract(item["memory"]))
                      for item in final if not PROVENANCE.search(item["memory"]))
    shapes = set()
    for item in original:
        key = (item["function"], item["opcode"], item["data"], normalize(item["memory"]))
        if not primaries[key]:
            raise ValueError("primary memory metadata changed: " + str(item))
        primaries[key] -= 1
        if item["data"] not in P2S:
            raise ValueError("fixture used a reserved shadow data register: " + str(item))
        shadow_key = (item["function"], item["opcode"], P2S[item["data"]], contract(item["memory"]))
        if not shadows[shadow_key]:
            raise ValueError("independent shadow MMO missing or changed access facts: " + str(item))
        shadows[shadow_key] -= 1
        memory = item["memory"]
        shapes.add("incoming" if "%fixed-stack." in memory else
                   "private" if "%stack." in memory or "%ir." in memory else "global")
    if len(original) < 8 or not {"incoming", "private", "global"}.issubset(shapes):
        raise ValueError("fixture no longer covers incoming/private/global accesses: " + str(shapes))
    if not any("invariant " in item["memory"] for item in original):
        raise ValueError("fixture lost its invariant primary load")
    if not any("syncscope(" in item["memory"] and "monotonic " in item["memory"] for item in original):
        raise ValueError("fixture lost its atomic scope/order accesses")
    if not any("basealign 64" in item["memory"] for item in original):
        raise ValueError("fixture lost its distinct base/effective alignments")
    return dict(primary_operands=len(original), independent_shadow_operands=len(original),
                access_shapes=sorted(shapes), atomic_scope_order=True,
                provenance_flags_removed=True, effective_alignment_preserved=True)


def check_loadbacks(before, after, arch):
    """Store loadbacks are fresh loads, rather than ordinary EDDI duplicates."""
    del arch
    original = [item for item in accesses(before)
                if item["opcode"] in STORES and "@metadata_plain" in item["memory"]]
    final = list(accesses(after))
    checked = 0
    for item in original:
        if any(word in item["memory"] for word in
               ("volatile ", "monotonic ", "acquire ", "release ", "seq_cst ")):
            raise ValueError("loadback fixture became an ordered store")
        if not any(candidate["function"] == item["function"] and
                   candidate["opcode"] == item["opcode"] and
                   candidate["data"] == item["data"] and
                   normalize(candidate["memory"]) == normalize(item["memory"])
                   for candidate in final):
            raise ValueError("S3 primary store metadata changed: " + str(item))
        registers = re.findall(r"\$x(\d+)\b", item["instruction"])
        if len(registers) < 2 or int(registers[1]) not in P2S:
            raise ValueError("loadback fixture lost a mapped primary address register")
        expected_base = P2S[int(registers[1])]
        opcode = {"SB": "LB", "SH": "LH", "SW": "LW", "SD": "LD"}[item["opcode"]]
        _, width, alignment, _ = contract(item["memory"])
        matches = []
        for candidate in final:
            if (candidate["function"] != item["function"] or
                    candidate["opcode"] != opcode or PROVENANCE.search(candidate["memory"])):
                continue
            registers = re.findall(r"\$x(\d+)\b", candidate["instruction"])
            if len(registers) >= 2 and int(registers[1]) == expected_base:
                if contract(candidate["memory"]) == ("load", width, alignment, 0):
                    matches.append(candidate)
        if len(matches) != 1:
            raise ValueError("expected one independent S3 loadback: " + str(item))
        checked += 1
    if not checked:
        raise ValueError("fixture lost its ordinary nonvolatile store loadback")
    return dict(primary_store_operands=checked, independent_loadbacks=checked)
