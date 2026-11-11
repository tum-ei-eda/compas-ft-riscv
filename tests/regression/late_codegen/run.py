#!/usr/bin/env python3
"""Check late preservation with a large existing fixed area in machine IR."""

from concurrent.futures import ThreadPoolExecutor
from fnmatch import fnmatchcase
import itertools
import json
from pathlib import Path
import re
import resource
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import runner


HERE = Path(__file__).resolve().parent
PROFILES = {"signature": ("none", []),
            "caller_context": ("EDDI", ["late_caller"]),
            "callee_context": ("EDDI", ["late_leaf"])}


def reserve_fixed_area(text, define_scratch):
    """Model an existing target-owned fixed object before PEI assigns CSI."""
    documents = text.split("---\n")
    count = 0
    for index, document in enumerate(documents):
        if not re.search(r"^name: +late_caller$", document, re.MULTILINE):
            continue
        if "fixedStack:      []" not in document:
            raise runner.TestError("late_caller already has fixed objects; review the MIR fixture")
        document = document.replace(
            "fixedStack:      []",
            "fixedStack:\n  - { id: 0, type: default, offset: -4096, size: 4096, "
            "alignment: 16, isImmutable: false, isAliased: false }")
        # The helper borrows caller-clobbered x7. Give that otherwise
        # unspecified register a real definition, without inventing a live-in.
        if define_scratch:
            lines = document.splitlines()
            body = next(i for i, line in enumerate(lines) if line == "body:             |")
            insertion = next(i for i in range(body + 1, len(lines))
                             if lines[i].startswith("    ") and lines[i].strip()
                             and not lines[i].lstrip().startswith(("liveins:", "successors:")))
            lines.insert(insertion, "    $x7 = ADDI $x0, 211")
            document = "\n".join(lines) + "\n"
        documents[index] = document
        count += 1
    if count != 1:
        raise runner.TestError(f"expected exactly one late_caller, found {count}")
    return "---\n".join(documents)


def check(args, tools, profile):
    arch, target, name, cfp, schedule = profile
    mode, functions = PROFILES[name]
    directory = (args.build_dir / arch /
                 f"{target['isa']}-{target['abi']}-{target['code_model']}" /
                 f"{name}-{cfp}-{schedule}")
    directory.mkdir(parents=True, exist_ok=True)
    result = dict(name="late_codegen/" + name, group="regression", arch=arch,
                  mode=mode, cfp=cfp, schedule=schedule, logdir=str(directory))
    build = lambda argv, label: runner.command(argv, directory, label, args.build_timeout)
    try:
        ir = directory / "input.ll"
        isa_flags = ["-march=" + target["isa"], "-mabi=" + target["abi"],
                     "-mcmodel=" + target["code_model"]]
        if not target["relax"]:
            isa_flags.append("-mno-relax")
        build([tools["clang"], "--target=riscv" + arch[2:], *isa_flags,
               "-O1", "-fno-optimize-sibling-calls", "-emit-llvm", "-S",
               HERE / "late_codegen.c", "-o", ir], "clang")
        flags = ["-" + cfp + "=late_caller"]
        if mode != "none":
            flags.append("-EDDI=" + ",".join(functions))
            if schedule == "fgs":
                flags.append("-FGS=" + ",".join(functions))
        llc = [tools["llc"], "-march=riscv" + arch[2:],
               "-mattr=" + ",".join(target["features"]),
               "-target-abi=" + target["abi"],
               "-code-model=" + ("small" if target["code_model"] == "medlow" else "medium"),
               "-O1", *flags, "-verify-machineinstrs"]
        before = directory / "before-pei.mir"
        build([*llc, "-stop-before=prologepilog", ir, "-o", before], "before-pei")
        padded = directory / "large-fixed-area.mir"
        # In a protected caller x7 is initialized as EDDI's shadow RA. An
        # original instruction must never write this reserved shadow register.
        padded.write_text(reserve_fixed_area(before.read_text(), name != "caller_context"))
        layout = directory / "after-pei.mir"
        build([*llc, "-start-before=prologepilog", "-stop-after=prologepilog",
               padded, "-o", layout], "layout")
        caller_layout = next(document for document in layout.read_text().split("---\n")
                             if re.search(r"^name: +late_caller$", document, re.MULTILINE))
        objects = sorted((int(offset), int(size)) for offset, size in re.findall(
            r"\boffset: (-?\d+), size: (\d+)", caller_layout.split("body:", 1)[0]))
        if (not objects or objects[-1] != (-4096, 4096)
                or any(offset + size > following
                       for (offset, size), (following, _) in zip(objects, objects[1:]))):
            raise runner.TestError("PEI produced overlapping objects or lost the fixed-area fixture")
        result["frame_objects"] = [dict(offset=offset, size=size) for offset, size in objects]
        assembly = directory / "output.s"
        build([*llc, "-start-before=prologepilog", padded, "-o", assembly], "resume")
        emitted = assembly.read_text().split("late_caller:", 1)[1].split(".Lfunc_end", 1)[0]
        # Confirm the fixture reaches both large-address helpers rather than
        # merely exercising a large ordinary local frame.
        if not re.search(r"\badd\s+t[45],\s*s0,\s*t[45]", emitted):
            raise runner.TestError("fixture did not materialize a large signature address")
        if mode != "none" and not re.search(r"\badd\s+s11,\s*s0,\s*s11", emitted):
            raise runner.TestError("fixture did not materialize a large DMR context address")
        elf = directory / "test.elf"
        build([tools["cc"], *isa_flags, "-nostdlib", "-static", "-no-pie",
               "-Wl,--build-id=none", "-Wl,-Ttext=0x10000",
               *([] if target["relax"] else ["-Wl,--no-relax"]),
               runner.TESTS / "support/start.S", assembly, "-o", elf], "link")
        outcome = runner.command([tools["qemu"][arch], "-strace", elf],
                                 directory, "run", args.timeout, check=False)
        exits = re.findall(r"\bexit(?:_group)?\((-?\d+)\)", outcome["stderr"])
        if (exits != ["42"] or outcome["host_exit"] != 42 or outcome["stdout"]):
            raise runner.TestError(f"independent oracle failed: target exits {exits}; see {directory}")
        result.update(status="PASS", detail="machine verifier and independent arithmetic/side-effect oracle matched")
    except (runner.TestError, OSError, ValueError, StopIteration, IndexError) as error:
        result.update(status="ERROR", detail=str(error))
    return result


def main():
    cli = runner.parser("regression")
    cli.description = __doc__
    cli.set_defaults(build_dir=runner.TESTS.parent / "build/tests/late_codegen")
    args = cli.parse_args()
    if args.timeout <= 0 or args.build_timeout <= 0 or args.jobs <= 0:
        cli.error("timeouts and jobs must be positive")
    if args.mode and any(mode not in ("none", "EDDI") for mode in args.mode):
        cli.error("late_codegen supports --mode none (signature) and --mode EDDI (call contexts)")
    if args.cfp and "none" in args.cfp:
        cli.error("late_codegen requires CFCSS, RASM or RACFED")
    if args.verify_machineinstrs is False:
        cli.error("machine verification is required by late_codegen")
    if args.functions is not None or args.cfp_functions is not None:
        cli.error("late_codegen uses fixed function selections for each compiler fixture")
    arches = args.arch or ["rv32", "rv64"]
    try:
        case = dict(adapter="freestanding", selected_arches=arches, directory=HERE,
                    sources=["late_codegen.c"], verify_machineinstrs=True,
                    expected=dict(exit=42, stdout=""))
        targets = {arch: runner.target_profiles(args, case, arch) for arch in arches}
        profiles = [(arch, target, name, cfp, schedule)
                    for arch, name, cfp, schedule in itertools.product(
                        arches, PROFILES, args.cfp or ["CFCSS", "RASM", "RACFED"],
                        args.schedule or ["cgs", "fgs"])
                    for target in targets[arch]
                    if (not args.mode or PROFILES[name][0] in args.mode)
                    and (not args.case or any(fnmatchcase("late_codegen/" + name, pattern)
                                             for pattern in args.case))
                    and (name != "signature" or schedule == "cgs")]
        if not profiles:
            raise runner.TestError("no late_codegen configurations selected")
        if args.list:
            for arch, target, name, cfp, schedule in profiles:
                print(f"late_codegen/{name} {arch} {PROFILES[name][0]}/{cfp}/{schedule}")
            return 0
        tools = runner.tools_for(args, [case])
        args.build_dir = args.build_dir.resolve()
        args.build_dir.mkdir(parents=True, exist_ok=True)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        results = []
        for arch in arches:
            for target in targets[arch]:
                directory = (args.build_dir / arch /
                             f"{target['isa']}-{target['abi']}-{target['code_model']}" / "reference")
                result = dict(name="late_codegen/reference", group="regression", arch=arch,
                              mode="reference", cfp="none", schedule="cgs", logdir=str(directory))
                observed, verification = runner.build_and_run(
                    args, tools, case, arch, "none", "none", "cgs", [], [], directory, target)
                if not runner.oracle_matches(case, observed) or verification["status"] != "PASS":
                    raise runner.TestError(f"unprotected fixture violates its oracle or verifier: {directory}")
                result.update(status="PASS", detail="unprotected reference and independent oracle matched")
                runner.emit(results, result)
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for result in pool.map(lambda profile: check(args, tools, profile), profiles):
                runner.emit(results, result)
        (args.build_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        return int(any(result["status"] != "PASS" for result in results))
    except (runner.TestError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
