#!/usr/bin/env python3
"""Check direct Clang object generation and the Clang-to-llc pipeline."""

from concurrent.futures import ThreadPoolExecutor
from fnmatch import fnmatchcase
import itertools
import json
from pathlib import Path
import re
import resource
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import runner


HERE = Path(__file__).resolve().parent
FUNCTIONS = ["identity", "codegen_calculate"]


def object_header(path, arch):
    """Require an actual little-endian relocatable RISC-V ELF object."""
    header = path.read_bytes()[:20]
    if (len(header) != 20 or header[:4] != b"\x7fELF" or header[5] != 1 or
            header[4] != (1 if arch == "rv32" else 2) or
            struct.unpack_from("<HH", header, 16) != (1, 243)):
        raise runner.TestError(f"not a relocatable {arch} object: {path}")


def check(args, tools, profile):
    arch, target, kind, mode, schedule = profile
    directory = (args.build_dir / arch /
                 f"{target['isa']}-{target['abi']}-{target['code_model']}" /
                 f"{kind}-{mode}-{schedule}")
    directory.mkdir(parents=True, exist_ok=True)
    result = dict(name="clang_codegen/" + kind, group="regression", arch=arch,
                  mode=mode, cfp="none", schedule=schedule, logdir=str(directory))
    build = lambda argv, label: runner.command(argv, directory, label, args.build_timeout)
    try:
        isa_flags = ["-march=" + target["isa"], "-mabi=" + target["abi"],
                     "-mcmodel=" + target["code_model"]]
        if not target["relax"]:
            isa_flags.append("-mno-relax")
        clang = [tools["clang"], "--target=riscv" + arch[2:], *isa_flags,
                 "-O2", "-ffreestanding"]
        if kind.startswith("identity"):
            # Keep the reported no-hardening invocation free of -mllvm flags.
            flags = ([] if mode == "none" else
                     ["-mllvm", "-EDDI=not_selected_for_hardening"])
            output = directory / "identity.o"
            build([*clang, *flags, "-c", HERE / "identity.c", "-o", output], "clang")
            object_header(output, arch)
            result.update(status="PASS", detail="direct Clang compilation produced a RISC-V object")
            return result
        selection = ",".join(FUNCTIONS)
        flags = [] if mode == "none" else ["-EDDI=" + selection]
        if mode != "none" and schedule == "fgs":
            flags.append("-FGS=" + selection)
        objects = []
        for source in ("identity.c", "clang_codegen.c"):
            stem = Path(source).stem
            output = directory / (stem + ".o")
            if kind == "direct":
                forwarded = [item for flag in [*flags, "-verify-machineinstrs"]
                             for item in ("-mllvm", flag)]
                compiled = build([*clang, "-fno-optimize-sibling-calls", *forwarded,
                                  "-c", HERE / source, "-o", output], stem + ".clang")
            else:
                ir = directory / (stem + ".ll")
                build([*clang, "-fno-optimize-sibling-calls", "-emit-llvm", "-S",
                       HERE / source, "-o", ir], stem + ".clang")
                compiled = build([tools["llc"], "-march=riscv" + arch[2:],
                                  "-mattr=" + ",".join(target["features"]),
                                  "-target-abi=" + target["abi"],
                                  "-code-model=" + ("small" if target["code_model"] == "medlow" else "medium"),
                                  "-O2", *flags, "-verify-machineinstrs", "-filetype=obj",
                                  ir, "-o", output], stem + ".llc")
            if mode != "none":
                function = "identity" if source == "identity.c" else "codegen_calculate"
                expected = f"COMPAS: Running EDDI pass with {schedule.upper()} on {function}"
                if expected not in compiled["stdout"].splitlines():
                    raise runner.TestError(f"EDDI was not applied to {function} with {schedule.upper()}")
            object_header(output, arch)
            objects.append(output)
        elf = directory / "test.elf"
        build([tools["cc"], *isa_flags, "-nostdlib", "-static", "-no-pie",
               "-Wl,--build-id=none", "-Wl,-Ttext=0x10000",
               *([] if target["relax"] else ["-Wl,--no-relax"]),
               runner.TESTS / "support/start.S", *objects, "-o", elf], "link")
        observed = runner.command([tools["qemu"][arch], "-strace", elf],
                                  directory, "run", args.timeout, check=False)
        exits = re.findall(r"\bexit(?:_group)?\((-?\d+)\)", observed["stderr"])
        if exits != ["42"] or observed["host_exit"] != 42 or observed["stdout"]:
            raise runner.TestError(f"independent runtime oracle failed: target exits {exits}")
        result.update(status="PASS", verification=dict(status="PASS", errors=[]),
                      detail="RISC-V objects, machine verifier and literal runtime oracle matched")
    except (runner.TestError, OSError, ValueError, struct.error) as error:
        result.update(status="ERROR", detail=str(error))
    return result


def main():
    cli = runner.parser("regression")
    cli.description = __doc__
    cli.set_defaults(build_dir=runner.TESTS.parent / "build/tests/clang_codegen")
    args = cli.parse_args()
    if args.timeout <= 0 or args.build_timeout <= 0 or args.jobs <= 0:
        cli.error("timeouts and jobs must be positive")
    if args.mode and any(mode not in ("none", "EDDI") for mode in args.mode):
        cli.error("clang_codegen supports --mode none and --mode EDDI")
    if args.cfp and any(cfp != "none" for cfp in args.cfp):
        cli.error("clang_codegen exercises DMR without CFP")
    if args.verify_machineinstrs is False:
        cli.error("machine verification is required by clang_codegen functional cases")
    if args.functions is not None or args.cfp_functions is not None:
        cli.error("clang_codegen uses fixed function selections")
    arches = args.arch or ["rv32", "rv64"]
    try:
        case = dict(adapter="freestanding", selected_arches=arches, isa="rv{bits}i")
        targets = {arch: runner.target_profiles(args, case, arch) for arch in arches}
        configurations = [("identity", "none", "cgs"),
                          ("identity_ignored", "EDDI", "cgs")]
        configurations += [(kind, mode, schedule)
                           for kind, mode, schedule in itertools.product(
                               ("direct", "llc"), ("none", "EDDI"), ("cgs", "fgs"))
                           if mode != "none" or schedule == "cgs"]
        profiles = [(arch, target, kind, mode, schedule)
                    for arch in arches for target in targets[arch]
                    for kind, mode, schedule in configurations
                    if (not args.mode or mode in args.mode)
                    and (not args.schedule or schedule in args.schedule)
                    and (not args.case or any(fnmatchcase("clang_codegen/" + kind, pattern)
                                             for pattern in args.case))]
        if not profiles:
            raise runner.TestError("no clang_codegen configurations selected")
        if args.list:
            for arch, target, kind, mode, schedule in profiles:
                print(f"clang_codegen/{kind} {arch} {mode}/none/{schedule}")
            return 0
        tools = runner.tools_for(args, [case])
        args.build_dir = args.build_dir.resolve()
        args.build_dir.mkdir(parents=True, exist_ok=True)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        results = []
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
