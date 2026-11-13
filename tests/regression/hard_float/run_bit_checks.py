#!/usr/bin/env python3
"""Exercise actual FP balance checks with controlled primary/shadow encodings."""

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
FUNCTION = "fp_bit_check_probe"


def patterns(kind):
    if kind == "double":
        same = {
            "quiet_nan": 0x7ff8000000000001,
            "negative_quiet_nan": 0xfff8123456789abc,
            "signaling_nan": 0x7ff0000000000001,
            "negative_signaling_nan": 0xfff0000012345678,
            "positive_zero": 0,
            "negative_zero": 0x8000000000000000,
            "positive_infinity": 0x7ff0000000000000,
            "negative_infinity": 0xfff0000000000000,
            "least_subnormal": 1,
            "greatest_subnormal": 0x000fffffffffffff,
            "finite_low_bits": 0x3ff0000000000001,
        }
        different = {
            "zero_sign": (0, 0x8000000000000000),
            "reverse_zero_sign": (0x8000000000000000, 0),
            "quiet_nan_payload": (0x7ff8000000000001, 0x7ff8000000000002),
            "signaling_nan_payload": (0x7ff0000000000001, 0x7ff0000000000002),
            "nan_sign": (0x7ff8000000000001, 0xfff8000000000001),
            "low_half": (0x3ff0000000000001, 0x3ff0000000000002),
            "high_half": (0x3ff0000000000001, 0x4000000000000001),
            "subnormal": (1, 2),
            "infinity_sign": (0x7ff0000000000000, 0xfff0000000000000),
        }
    else:
        same = {
            "quiet_nan": 0x7fc00001,
            "negative_quiet_nan": 0xffc12345,
            "signaling_nan": 0x7f800001,
            "negative_signaling_nan": 0xff812345,
            "positive_zero": 0,
            "negative_zero": 0x80000000,
            "positive_infinity": 0x7f800000,
            "negative_infinity": 0xff800000,
            "least_subnormal": 1,
            "greatest_subnormal": 0x007fffff,
            "finite_low_bits": 0x3f800001,
        }
        different = {
            "zero_sign": (0, 0x80000000),
            "reverse_zero_sign": (0x80000000, 0),
            "quiet_nan_payload": (0x7fc00001, 0x7fc00002),
            "signaling_nan_payload": (0x7f800001, 0x7f800002),
            "nan_sign": (0x7fc00001, 0xffc00001),
            "low_bits": (0x3f800001, 0x3f800002),
            "subnormal": (1, 2),
            "infinity_sign": (0x7f800000, 0xff800000),
        }
    selected = [("same_" + name, value, value, 42) for name, value in same.items()] + [
        ("different_" + name, left, right, -512)
        for name, (left, right) in different.items()]
    if kind == "float_nanboxed":
        # The primary is loaded with FLW and therefore has canonical upper
        # NaN-boxing bits. Load the entire shadow through FLD, retaining the
        # valid box for ordinary patterns and corrupting only it below.
        selected = [(name, left, 0xffffffff00000000 | right, expected)
                    for name, left, right, expected in selected]
        bad_boxes = {
            "finite_top_bit": (0x3f800001, 0x7fffffff3f800001),
            "finite_bottom_bit": (0x3f800001, 0xfffffffe3f800001),
            "finite_clear": (0x3f800001, 0x000000003f800001),
            "positive_zero": (0x00000000, 0xfffffffe00000000),
            "negative_zero": (0x80000000, 0x7fffffff80000000),
            "positive_infinity": (0x7f800000, 0xfffffffe7f800000),
            "quiet_nan": (0x7fc00001, 0xfffffffe7fc00001),
            "signaling_nan": (0x7f800001, 0x7fffffff7f800001),
            "least_subnormal": (0x00000001, 0xfffffffe00000001),
            "greatest_subnormal": (0x007fffff, 0x00000000007fffff),
        }
        selected += [("different_box_" + name, left, right, -512)
                     for name, (left, right) in bad_boxes.items()]
    return selected


def inject(assembly, kind):
    """Change only the shadow FP argument after ordinary-call bank setup.

    EDDI/SWIFT check this argument before the probe's FP store. The conventional
    argument is fa0; COMPAS's shadow argument is fs8. Reserved shadow-zero s11
    supplies an address and is restored before entering protected code. This
    does not alter the comparison, its branch or the primary input.
    """
    lines = assembly.splitlines()
    calls = [i for i, line in enumerate(lines)
             if re.fullmatch(r"\s*call\s+" + FUNCTION + r"(?:@plt)?\s*", line)]
    if len(calls) != 1:
        raise runner.TestError("expected exactly one direct call to the protected probe")
    index = calls[0]
    setup = re.compile(r"\s*fmv\.[sd]\s+fs8,\s*fa0\s*")
    if not any(setup.fullmatch(line) for line in lines[:index]):
        raise runner.TestError("ordinary caller did not initialize the FP argument shadow")
    load = "flw" if kind == "float" else "fld"
    insertion = ["\t# Controlled shadow-input mutation; primary and GPR bank stay intact.",
                 "\tlui\ts11, %hi(fp_probe_shadow)",
                 f"\t{load}\tfs8, %lo(fp_probe_shadow)(s11)",
                 "\tli\ts11, 0"]
    lines[index:index] = insertion
    return "\n".join(lines) + "\n"


def flags(target):
    return ["-march=" + target["isa"], "-mabi=" + target["abi"], "-mcmodel=medlow"]


def prepare(args, tools, profile):
    arch, kind, mode, schedule = profile
    double = kind == "double"
    wide_file = double or kind == "float_nanboxed"
    target = dict(isa=arch + "imaf" + ("d" if wide_file else ""),
                  abi=("ilp32" if arch == "rv32" else "lp64") + ("d" if wide_file else "f"))
    directory = args.build_dir / arch / kind / mode / schedule
    directory.mkdir(parents=True, exist_ok=True)
    build = lambda argv, label: runner.command(argv, directory, label, args.build_timeout)
    ir = directory / "input.ll"
    build([tools["clang"], "--target=riscv" + arch[2:], *flags(target),
           "-O1", "-fno-optimize-sibling-calls", "-emit-llvm", "-S",
           *(["-DFP_DOUBLE"] if double else []), HERE / "bit_check_probe.c", "-o", ir], "clang")
    assembly = directory / "generated.s"
    llc = [tools["llc"], "-march=riscv" + arch[2:],
           "-mattr=+m,+a,+f" + (",+d" if wide_file else ""),
           "-target-abi=" + target["abi"], "-O1", "-" + mode + "=" + FUNCTION,
           *(["-FGS=" + FUNCTION] if schedule == "fgs" else [])]
    build([*llc, ir, "-o", assembly], "llc")
    verified = directory / "generated.verify.s"
    build([*llc, "-verify-machineinstrs", ir, "-o", verified], "verify")
    injected = directory / "injected.s"
    injected.write_text(inject(assembly.read_text(), kind))
    # Check the same injection anchor in independently verified code generation.
    (directory / "injected.verify.s").write_text(inject(verified.read_text(), kind))
    return directory, target, injected


def check(args, tools, profile, prepared, pattern):
    arch, kind, mode, schedule = profile
    name, left, right, expected = pattern
    directory, target, assembly = prepared
    directory = directory / name
    directory.mkdir(parents=True, exist_ok=True)
    primary = left | (0xffffffff00000000 if kind == "float_nanboxed" else 0)
    result = dict(name="hard_float/bit_check/" + kind + "/" + name,
                  group="regression", arch=arch, mode=mode, cfp="none", schedule=schedule,
                  primary=hex(primary), shadow=hex(right), expected_exit=expected, logdir=str(directory))
    try:
        data = directory / "inputs.s"
        primary_directive = ".dword" if kind == "double" else ".word"
        shadow_directive = ".word" if kind == "float" else ".dword"
        data.write_text("\t.section .data\n" + "".join(
            f"\t.p2align 3\n\t.globl {symbol}\n{symbol}:\n\t{directive} 0x{value:x}\n"
            for symbol, value, directive in (("fp_probe_primary", left, primary_directive),
                                              ("fp_probe_shadow", right, shadow_directive))))
        elf = directory / "probe.elf"
        runner.command([tools["cc"], *flags(target), "-nostdlib", "-static", "-no-pie",
                        "-Wl,--build-id=none", "-Wl,-Ttext=0x10000",
                        runner.TESTS / "support/start.S", assembly, data, "-o", elf],
                       directory, "link", args.build_timeout)
        observed = runner.command([tools["qemu"][arch], "-strace", elf],
                                  directory, "run", args.timeout, check=False)
        exits = re.findall(r"\bexit(?:_group)?\((-?\d+)\)", observed["stderr"])
        if exits != [str(expected)] or observed["stdout"] or observed["host_exit"] != expected % 256:
            raise runner.TestError(f"expected target exit {expected}, observed exits {exits}, host {observed['host_exit']}")
        result.update(status="PASS", detail="actual FP monitor accepted equal bits or detected the controlled difference")
    except (runner.TestError, OSError, ValueError) as error:
        result.update(status="FAIL", detail=str(error))
    return result


def main():
    cli = runner.parser("regression")
    cli.description = __doc__
    cli.set_defaults(build_dir=runner.TESTS.parent / "build/tests/fp_bit_checks")
    args = cli.parse_args()
    if args.functions is not None or args.cfp_functions is not None:
        cli.error("FP bit checks require their fixed probe function selection")
    if args.cfp and args.cfp != ["none"]:
        cli.error("FP bit checks isolate the DMR monitor; use --cfp none")
    if args.mode and any(mode not in ("EDDI", "SWIFT") for mode in args.mode):
        cli.error("FP bit checks require the EDDI or SWIFT pre-store comparison")
    if args.verify_machineinstrs is False:
        cli.error("machine verification is required by FP bit checks")
    if args.timeout <= 0 or args.build_timeout <= 0 or args.jobs <= 0:
        cli.error("timeouts and jobs must be positive")
    if args.isa or args.abi or args.code_model:
        cli.error("FP bit checks use fixed F-only, D and NaN-boxed target profiles")
    profiles = list(itertools.product(args.arch or ["rv32", "rv64"],
                                     ["float", "double", "float_nanboxed"],
                                     args.mode or ["EDDI", "SWIFT"],
                                     args.schedule or ["cgs", "fgs"]))
    jobs = [(profile, pattern) for profile in profiles
            for pattern in patterns(profile[1])
            if not args.case or any(fnmatchcase("hard_float/bit_check/" + profile[1] + "/" + pattern[0], glob)
                                    for glob in args.case)]
    if not jobs:
        cli.error("no FP bit-check configurations selected")
    if args.list:
        for (arch, kind, mode, schedule), (name, *_rest) in jobs:
            print(f"hard_float/bit_check/{kind}/{name} {arch} {mode}/none/{schedule}")
        return 0
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        tools = runner.tools_for(args, [dict(adapter="freestanding", selected_arches=args.arch or ["rv32", "rv64"])])
        args.build_dir = args.build_dir.resolve()
        args.build_dir.mkdir(parents=True, exist_ok=True)
        selected = dict.fromkeys(profile for profile, _pattern in jobs)
        prepared = {profile: prepare(args, tools, profile) for profile in selected}
        results = []
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for result in pool.map(lambda job: check(args, tools, job[0], prepared[job[0]], job[1]), jobs):
                runner.emit(results, result)
        (args.build_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        return int(any(result["status"] != "PASS" for result in results))
    except (runner.TestError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
