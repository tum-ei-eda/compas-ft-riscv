#!/usr/bin/env python3
"""Verify shadow call and memory metadata through the normal COMPAS pipeline."""

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
import calls
import memory


HERE = Path(__file__).resolve().parent
FUNCTIONS = ["metadata_memory", "metadata_stack", "metadata_indirect",
             "metadata_integer_leaf"]


def flags_for(target):
    flags = ["-march=" + target["isa"], "-mabi=" + target["abi"],
             "-mcmodel=" + target["code_model"]]
    return flags + ([] if target["relax"] else ["-mno-relax"])


def check(args, tools, final_checkpoint, profile):
    arch, target, floating, mode, cfp, schedule = profile
    kind = "hard_float" if floating else "integer"
    directory = (args.build_dir / arch /
                 f"{target['isa']}-{target['abi']}-{target['code_model']}" /
                 f"{kind}-{mode}-{cfp}-{schedule}")
    directory.mkdir(parents=True, exist_ok=True)
    result = dict(name="machine_metadata/" + kind, group="regression", arch=arch,
                  mode=mode, cfp=cfp, schedule=schedule, logdir=str(directory))
    build = lambda argv, label: runner.command(argv, directory, label, args.build_timeout)
    try:
        functions = FUNCTIONS + (["metadata_float_indirect", "metadata_float_leaf"]
                                 if floating else [])
        selection = ",".join(functions)
        flags = ["-" + mode + "=" + selection]
        if cfp != "none":
            flags.append("-" + cfp + "=" + selection)
        if schedule == "fgs":
            flags.append("-FGS=" + selection)
        ir = directory / "input.ll"
        build([tools["clang"], "--target=riscv" + arch[2:], *flags_for(target),
               "-O1", "-fno-optimize-sibling-calls", "-emit-llvm", "-S",
               *(["-DMETADATA_FLOAT"] if floating else []),
               HERE / "machine_metadata.c", "-o", ir], "clang")
        base_llc = [tools["llc"], "-march=riscv" + arch[2:],
                    "-mattr=" + ",".join(target["features"]),
                    "-target-abi=" + target["abi"],
                    "-code-model=" + ("small" if target["code_model"] == "medlow" else "medium"),
                    "-O1", "-verify-machineinstrs"]
        llc = [*base_llc, *flags]
        early = directory / "before-pei.mir"
        build([*llc, "-stop-before=prologepilog", ir, "-o", early], "before-pei")
        prepared = directory / "metadata-input.mir"
        prepared.write_text(memory.prepare(early.read_text(), arch))
        # Resume before PEI: COMPAS's private frame indices are target-owned
        # state, not serialized MIR fields. PEI reconstructs them normally.
        before = directory / "before-compas.mir"
        after = directory / "after-compas.mir"
        build([*llc, "-start-before=prologepilog",
               "-stop-after=livedebugvalues", prepared, "-o", before], "before-compas")
        build([*llc, "-start-before=prologepilog", "-stop-after=" + final_checkpoint,
               prepared, "-o", after], "after-compas")
        result["calls"] = calls.check(before.read_text(), after.read_text(), mode, arch, target["abi"])
        if mode == "EDDI":
            result["memory"] = memory.check(before.read_text(), after.read_text(), arch)
        elif mode.startswith("NZDC"):
            result["loadbacks"] = memory.check_loadbacks(before.read_text(), after.read_text(), arch)
        probes = []
        for label, text, expect_failure in calls.mask_probes(after.read_text(), mode, arch):
            probe = directory / ("mask-" + label + ".mir")
            probe.write_text(text)
            observation = runner.command(
                [*base_llc, "-run-pass=machineverifier", probe, "-o", "/dev/null"],
                directory, "mask-" + label, args.build_timeout, check=False)
            if expect_failure:
                if (observation["host_exit"] == 0 or
                        "Using an undefined physical register" not in observation["stderr"] or
                        "$" + label not in observation["stderr"]):
                    raise runner.TestError(f"mask probe ${label} did not report its expected undefined use")
            elif observation["host_exit"] != 0:
                raise runner.TestError(f"mask probe ${label} unexpectedly failed verification")
            probes.append(dict(register=label, expected_undefined=expect_failure, status="PASS"))
        result["mask_probes"] = probes
        assembly = directory / "output.s"
        build([*llc, "-start-before=prologepilog", prepared, "-o", assembly], "resume")
        elf = directory / "test.elf"
        build([tools["cc"], *flags_for(target), "-nostdlib", "-static", "-no-pie",
               "-Wl,--build-id=none", "-Wl,-Ttext=0x10000",
               *([] if target["relax"] else ["-Wl,--no-relax"]),
               runner.TESTS / "support/start.S", assembly, "-o", elf], "link")
        observed = runner.command([tools["qemu"][arch], "-strace", elf],
                                  directory, "run", args.timeout, check=False)
        exits = re.findall(r"\bexit(?:_group)?\((-?\d+)\)", observed["stderr"])
        if exits != ["42"] or observed["host_exit"] != 42 or observed["stdout"]:
            raise runner.TestError(f"independent runtime oracle failed: target exits {exits}")
        result.update(status="PASS", detail="call/memory metadata, actual verifier and literal runtime oracle matched")
    except (runner.TestError, OSError, ValueError, StopIteration, IndexError) as error:
        result.update(status="ERROR", detail=str(error))
    return result


def main():
    cli = runner.parser("regression")
    cli.description = __doc__
    cli.set_defaults(build_dir=runner.TESTS.parent / "build/tests/machine_metadata")
    args = cli.parse_args()
    if args.timeout <= 0 or args.build_timeout <= 0 or args.jobs <= 0:
        cli.error("timeouts and jobs must be positive")
    if args.mode and "none" in args.mode:
        cli.error("metadata profiles require a DMR mode; unprotected references always run")
    if args.verify_machineinstrs is False:
        cli.error("machine verification is required by machine_metadata")
    if args.functions is not None or args.cfp_functions is not None:
        cli.error("machine_metadata uses fixed function selections")
    arches = args.arch or ["rv32", "rv64"]
    try:
        cases = {}
        for floating in (False, True):
            cases[floating] = dict(adapter="freestanding", selected_arches=arches,
                                   directory=HERE, sources=["machine_metadata.c"],
                                   defines=["METADATA_FLOAT"] if floating else [],
                                   isa="rv{bits}imafd" if floating else "rv{bits}ima",
                                   verify_machineinstrs=True, expected=dict(exit=42, stdout=""))
        targets = {}
        for arch, floating in itertools.product(arches, cases):
            case = dict(cases[floating], abi=("ilp32" if arch == "rv32" else "lp64") +
                        ("d" if floating else ""))
            targets[arch, floating] = runner.target_profiles(args, case, arch)
        profiles = [(arch, target, floating, mode, cfp, schedule)
                    for arch, floating, mode, cfp, schedule in itertools.product(
                        arches, cases, args.mode or runner.MODES[1:],
                        args.cfp or runner.CFPS, args.schedule or ["cgs", "fgs"])
                    for target in targets[arch, floating]
                    if not args.case or any(fnmatchcase("machine_metadata/" +
                        ("hard_float" if floating else "integer"), pattern) for pattern in args.case)]
        if not profiles:
            raise runner.TestError("no machine_metadata configurations selected")
        if args.list:
            for arch, target, floating, mode, cfp, schedule in profiles:
                print(f"machine_metadata/{'hard_float' if floating else 'integer'} {arch} {mode}/{cfp}/{schedule}")
            return 0
        tools = runner.tools_for(args, list(cases.values()))
        args.build_dir = args.build_dir.resolve()
        args.build_dir.mkdir(parents=True, exist_ok=True)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # COMPAS is unregistered. Its following remark pass gives a stable
        # YAML checkpoint; the instance number varies with the LLVM pipeline.
        pipeline = runner.command([tools["llc"], "-march=riscv" + arches[0][2:],
                                   "-debug-pass=Arguments", "/dev/null", "-o", "/dev/null"],
                                  args.build_dir, "pipeline", args.build_timeout)
        arguments = next(line for line in pipeline["stderr"].splitlines()
                         if line.startswith("Pass Arguments:"))
        count = arguments.split().count("-machine-opt-remark-emitter")
        if count == 0:
            raise runner.TestError("LLVM pipeline has no final machine remark checkpoint")
        checkpoint = "machine-opt-remark-emitter," + str(count - 1)
        results = []
        for arch, target, floating in dict.fromkeys((p[0], json.dumps(p[1], sort_keys=True), p[2]) for p in profiles):
            target = json.loads(target)
            directory = args.build_dir / arch / ("reference-float" if floating else "reference-integer") / \
                        f"{target['isa']}-{target['abi']}-{target['code_model']}"
            reference = dict(name="machine_metadata/reference", group="regression", arch=arch,
                             mode="reference", cfp="none", schedule="cgs", logdir=str(directory))
            case = cases[floating]
            observed, verification = runner.build_and_run(
                args, tools, case, arch, "none", "none", "cgs", [], [], directory, target)
            if not runner.oracle_matches(case, observed) or verification["status"] != "PASS":
                raise runner.TestError(f"unprotected fixture violates its oracle or verifier: {directory}")
            reference.update(status="PASS", detail="unprotected reference and literal oracle matched")
            runner.emit(results, reference)
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for result in pool.map(lambda profile: check(args, tools, checkpoint, profile), profiles):
                runner.emit(results, result)
        (args.build_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        return int(any(result["status"] != "PASS" for result in results))
    except (runner.TestError, OSError, ValueError, StopIteration) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
