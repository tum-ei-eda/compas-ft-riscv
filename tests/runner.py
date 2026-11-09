"""Manifest-driven, fault-free functional equivalence checks for COMPAS."""

import argparse
from collections import Counter
import fnmatch
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import signal
import subprocess
import sys


TESTS = Path(__file__).resolve().parent
MODES = ("none", "EDDI", "SWIFT", "NZDC", "NZDC+NEMESIS", "NZDC+NEMESEC")
CFPS = ("none", "CFCSS", "RASM", "RACFED")


class TestError(Exception):
    """An invalid test setup, build, or simulator execution."""


def function_list(value):
    return [part.strip() for part in re.split("[,;]", value) if part.strip()]


def parser(default_suite):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--suite", choices=("all", "regression", "apps"), default=default_suite)
    cli.add_argument("--list", action="store_true", help="list selected cases without requiring tools")
    cli.add_argument("--case", action="append", help="repeatable suite/case glob")
    cli.add_argument("--arch", action="append", choices=("rv32", "rv64"))
    cli.add_argument("--mode", action="append", choices=MODES)
    cli.add_argument("--schedule", action="append", choices=("cgs", "fgs"))
    cli.add_argument("--cfp", action="append", choices=CFPS)
    cli.add_argument("--functions", type=function_list, help="override DMR functions (comma/semicolon list)")
    cli.add_argument("--cfp-functions", type=function_list, help="override CFP functions (comma/semicolon list)")
    for option, env in (("clang", "COMPAS_CLANG"), ("llc", "COMPAS_LLC"),
                        ("llvm-root", "COMPAS_LLVM_ROOT"), ("cc", "RISCV_CC"),
                        ("qemu", "RISCV_QEMU"), ("spike", "RISCV_SPIKE"),
                        ("pk", "RISCV_PK"), ("riscv-prefix", "RISCV_TOOLCHAIN_PREFIX"),
                        ("riscv-basename", "RISCV_TOOLCHAIN_BASENAME")):
        cli.add_argument("--" + option, default=os.environ.get(env), help=f"default: ${env}")
    cli.add_argument("--build-dir", type=Path, default=TESTS.parent / "build" / "tests")
    cli.add_argument("--timeout", type=float, default=5, help="execution timeout in seconds (default: 5)")
    cli.add_argument("--build-timeout", type=float, default=180, help="per-command build timeout (default: 180)")
    cli.add_argument("--jobs", type=int, default=2, help="CMake build jobs (default: 2)")
    cli.add_argument("--allow-xpass", action="store_true", help="do not fail on stale known-failure expectations")
    return cli


def discover(args):
    selected = []
    seen = set()
    groups = ("regression", "apps") if args.suite == "all" else (args.suite,)
    for group in groups:
        for manifest in sorted((TESTS / group).rglob("suite.json")):
            try:
                suite = json.loads(manifest.read_text())
                if suite["adapter"] not in ("freestanding", "cmake"):
                    raise ValueError("adapter must be freestanding or cmake")
                if not re.fullmatch(r"[A-Za-z0-9_-]+", suite["name"]):
                    raise ValueError("suite name must contain only letters, digits, '_' or '-'")
                for case in suite["cases"]:
                    if not re.fullmatch(r"[A-Za-z0-9_-]+", case["name"]):
                        raise ValueError("invalid case name")
                    name = f"{suite['name']}/{case['name']}"
                    if name in seen:
                        raise ValueError(f"duplicate case: {name}")
                    seen.add(name)
                    config = {**suite, **case}
                    config.update(suite_name=suite["name"], name=name, group=group,
                                  directory=manifest.parent, case_name=case["name"])
                    expected = config["expected"]
                    if not isinstance(expected["exit"], int):
                        raise ValueError("expected.exit must be an integer")
                    if ("stdout" in expected) == ("stdout_file" in expected):
                        raise ValueError("expected must specify exactly one of stdout or stdout_file")
                    if "stdout_file" in expected:
                        config["expected"] = {**expected, "stdout":
                            (manifest.parent / expected["stdout_file"]).read_text()}
                    if not isinstance(config["expected"]["stdout"], str):
                        raise ValueError("expected stdout must be a string")
                    arches = config["architectures"]
                    if not arches or any(arch not in ("rv32", "rv64") for arch in arches):
                        raise ValueError("architectures must contain rv32 and/or rv64")
                    for field, default, choices in (("modes", ["EDDI", "SWIFT"], MODES),
                                                     ("cfp_modes", ["none"], CFPS),
                                                     ("schedules", ["cgs"], ("cgs", "fgs"))):
                        values = config.get(field, default)
                        if not isinstance(values, list) or not values or any(value not in choices for value in values):
                            raise ValueError(f"{field} must be a nonempty list drawn from {choices}")
                    for field in ("functions", "defines"):
                        values = config.get(field, [])
                        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                            raise ValueError(f"{field} must be a list of strings")
                    if config["adapter"] == "freestanding":
                        sources = config["sources"]
                        if not isinstance(sources, list) or not sources or any(not isinstance(value, str) for value in sources):
                            raise ValueError("sources must be a nonempty list of paths")
                    elif not isinstance(config["executable"], str) or not config["executable"]:
                        raise ValueError("CMake suites require an executable path")
                    if args.case and not any(fnmatch.fnmatchcase(name, pattern) for pattern in args.case):
                        continue
                    config["selected_arches"] = [a for a in (args.arch or arches) if a in arches]
                    if config["selected_arches"]:
                        selected.append(config)
            except (OSError, ValueError, KeyError, TypeError) as error:
                raise TestError(f"{manifest}: {error}") from error
    if not selected:
        raise TestError("no cases match the requested suite, case and architecture selection")
    return selected


def executable(value):
    found = shutil.which(str(value))
    if not found:
        raise TestError(f"required executable not found: {value}")
    return str(Path(found).resolve())


def tools_for(args, cases):
    llvm_root = Path(args.llvm_root).expanduser().resolve() if args.llvm_root else None
    clang = executable(args.clang or (llvm_root / "bin/clang" if llvm_root else "clang"))
    llc = executable(args.llc or (llvm_root / "bin/llc" if llvm_root else "llc"))
    prefix = Path(args.riscv_prefix).expanduser().resolve() if args.riscv_prefix else None
    basename = args.riscv_basename or "riscv-none-elf"
    cc = executable(args.cc or (prefix / "bin" / (basename + "-gcc") if prefix else basename + "-gcc"))
    if args.cc and not args.riscv_basename and Path(cc).name.endswith("-gcc"):
        basename = Path(cc).name[:-4]
    if not prefix:
        prefix = Path(cc).parent.parent
    tools = dict(clang=clang, llc=llc, cc=cc, prefix=str(prefix), basename=basename,
                 llvm_root=str(llvm_root or Path(llc).parent.parent))
    adapters = {case["adapter"] for case in cases}
    if "freestanding" in adapters:
        tools["qemu"] = {arch: executable((args.qemu or "qemu-riscv{bits}").format(bits=arch[2:]))
                         for case in cases if case["adapter"] == "freestanding"
                         for arch in case["selected_arches"]}
    if "cmake" in adapters:
        tools["cmake"] = executable("cmake")
        tools["spike"] = executable(args.spike or prefix / "bin/spike")
        tools["pk"] = executable(args.pk or prefix / basename / "bin/pk")
    return tools


def command(argv, directory, label, timeout, check=True):
    """Capture both streams; kill the complete build process group on timeout."""
    argv = [str(arg) for arg in argv]
    (directory / f"{label}.command").write_text(shlex.join(argv) + "\n")
    try:
        process = subprocess.Popen(argv, cwd=directory, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, errors="replace", start_new_session=True)
    except OSError as error:
        raise TestError(f"cannot start {label}: {error}") from error
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
    (directory / f"{label}.stdout").write_text(stdout)
    (directory / f"{label}.stderr").write_text(stderr)
    if timed_out:
        raise TestError(f"{label} timed out after {timeout:g}s; see {directory}")
    if check and process.returncode:
        raise TestError(f"{label} failed with status {process.returncode}; see {directory / (label + '.stderr')}")
    return dict(host_exit=process.returncode, stdout=stdout, stderr=stderr)


def build_and_run(args, tools, case, arch, mode, cfp, schedule, functions, cfp_functions, directory):
    directory.mkdir(parents=True, exist_ok=True)
    build = lambda argv, label: command(argv, directory, label, args.build_timeout)
    if case["adapter"] == "freestanding":
        abi = "ilp32" if arch == "rv32" else "lp64"
        assembly = []
        flags = [] if mode == "none" else [f"-{mode}={','.join(functions)}"]
        if cfp != "none":
            flags.append(f"-{cfp}={','.join(cfp_functions)}")
        if schedule == "fgs" and mode != "none":
            flags.append(f"-FGS={','.join(functions)}")
        for index, source in enumerate(case["sources"]):
            stem = f"source-{index}"
            ir = directory / (stem + ".ll")
            asm = directory / (stem + ".s")
            build([tools["clang"], f"--target=riscv{arch[2:]}", f"-march={arch}im",
                   f"-mabi={abi}", "-O1", "-fno-optimize-sibling-calls", "-emit-llvm", "-S",
                   *["-D" + define for define in case.get("defines", [])],
                   case["directory"] / source, "-o", ir], stem + ".clang")
            build([tools["llc"], f"-march=riscv{arch[2:]}", "-mattr=+m", "-O1", *flags,
                   ir, "-o", asm], stem + ".llc")
            assembly.append(asm)
        elf = directory / "test.elf"
        build([tools["cc"], f"-march={arch}im", f"-mabi={abi}", "-nostdlib", "-static", "-no-pie",
               "-Wl,--build-id=none", "-Wl,-Ttext=0x10000", TESTS / "support/start.S",
               *assembly, "-o", elf], "link")
        outcome = command([tools["qemu"][arch], "-strace", elf], directory, "run", args.timeout, check=False)
        exits = re.findall(r"\bexit(?:_group)?\((-?\d+)\)", outcome["stderr"])
        if len(exits) != 1:
            raise TestError(f"expected one target exit in QEMU trace, found {exits}; see {directory / 'run.stderr'}")
        outcome["target_exit"] = int(exits[0])
        if outcome["host_exit"] != (outcome["target_exit"] & 255):
            raise TestError(f"QEMU host status disagrees with target exit; see {directory / 'run.stderr'}")
    else:
        source = (case["directory"] / case.get("source_dir", ".")).resolve()
        isa = case.get("isa", arch + "gc")
        if not isa.startswith(arch):
            raise TestError(f"ISA {isa} does not match architecture {arch}")
        build([tools["cmake"], "-S", source, "-B", directory,
               "-DCOMPAS_LLVM_ROOT=" + tools["llvm_root"], "-DCOMPAS_CLANG=" + tools["clang"],
               "-DCOMPAS_LLC=" + tools["llc"], "-DRISCV_TOOLCHAIN_PREFIX=" + tools["prefix"],
               "-DRISCV_TOOLCHAIN_BASENAME=" + tools["basename"], "-DRISCV_ISA=" + isa,
               "-DDMR_MOD=" + (mode if mode != "none" else ""),
               "-DDMR_FUNCTIONS=" + ";".join(functions),
               "-DCFP_MOD=" + (cfp if cfp != "none" else ""),
               "-DCFP_FUNCTIONS=" + ";".join(cfp_functions),
               "-DCOMPAS_FINE_GRAINED=" + ("ON" if schedule == "fgs" and mode != "none" else "OFF")], "configure")
        # compas_source() does not track every source/tool change as a Make
        # dependency. Rebuild generated IR/assembly instead of trusting stale outputs.
        build([tools["cmake"], "--build", directory, "--clean-first", "--parallel", str(args.jobs)], "build")
        outcome = command([tools["spike"], "--isa=" + isa, tools["pk"], directory / case["executable"]],
                          directory, "run", args.timeout, check=False)
        if outcome["host_exit"] < 0:
            raise TestError(f"Spike terminated by signal {-outcome['host_exit']}; see {directory / 'run.stderr'}")
        outcome["target_exit"] = None
    # Stderr is retained as a log; simulator diagnostics are not program output.
    del outcome["stderr"]
    return outcome


def known_failure(case, arch, mode, cfp, schedule, functions, cfp_functions):
    if functions != case.get("functions", []) or cfp_functions != case.get("functions", []):
        return None
    for failure in case.get("known_failures", []):
        if (failure["case"] == case["case_name"] and failure["mode"] == mode
                and failure["schedule"] == schedule and arch in failure["architectures"]
                and cfp == failure.get("cfp", "none")):
            if not failure.get("issue") or not failure.get("reason") or "target_exit" not in failure:
                raise TestError("known failures require issue, reason and target_exit")
            return failure
    return None


def oracle_matches(case, outcome):
    exit_value = outcome["target_exit"] if outcome["target_exit"] is not None else outcome["host_exit"]
    return exit_value == case["expected"]["exit"] and outcome["stdout"] == case["expected"]["stdout"]


def emit(results, result):
    results.append(result)
    config = f"{result['mode']}/{result['cfp']}/{result['schedule']}"
    print(f"{result['status']:6} {result['name']} {result['arch']} {config}: {result['detail']}", flush=True)


def execute(args, tools, cases, results):
    for case in cases:
        functions = args.functions if args.functions is not None else case.get("functions", [])
        cfp_functions = args.cfp_functions if args.cfp_functions is not None else functions
        configurations = list(dict.fromkeys(itertools.product(
            args.mode or case.get("modes", ["EDDI", "SWIFT"]),
            args.cfp or case.get("cfp_modes", ["none"]),
            args.schedule or case.get("schedules", ["cgs"]))))
        for mode, cfp, schedule in configurations:
            if mode not in MODES or cfp not in CFPS or schedule not in ("cgs", "fgs"):
                raise TestError(f"invalid configuration in {case['name']}: {mode}/{cfp}/{schedule}")
        identity = hashlib.sha256(json.dumps([functions, cfp_functions, tools], sort_keys=True).encode()).hexdigest()[:10]
        for arch in dict.fromkeys(case["selected_arches"]):
            root = args.build_dir / case["group"] / case["name"] / arch / identity
            base = dict(name=case["name"], group=case["group"], arch=arch,
                        functions=functions, cfp_functions=cfp_functions)
            reference = dict(base, mode="reference", cfp="none", schedule="cgs", logdir=str(root / "reference"))
            try:
                outcome = build_and_run(args, tools, case, arch, "none", "none", "cgs", [], [], root / "reference")
                reference["outcome"] = outcome
                if not oracle_matches(case, outcome):
                    raise TestError(f"reference violates independent oracle: expected {case['expected']}, observed {outcome}")
                reference.update(status="PASS", detail="independent oracle matched")
            except (TestError, OSError, KeyError) as error:
                reference.update(status="ERROR", detail=str(error))
                emit(results, reference)
                continue
            emit(results, reference)
            for mode, cfp, schedule in configurations:
                if mode == "none" and cfp == "none":
                    continue  # The reference already checks this configuration.
                directory = root / f"{mode}-{cfp}-{schedule}"
                result = dict(base, mode=mode, cfp=cfp, schedule=schedule, logdir=str(directory))
                try:
                    failure = known_failure(case, arch, mode, cfp, schedule, functions, cfp_functions)
                    if failure:
                        result["known_failure"] = failure
                    observed = build_and_run(args, tools, case, arch, mode, cfp, schedule,
                                             functions, cfp_functions, directory)
                    result["outcome"] = observed
                    if observed == outcome and oracle_matches(case, observed):
                        result.update(status="XPASS" if failure else "PASS", detail="matches reference and independent oracle")
                    elif (failure and observed["target_exit"] == failure["target_exit"]
                          and observed["stdout"] == outcome["stdout"]):
                        result.update(status="XFAIL", detail=f"target exit {observed['target_exit']}; {failure['reason']} ({failure['issue']})")
                    else:
                        result.update(status="FAIL", detail=f"functional mismatch: observed {observed}, reference {outcome}")
                except (TestError, OSError, KeyError) as error:
                    result.update(status="ERROR", detail=str(error))
                emit(results, result)


def main(default_suite="all"):
    cli = parser(default_suite)
    args = cli.parse_args()
    if args.timeout <= 0 or args.build_timeout <= 0 or args.jobs <= 0:
        cli.error("timeouts and jobs must be positive")
    try:
        cases = discover(args)
        if args.list:
            for case in cases:
                print(f"{case['name']} [{case['adapter']}] arch={','.join(case['selected_arches'])} "
                      f"modes={','.join(args.mode or case.get('modes', []))} "
                      f"schedules={','.join(args.schedule or case.get('schedules', ['cgs']))}")
            return 0
        args.build_dir = args.build_dir.expanduser().resolve()
        if args.build_dir == TESTS or TESTS in args.build_dir.parents:
            raise TestError("place build artifacts outside the tests source tree (for example build/tests)")
        args.build_dir.mkdir(parents=True, exist_ok=True)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        results = []
        try:
            tool_paths = tools_for(args, cases)
            execute(args, tool_paths, cases, results)
        except TestError as error:
            results.append(dict(status="ERROR", detail=str(error)))
            print(f"ERROR {error}", file=sys.stderr)
        finally:
            counts = dict(Counter(result["status"] for result in results))
            report = dict(results=results, counts=counts)
            (args.build_dir / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print("Results: " + ", ".join(f"{count} {status}" for status, count in sorted(counts.items())))
        print(f"Report: {args.build_dir / 'results.json'}")
        return int(any(counts.get(status, 0) for status in
                       (("FAIL", "ERROR") if args.allow_xpass else ("FAIL", "ERROR", "XPASS"))))
    except (TestError, OSError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 1
