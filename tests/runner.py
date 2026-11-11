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


def function_selections(args, case):
    functions = args.functions if args.functions is not None else case.get("functions", [])
    cfp_functions = (args.cfp_functions if args.cfp_functions is not None
                     else case.get("cfp_functions", functions))
    return functions, cfp_functions


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
    cli.add_argument("--isa", help="freestanding ISA override; {bits} expands to 32 or 64")
    cli.add_argument("--abi", help="freestanding ABI override (ilp32, ilp32f, ilp32d, lp64, lp64f, lp64d)")
    cli.add_argument("--code-model", action="append", choices=("medlow", "medany"),
                     help="repeatable freestanding code model (default: manifest or medlow)")
    verification = cli.add_mutually_exclusive_group()
    verification.add_argument("--verify-machineinstrs", dest="verify_machineinstrs", action="store_true",
                              help="also compile freestanding cases with LLVM's machine verifier")
    verification.add_argument("--no-verify-machineinstrs", dest="verify_machineinstrs", action="store_false",
                              help="run functional checks without the optional machine verifier")
    cli.set_defaults(verify_machineinstrs=None)
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


def target_profiles(args, case, arch):
    """Resolve explicit frontend, backend and linker settings together."""
    if case["adapter"] != "freestanding":
        if (args.isa is not None or args.abi is not None or args.code_model
                or "abi" in case or "code_models" in case or "relax" in case
                or "frame_pointer" in case):
            raise ValueError("ISA/ABI overrides, code_models, relax and frame_pointer are supported by the freestanding adapter")
        return [None]
    isa = (args.isa if args.isa is not None else case.get("isa", "rv{bits}im")).format(bits=arch[2:])
    match = re.fullmatch(r"rv(32|64)(i[mafdc]*|gc?)", isa)
    if not match or match[1] != arch[2:]:
        raise ValueError(f"ISA {isa!r} must match {arch} and use the supported I/M/A/F/D/C/G extensions")
    extensions = match[2].replace("g", "imafd")
    if len(set(extensions)) != len(extensions) or ("d" in extensions and "f" not in extensions):
        raise ValueError(f"invalid ISA extensions: {isa}")
    abi = args.abi if args.abi is not None else case.get("abi", "ilp32" if arch == "rv32" else "lp64")
    base_abi = "ilp32" if arch == "rv32" else "lp64"
    if abi not in (base_abi, base_abi + "f", base_abi + "d"):
        raise ValueError(f"ABI {abi!r} does not match {arch}")
    if (abi.endswith("f") and "f" not in extensions) or (abi.endswith("d") and "d" not in extensions):
        raise ValueError(f"ABI {abi} requires matching floating-point extensions in {isa}")
    relax = case.get("relax", True)
    features = ["+" + extension for extension in extensions if extension != "i"]
    if not relax:
        features.append("-relax")
    frame_pointer = {"frame_pointer": True} if case.get("frame_pointer", False) else {}
    return [dict(isa=isa, abi=abi, code_model=model, relax=relax, features=features,
                 **frame_pointer)
            for model in dict.fromkeys(args.code_model or case.get("code_models", ["medlow"]))]


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
                    for field in ("functions", "cfp_functions", "defines"):
                        values = config.get(field, [])
                        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                            raise ValueError(f"{field} must be a list of strings")
                    if config["adapter"] == "freestanding":
                        sources = config["sources"]
                        if not isinstance(sources, list) or not sources or any(not isinstance(value, str) for value in sources):
                            raise ValueError("sources must be a nonempty list of paths")
                        diagnostic = config.get("expected_build_diagnostic")
                        if diagnostic is not None:
                            if (not isinstance(diagnostic, dict)
                                    or diagnostic.get("source") not in sources
                                    or not isinstance(diagnostic.get("message"), str)
                                    or not diagnostic["message"].strip()):
                                raise ValueError("expected_build_diagnostic requires a source from sources and a nonempty message")
                            modes = diagnostic.get("modes")
                            functions = diagnostic.get("functions")
                            if (not isinstance(modes, list) or not modes
                                    or any(value not in MODES[1:] for value in modes)):
                                raise ValueError("expected_build_diagnostic.modes must select nonempty DMR modes")
                            if (not isinstance(functions, list) or not functions
                                    or any(not isinstance(value, str) or not value
                                           or value not in config.get("functions", [])
                                           for value in functions)):
                                raise ValueError("expected_build_diagnostic.functions must select manifest DMR functions")
                    elif not isinstance(config["executable"], str) or not config["executable"]:
                        raise ValueError("CMake suites require an executable path")
                    elif "expected_build_diagnostic" in config:
                        raise ValueError("expected_build_diagnostic is supported by the freestanding adapter")
                    if not isinstance(config.get("verify_machineinstrs", False), bool):
                        raise ValueError("verify_machineinstrs must be a boolean")
                    for field in ("isa", "abi"):
                        if field in config and not isinstance(config[field], str):
                            raise ValueError(f"{field} must be a string")
                    models = config.get("code_models", ["medlow"])
                    if not isinstance(models, list) or not models or any(model not in ("medlow", "medany") for model in models):
                        raise ValueError("code_models must be a nonempty list of medlow/medany")
                    if not isinstance(config.get("relax", True), bool):
                        raise ValueError("relax must be a boolean")
                    if not isinstance(config.get("frame_pointer", False), bool):
                        raise ValueError("frame_pointer must be a boolean")
                    if args.case and not any(fnmatch.fnmatchcase(name, pattern) for pattern in args.case):
                        continue
                    config["selected_arches"] = [a for a in (args.arch or arches) if a in arches]
                    if config["selected_arches"]:
                        config["targets"] = {arch: target_profiles(args, config, arch)
                                             for arch in config["selected_arches"]}
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


def build_diagnostic_for(case, mode, functions):
    diagnostic = case.get("expected_build_diagnostic")
    if (diagnostic and mode in diagnostic["modes"]
            and all(function in functions for function in diagnostic["functions"])):
        return diagnostic
    return None


def check_build_diagnostic(observed, diagnostic, directory, label):
    # Match an ordinary compiler rejection, never an assertion or a signal
    # that happens to print the requested message before crashing.
    if (observed["host_exit"] != 1
            or diagnostic["message"] not in observed["stderr"]
            or re.search(r"Assertion .* failed|PLEASE submit a bug report|Stack dump:",
                         observed["stderr"])):
        raise TestError(f"expected compiler diagnostic was not emitted cleanly; "
                        f"status {observed['host_exit']}; see {directory / (label + '.stderr')}")


def build_and_run(args, tools, case, arch, mode, cfp, schedule, functions, cfp_functions, directory, target):
    directory.mkdir(parents=True, exist_ok=True)
    build = lambda argv, label: command(argv, directory, label, args.build_timeout)
    verify = args.verify_machineinstrs if args.verify_machineinstrs is not None else case.get("verify_machineinstrs", False)
    verification = {"status": "PASS", "errors": []} if verify else None
    if case["adapter"] == "freestanding":
        isa, abi, model = target["isa"], target["abi"], target["code_model"]
        isa_flags = [f"-march={isa}", f"-mabi={abi}", f"-mcmodel={model}"]
        if not target["relax"]:
            isa_flags.append("-mno-relax")
        assembly = []
        flags = [] if mode == "none" else [f"-{mode}={','.join(functions)}"]
        if cfp != "none":
            flags.append(f"-{cfp}={','.join(cfp_functions)}")
        if schedule == "fgs" and mode != "none":
            flags.append(f"-FGS={','.join(functions)}")
        frame_flags = (["-fno-omit-frame-pointer", "-mno-omit-leaf-frame-pointer"]
                       if target.get("frame_pointer", False) else [])
        diagnostic = build_diagnostic_for(case, mode, functions)
        for index, source in enumerate(case["sources"]):
            stem = f"source-{index}"
            ir = directory / (stem + ".ll")
            asm = directory / (stem + ".s")
            build([tools["clang"], f"--target=riscv{arch[2:]}", *isa_flags,
                   "-O1", "-fno-optimize-sibling-calls", "-emit-llvm", "-S",
                   *frame_flags,
                   *["-D" + define for define in case.get("defines", [])],
                   case["directory"] / source, "-o", ir], stem + ".clang")
            llc = [tools["llc"], f"-march=riscv{arch[2:]}", "-mattr=" + ",".join(target["features"]),
                   "-target-abi=" + abi, "-code-model=" + ("small" if model == "medlow" else "medium"),
                   "-O1", *flags, ir]
            if diagnostic and source == diagnostic["source"]:
                label = stem + ".llc"
                observed = command([*llc, "-o", asm], directory, label,
                                   args.build_timeout, check=False)
                matched = observed["host_exit"] != 0
                if matched:
                    check_build_diagnostic(observed, diagnostic, directory, label)
                if verify:
                    verification["kind"] = "build_diagnostic"
                    label = stem + ".verify"
                    try:
                        checked = command([*llc, "-verify-machineinstrs", "-o", directory / (stem + ".verify.s")],
                                          directory, label, args.build_timeout, check=False)
                        if matched or checked["host_exit"] != 0:
                            check_build_diagnostic(checked, diagnostic, directory, label)
                    except TestError as error:
                        verification["status"] = "ERROR"
                        verification["errors"].append(str(error))
                # Rejected code has no executable or functional outcome.
                return {"build_diagnostic": dict(matched=matched,
                            message=diagnostic["message"], source=source,
                            host_exit=observed["host_exit"])}, verification
            build([*llc, "-o", asm], stem + ".llc")
            if verify:
                # A verifier failure must not prevent the normal executable
                # from supplying functional evidence. Keep its output separate.
                label = stem + ".verify"
                try:
                    checked = command([*llc, "-verify-machineinstrs", "-o", directory / (stem + ".verify.s")],
                                      directory, label, args.build_timeout, check=False)
                    if checked["host_exit"]:
                        raise TestError(f"machine verifier failed with status {checked['host_exit']}; "
                                        f"see {directory / (label + '.stderr')}")
                except TestError as error:
                    verification["status"] = "ERROR"
                    verification["errors"].append(str(error))
            assembly.append(asm)
        elf = directory / "test.elf"
        build([tools["cc"], *isa_flags, "-nostdlib", "-static", "-no-pie",
               "-Wl,--build-id=none", "-Wl,-Ttext=0x10000", TESTS / "support/start.S",
               *([] if target["relax"] else ["-Wl,--no-relax"]),
               *assembly, "-o", elf], "link")
        outcome = command([tools["qemu"][arch], "-strace", elf], directory, "run", args.timeout, check=False)
        exits = re.findall(r"\bexit(?:_group)?\((-?\d+)\)", outcome["stderr"])
        if len(exits) != 1:
            raise TestError(f"expected one target exit in QEMU trace, found {exits}; see {directory / 'run.stderr'}")
        outcome["target_exit"] = int(exits[0])
        if outcome["host_exit"] != (outcome["target_exit"] & 255):
            raise TestError(f"QEMU host status disagrees with target exit; see {directory / 'run.stderr'}")
    else:
        if verify:
            raise TestError("machine verification is supported by the freestanding adapter")
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
    return outcome, verification


def attach_verification(result, verification):
    if verification is not None:
        result["functional_status"] = result["status"]
        result["verification"] = verification
        if verification["status"] == "ERROR":
            result["detail"] = f"functional {result['status']}; " + "; ".join(verification["errors"])
            result["status"] = "ERROR"


def known_failure(case, arch, mode, cfp, schedule, functions, cfp_functions, target):
    if (functions != case.get("functions", [])
            or cfp_functions != case.get("cfp_functions", case.get("functions", []))):
        return None
    for failure in case.get("known_failures", []):
        if (failure["case"] == case["case_name"] and failure["mode"] == mode
                and failure["schedule"] == schedule and arch in failure["architectures"]
                and cfp == failure.get("cfp", "none")):
            if target and any(target.get(field, default) != failure.get(field, default) for field, default in (
                    ("isa", arch + "im"), ("abi", "ilp32" if arch == "rv32" else "lp64"),
                    ("code_model", "medlow"), ("relax", True), ("frame_pointer", False))):
                continue
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
    if "isa" in result:
        config += f" {result['isa']}/{result['abi']}/{result['code_model']}"
        if result.get("frame_pointer", False):
            config += "/frame-pointer"
    print(f"{result['status']:6} {result['name']} {result['arch']} {config}: {result['detail']}", flush=True)


def execute(args, tools, cases, results):
    for case in cases:
        functions, cfp_functions = function_selections(args, case)
        configurations = list(dict.fromkeys(itertools.product(
            args.mode or case.get("modes", ["EDDI", "SWIFT"]),
            args.cfp or case.get("cfp_modes", ["none"]),
            args.schedule or case.get("schedules", ["cgs"]))))
        for mode, cfp, schedule in configurations:
            if mode not in MODES or cfp not in CFPS or schedule not in ("cgs", "fgs"):
                raise TestError(f"invalid configuration in {case['name']}: {mode}/{cfp}/{schedule}")
        verify = args.verify_machineinstrs if args.verify_machineinstrs is not None else case.get("verify_machineinstrs", False)
        identity = hashlib.sha256(json.dumps([functions, cfp_functions, tools, verify, case["targets"]], sort_keys=True).encode()).hexdigest()[:10]
        for arch, target in ((arch, target) for arch in dict.fromkeys(case["selected_arches"])
                             for target in case["targets"][arch]):
            root = args.build_dir / case["group"] / case["name"] / arch / identity
            base = dict(name=case["name"], group=case["group"], arch=arch,
                        functions=functions, cfp_functions=cfp_functions)
            if target:
                profile = f"{target['isa']}-{target['abi']}-{target['code_model']}"
                if not target["relax"]:
                    profile += "-no-relax"
                if target.get("frame_pointer", False):
                    profile += "-frame-pointer"
                root /= profile
                base.update({field: target[field] for field in ("isa", "abi", "code_model", "relax", "frame_pointer")
                             if field in target})
            reference = dict(base, mode="reference", cfp="none", schedule="cgs", logdir=str(root / "reference"))
            try:
                outcome, verification = build_and_run(args, tools, case, arch, "none", "none", "cgs", [], [], root / "reference", target)
                reference["outcome"] = outcome
                if not oracle_matches(case, outcome):
                    raise TestError(f"reference violates independent oracle: expected {case['expected']}, observed {outcome}")
                reference.update(status="PASS", detail="independent oracle matched")
                attach_verification(reference, verification)
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
                if build_diagnostic_for(case, mode, functions):
                    result["kind"] = "build_diagnostic"
                try:
                    failure = known_failure(case, arch, mode, cfp, schedule, functions, cfp_functions, target)
                    if failure:
                        result["known_failure"] = failure
                    observed, verification = build_and_run(args, tools, case, arch, mode, cfp, schedule,
                                                           functions, cfp_functions, directory, target)
                    if "build_diagnostic" in observed:
                        diagnostic = observed["build_diagnostic"]
                        result["build_diagnostic"] = diagnostic
                        result.update(status="PASS" if diagnostic["matched"] else "FAIL",
                                      detail=("expected compiler diagnostic matched" if diagnostic["matched"]
                                              else "compiler unexpectedly accepted an unsupported pattern"))
                        if verification is not None:
                            result["verification"] = verification
                            if verification["status"] == "ERROR":
                                result.update(status="ERROR", detail="; ".join(verification["errors"]))
                        emit(results, result)
                        continue
                    result["outcome"] = observed
                    if observed == outcome and oracle_matches(case, observed):
                        result.update(status="XPASS" if failure else "PASS", detail="matches reference and independent oracle")
                    elif (failure and observed["target_exit"] == failure["target_exit"]
                          and observed["stdout"] == outcome["stdout"]):
                        result.update(status="XFAIL", detail=f"target exit {observed['target_exit']}; {failure['reason']} ({failure['issue']})")
                    else:
                        result.update(status="FAIL", detail=f"functional mismatch: observed {observed}, reference {outcome}")
                    attach_verification(result, verification)
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
                functions, cfp_functions = function_selections(args, case)
                profiles = [f"{target['isa']}/{target['abi']}/{target['code_model']}"
                            + ("/no-relax" if not target["relax"] else "")
                            + ("/frame-pointer" if target.get("frame_pointer", False) else "")
                            for targets in case["targets"].values() for target in targets if target]
                print(f"{case['name']} [{case['adapter']}] arch={','.join(case['selected_arches'])} "
                      f"modes={','.join(args.mode or case.get('modes', []))} "
                      f"cfp={','.join(args.cfp or case.get('cfp_modes', ['none']))} "
                      f"functions={','.join(functions)} cfp-functions={','.join(cfp_functions)} "
                      f"schedules={','.join(args.schedule or case.get('schedules', ['cgs']))} "
                      f"verify={args.verify_machineinstrs if args.verify_machineinstrs is not None else case.get('verify_machineinstrs', False)} "
                      f"targets={';'.join(profiles) if profiles else 'CMake toolchain'}")
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
            functional_counts = dict(Counter(result.get("functional_status", result["status"]) for result in results
                                            if result.get("kind") != "build_diagnostic"))
            report = dict(results=results, counts=counts, functional_counts=functional_counts)
            (args.build_dir / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print("Results: " + ", ".join(f"{count} {status}" for status, count in sorted(counts.items())))
        if any("verification" in result for result in results):
            print("Functional results: " + ", ".join(f"{count} {status}" for status, count in sorted(functional_counts.items())))
        print(f"Report: {args.build_dir / 'results.json'}")
        return int(any(counts.get(status, 0) for status in
                       (("FAIL", "ERROR") if args.allow_xpass else ("FAIL", "ERROR", "XPASS"))))
    except (TestError, OSError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 1
