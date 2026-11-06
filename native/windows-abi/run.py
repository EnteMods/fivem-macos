#!/usr/bin/env python3
"""Compile and run only the local /MD ABI fixture in the marked account-free prefix."""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/windows-abi"
BUILD = ROOT / "build/windows-abi"
PREFIX = ROOT / "prefixes/corert-regression"
sys.path.insert(0, str(ROOT / "scripts"))
from probe_environment import assert_account_free_prefix, probe_prefix


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["build", "run", "all"])
    action = parser.parse_args().action
    BUILD.mkdir(parents=True, exist_ok=True)
    vc = ROOT / "toolchains/msvc-2022/VC/Tools/MSVC/14.44.35207"
    sdk = ROOT / "toolchains/msvc-2022/Windows Kits/10"
    compiler = "/opt/homebrew/opt/llvm/bin/clang-cl"
    linker = "/opt/homebrew/opt/lld/bin/lld-link"
    includes = [vc / "include"] + [sdk / "Include/10.0.26100.0" / part for part in ("ucrt", "shared", "um", "winrt")]
    common = [compiler, "--target=x86_64-pc-windows-msvc", "/nologo", "/std:c++17", "/EHsc", "/MD", "/O2", "/Z7", "/utf-8", "/D_ITERATOR_DEBUG_LEVEL=0", "/clang:-fms-compatibility-version=19.44", "/I" + str(ROOT / "port/fivem/code/client/shared")]
    for folder in includes:
        common += ["/imsvc", str(folder)]
    libs = ["/libpath:" + str(vc / "lib/x64")] + ["/libpath:" + str(sdk / "Lib/10.0.26100.0" / part / "x64") for part in ("ucrt", "um")]
    commands = [
        common + ["/c", "fixture.cpp", "/Fo" + str(BUILD / "fixture.obj")],
        common + ["/c", "consumer.cpp", "/Fo" + str(BUILD / "consumer.obj")],
        [linker, "/nologo", "/dll", "/machine:x64", "/out:" + str(BUILD / "abi-fixture.dll"), "/implib:" + str(BUILD / "abi-fixture.lib"), str(BUILD / "fixture.obj"), *libs, "kernel32.lib"],
        [linker, "/nologo", "/subsystem:console", "/machine:x64", "/out:" + str(BUILD / "md-abi-consumer.exe"), str(BUILD / "consumer.obj"), str(BUILD / "abi-fixture.lib"), *libs, "kernel32.lib"],
    ]
    if action in ("build", "all"):
        (BUILD / "build-commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        with (BUILD / "build.log").open("w") as log:
            for command in commands:
                result = subprocess.run(command, cwd=SOURCE, stdout=log, stderr=subprocess.STDOUT)
                if result.returncode:
                    raise SystemExit(result.returncode)
        inventory = subprocess.run(["/opt/homebrew/opt/llvm/bin/llvm-readobj", "--coff-imports", str(BUILD / "abi-fixture.dll"), str(BUILD / "md-abi-consumer.exe")], capture_output=True, text=True, check=True)
        (BUILD / "imports.txt").write_text(inventory.stdout)
        print("/MD DLL and consumer built; PE import inventory saved.", flush=True)
    if action in ("run", "all"):
        with probe_prefix(PREFIX, root=ROOT):
            return run_locked()
    return 0


def run_locked():
    spec = importlib.util.spec_from_file_location("known_gta_environment", ROOT.parent / "GTA-V-macOS/scripts/gta-macos.py")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    if PREFIX.resolve() == runtime.PREFIX.resolve():
        raise SystemExit("Refusing productive GTA prefix")
    env = runtime.environment()
    env["WINEPREFIX"] = str(PREFIX)
    env["WINEDEBUG"] = "-all,+loaddll"
    binary = BUILD / "md-abi-consumer.exe"
    assert_account_free_prefix(PREFIX, root=ROOT)
    try:
        result = subprocess.run([str(runtime.WINE), str(binary)], cwd=BUILD, env=env, capture_output=True, text=True, timeout=90)
        assert_account_free_prefix(PREFIX, root=ROOT)
    finally:
        subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-k"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    output = result.stdout + result.stderr
    (BUILD / "run.log").write_text(output)
    record = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "prefix": str(PREFIX), "account_free": True, "crt_mode": "/MD",
        "returncode": result.returncode, "passed": result.returncode == 0 and "MD_DLL_ABI_OK" in output,
        "dll_sha256": hashlib.sha256((BUILD / "abi-fixture.dll").read_bytes()).hexdigest(),
        "exe_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "runtime_load_lines": [line for line in output.splitlines() if any(name in line.lower() for name in ("msvcp140", "vcruntime140", "ucrtbase"))],
        "original_vc_runtime_dlls_copied": False,
        "full_client_or_auth_test": False,
    }
    (BUILD / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    for line in output.splitlines():
        if "MD_DLL_" in line or line.startswith("RUNTIME_MODULE"):
            print(line)
    print("exit", result.returncode, "passed", record["passed"])
    return 0 if record["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
