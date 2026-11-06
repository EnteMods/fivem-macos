#!/usr/bin/env python3
"""Test existing MAIN /MT vendor artifacts through account-free Windows API probes."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build/windows-client-tests"
PREFIX = ROOT / "prefixes/corert-regression"
LLVM = Path("/opt/homebrew/opt/llvm/bin")
DEFAULT_ARCHIVE = ROOT / "build/windows-client-vendor/cfx_main_compiler_rt.lib"
BUILD_RECORD = BUILD / "compiler-rt-build.json"
RESULT = ROOT / "research/main-compiler-rt-u128-results.json"
sys.path.insert(0, str(ROOT / "scripts"))
from probe_environment import assert_account_free_prefix, probe_prefix


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative(path):
    return str(Path(path).resolve().relative_to(ROOT))


def command_output(args):
    return subprocess.run([str(arg) for arg in args], capture_output=True, text=True, check=True).stdout


def write_if_changed(path, data):
    path = Path(path)
    if not path.is_file() or path.read_bytes() != data:
        path.write_bytes(data)


def inspect_archive(archive):
    headers = command_output([LLVM / "llvm-readobj", "--file-headers", "--coff-directives", archive])
    symbols = command_output([LLVM / "llvm-nm", "--defined-only", archive])
    machines = re.findall(r"Machine: ([^\n]+)", headers)
    directives = re.findall(r"Directive\(s\): ([^\n]+)", headers)
    defaults = [re.findall(r"/DEFAULTLIB:([^\s]+)", line, re.IGNORECASE) for line in directives]
    expected = {"libcmt.lib", "oldnames.lib"}
    if len(machines) != 3 or any(machine != "IMAGE_FILE_MACHINE_AMD64 (0x8664)" for machine in machines):
        raise SystemExit("Expected exactly three original AMD64 compiler-rt objects")
    if len(defaults) != 3 or any({lib.lower().strip('"') for lib in row} != expected for row in defaults):
        raise SystemExit("MAIN compiler-rt objects do not consistently select the /MT CRT")
    for name in ("__udivti3", "__umodti3", "__udivmodti4"):
        if not re.search(r"\bT " + name + r"$", symbols, re.MULTILINE):
            raise SystemExit("Missing original compiler-rt definition: " + name)
    (BUILD / "main-compiler-rt-archive-inspection.log").write_text(headers + symbols)
    return {"object_count": len(machines), "machine": "AMD64", "defaultlibs_per_object": defaults,
            "all_objects_static_crt": True, "md_defaultlib_found": False,
            "inspection_log": relative(BUILD / "main-compiler-rt-archive-inspection.log")}


def make_vectors():
    random_source = random.Random(0xCF128)
    values = [0, 1, 2, 3, (1 << 32) - 1, 1 << 32, (1 << 64) - 1, 1 << 64,
              (1 << 64) + 1, 1 << 127, (1 << 128) - 2, (1 << 128) - 1]
    pairs = [(a, b) for a in values for b in values if b]
    pairs += [(random_source.getrandbits(128), random_source.getrandbits(128) or 1) for _ in range(512)]
    pairs += [(random_source.getrandbits(128), random_source.getrandbits(64) or 1) for _ in range(128)]
    rows = []
    for a, b in pairs:
        q, r = divmod(a, b)
        words = [a & ((1 << 64) - 1), a >> 64, b & ((1 << 64) - 1), b >> 64,
                 q & ((1 << 64) - 1), q >> 64, r & ((1 << 64) - 1), r >> 64]
        rows.append("{" + ",".join("0x%016xULL" % word for word in words) + "}")
    if len(rows) != 772:
        raise SystemExit("Unexpected reference-vector count")
    vectors = BUILD / "vectors.inc"
    write_if_changed(vectors, ("static const uint64_t vectors[][8] = {\n" + ",\n".join(rows) + "\n};\n").encode())
    previous = ROOT / "build/compiler-rt-u128/vectors.inc"
    same = previous.is_file() and sha256(previous) == sha256(vectors)
    if previous.is_file() and not same:
        raise SystemExit("Reference vectors differ from the existing /MD compiler-rt suite")
    return {"count": len(rows), "sha256": sha256(vectors), "seed": "0xCF128",
            "matches_existing_md_suite": same,
            "reference": "Python arbitrary-precision divmod; deterministic 64/128-bit boundaries and random cases; no zero divisor"}


def inspect_harness():
    records = []
    forbidden = {"msvcrt.lib", "msvcrtd.lib", "msvcprt.lib", "msvcprtd.lib", "ucrt.lib", "vcruntime.lib"}
    for name in ("main_compiler_rt_fixture", "main_compiler_rt_probe"):
        obj = BUILD / "CMakeFiles" / (name + ".dir")
        objects = list(obj.rglob("*.obj"))
        if len(objects) != 1:
            raise SystemExit("Expected exactly one reused source object in " + name)
        directives = command_output([LLVM / "llvm-readobj", "--coff-directives", objects[0]])
        defaultlibs = {item.lower().strip('"') for item in re.findall(r"/DEFAULTLIB:([^\s]+)", directives, re.IGNORECASE)}
        if "libcmt.lib" not in defaultlibs or defaultlibs & forbidden:
            raise SystemExit("Harness object is not consistently /MT: " + name)
        artifact = BUILD / (name + (".dll" if name.endswith("fixture") else ".exe"))
        imports = command_output([LLVM / "llvm-readobj", "--file-headers", "--coff-imports", artifact])
        if "IMAGE_FILE_MACHINE_AMD64 (0x8664)" not in imports:
            raise SystemExit("Harness artifact is not AMD64")
        imported = re.findall(r"  Name: ([^\n]+)", imports)
        if any(re.match(r"(?i)(?:msvc(?:p|r)|vcruntime|ucrtbase|api-ms-win-crt-)", dll) for dll in imported):
            raise SystemExit("Unexpected dynamic Microsoft CRT import in " + name)
        (BUILD / (name + "-inspection.log")).write_text(directives + imports)
        records.append({"artifact": relative(artifact), "sha256": sha256(artifact),
                        "object_defaultlibs": sorted(defaultlibs), "imports": imported,
                        "dynamic_crt_import_found": False})
    map_text = (BUILD / "main-compiler-rt-fixture.map").read_text()
    for symbol in ("__udivti3", "__umodti3", "__udivmodti4"):
        line = next((line for line in map_text.splitlines() if re.search(r"\b" + symbol + r"\b", line)), "")
        if "main-compiler-rt:" not in line:
            raise SystemExit("Link map did not resolve " + symbol + " from the exact MAIN snapshot")
    return records


def build(archive):
    BUILD.mkdir(parents=True, exist_ok=True)
    archive = Path(archive).resolve(strict=True)
    archive.relative_to(ROOT)
    original_hash = sha256(archive)
    inspection = inspect_archive(archive)
    snapshot = BUILD / "main-compiler-rt.lib"
    write_if_changed(snapshot, archive.read_bytes())
    if sha256(snapshot) != original_hash or sha256(archive) != original_hash:
        raise SystemExit("MAIN archive changed while taking its test snapshot")
    vectors = make_vectors()
    args = ["cmake", "-S", str(ROOT / "native/windows-client-tests"), "-B", str(BUILD), "-G", "Ninja",
            "-DCMAKE_TOOLCHAIN_FILE=" + str(ROOT / "native/windows-core/toolchain.cmake"),
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo", "-DCFX_MAIN_OPENSSL_TESTS=OFF",
            "-DCFX_MAIN_BUILTINS_ARCHIVE=" + str(snapshot)]
    subprocess.run(args, check=True)
    subprocess.run(["cmake", "--build", str(BUILD), "--parallel", "2"], check=True)
    harness = inspect_harness()
    sources = [ROOT / "native/compiler-rt/fixture.c", ROOT / "native/compiler-rt/probe.c"]
    record = {"archive": relative(archive), "archive_sha256": original_hash,
              "snapshot": relative(snapshot), "snapshot_sha256": sha256(snapshot), "archive_inspection": inspection,
              "archive_unchanged_after_build": sha256(archive) == original_hash, "vectors": vectors,
              "reused_original_probe_sources": {relative(path): sha256(path) for path in sources},
              "harness": harness, "link_map": relative(BUILD / "main-compiler-rt-fixture.map"),
              "llvm_version": command_output([LLVM / "clang-cl", "--version"]).splitlines()[0],
              "llvm_source_commit": json.loads((ROOT / "config/compiler-rt-23.1.4.json").read_text())["commit"]}
    if not record["archive_unchanged_after_build"]:
        raise SystemExit("Original MAIN archive changed during test build; retry")
    BUILD_RECORD.write_text(json.dumps(record, indent=2) + "\n")
    print("MAIN /MT build ready: " + original_hash)


def test():
    record = json.loads(BUILD_RECORD.read_text())
    if sha256(ROOT / record["snapshot"]) != record["archive_sha256"]:
        raise SystemExit("MAIN snapshot differs from inspected archive")
    for artifact in record["harness"]:
        if sha256(ROOT / artifact["artifact"]) != artifact["sha256"]:
            raise SystemExit("Harness artifact changed after inspection")
    with probe_prefix(PREFIX, root=ROOT):
        spec = importlib.util.spec_from_file_location("gta_runtime", ROOT.parent / "GTA-V-macOS/scripts/gta-macos.py")
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        env = runtime.environment()
        env["WINEPREFIX"] = str(PREFIX)
        try:
            assert_account_free_prefix(PREFIX, root=ROOT)
            result = subprocess.run([str(runtime.WINE), str(BUILD / "main_compiler_rt_probe.exe")], cwd=BUILD,
                                    env=env, capture_output=True, text=True, timeout=60)
            assert_account_free_prefix(PREFIX, root=ROOT)
        finally:
            subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-k"], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-w"], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=True)
        output = result.stdout + result.stderr
        log = ROOT / "logs/main-compiler-rt-u128-run.log"
        log.write_text(output)
        expected = "U128_MSVC_ABI_OK vectors=772 implicit_and_direct=1 dll_boundary=1"
        record.update({"at": datetime.now(timezone.utc).isoformat(), "returncode": result.returncode,
                       "passed": result.returncode == 0 and expected in output, "log": relative(log),
                       "account_free": True, "prefix": relative(PREFIX), "shared_guard_and_lock": True,
                       "main_or_client_executed": False, "auth_or_gui_started": False,
                       "scope": "Actual MAIN /MT compiler-rt archive, original arithmetic DLL/EXE probe; no MAIN/client compatibility claim"})
        RESULT.write_text(json.dumps(record, indent=2) + "\n")
        print(output[-1500:])
        if not record["passed"]:
            raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "test", "all"))
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    arguments = parser.parse_args()
    if arguments.action in ("build", "all"):
        build(arguments.archive)
    if arguments.action in ("test", "all"):
        test()
