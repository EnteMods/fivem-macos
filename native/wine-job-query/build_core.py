#!/usr/bin/env python3
"""Configure/build isolated Wine core targets, with no Wine runtime invocation."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from common import PROJECT, WORK, PINS, owned_path
SOURCE = WORK / "source"
BUILD = WORK / "core-x86_64"
BISON = WORK / "tools/bison-3.8.2/bin/bison"


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    global BUILD
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["configure", "core", "all"])
    parser.add_argument("--variant", choices=["core", "moltenvk"], default="core")
    args = parser.parse_args()
    BUILD = WORK / ("full-x86_64" if args.variant == "moltenvk" else "core-x86_64")
    record_prefix = "wine-moltenvk-" if args.variant == "moltenvk" else "wine-"
    owned_path(SOURCE)
    owned_path(BUILD)
    owned_path(WORK / "logs")
    source_record = json.loads((WORK / "source-preparation.json").read_text())
    if not source_record["original_generator_executed"]:
        raise RuntimeError("Pinned source preparation is incomplete")
    proposal = {"files": PINS["query_patch"]["source_files"]}
    for item in proposal["files"]:
        if sha(SOURCE / item["path"]) != item["proposed_sha256"]:
            raise RuntimeError("Prepared query source identity changed")
    for name, digest in source_record["generated_after_sha256"].items():
        if sha(SOURCE / name) != digest:
            raise RuntimeError("Generated protocol identity changed")
    bison_record = json.loads((WORK / "bison-build.json").read_text())
    if sha(BISON) != bison_record["binary_sha256"]:
        raise RuntimeError("Local build-tool identity mismatch")
    BUILD.mkdir(exist_ok=True)
    env = dict(os.environ)
    env.update({
        "PATH": str(BISON.parent) + ":/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "MACOSX_DEPLOYMENT_TARGET": "14.0",
        "CC": "/usr/bin/clang --target=x86_64-apple-macos14",
        "CXX": "/usr/bin/clang++ --target=x86_64-apple-macos14",
        "OBJC": "/usr/bin/clang --target=x86_64-apple-macos14",
        "BISON": str(BISON),
        "i386_CC": "/opt/homebrew/bin/i686-w64-mingw32-gcc",
        "x86_64_CC": "/opt/homebrew/bin/x86_64-w64-mingw32-gcc",
    })
    dependency_record = None
    if args.variant == "moltenvk":
        dependency_record = json.loads((WORK / "moltenvk-build-dependency.json").read_text())
        dependency = WORK / dependency_record["path"]
        if sha(dependency) != dependency_record["sha256"]:
            raise RuntimeError("Pinned MoltenVK build dependency identity changed")
        env["LDFLAGS"] = "-L" + str(dependency.parent)
    if args.phase == "configure":
        if (BUILD / "Makefile").exists():
            raise RuntimeError("Refusing to overwrite a configured build")
        command = [
            str(SOURCE / "configure"),
            "--build=x86_64-apple-darwin", "--host=x86_64-apple-darwin",
            "--prefix=" + str(WORK / "install-core"),
            "--enable-archs=i386,x86_64", "--with-mingw", "--disable-tests",
            "--without-alsa", "--without-capi", "--with-coreaudio",
            "--without-cups", "--without-dbus", "--without-fontconfig",
            "--without-freetype", "--without-gnutls", "--without-gphoto",
            "--without-gstreamer", "--without-krb5", "--without-netapi",
            "--without-oss", "--without-pulse", "--without-sane",
            "--without-sdl", "--without-udev", "--without-usb",
            "--without-v4l2", "--without-x", "--without-wayland",
            "--without-opengl", "--without-vulkan", "--without-ffmpeg",
        ]
        if args.variant == "moltenvk":
            command.remove("--without-vulkan")
            command.append("--with-vulkan")
        timeout = 600
    else:
        if not (BUILD / "Makefile").is_file():
            raise RuntimeError("Configure phase must complete first")
        command = ["/usr/bin/make", "-j4"]
        if args.phase == "core":
            command += ["server/all", "loader/all", "dlls/ntdll/all"]
        timeout = 1200
    log = WORK / "logs" / (record_prefix + args.phase + ".log")
    started = time.monotonic()
    timed_out = False
    with owned_path(log).open("w") as stream:
        process = subprocess.Popen(command, cwd=BUILD, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Only our newly created build process group is eligible for cleanup.
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
            returncode = process.returncode
    artifacts = []
    for relative in ["loader/wine", "server/wineserver",
                     "dlls/ntdll/ntdll.so", "dlls/ntdll/x86_64-unix/ntdll.so",
                     "dlls/ntdll/x86_64-windows/ntdll.dll",
                     "dlls/ntdll/i386-windows/ntdll.dll"]:
        path = BUILD / relative
        if path.is_file():
            artifacts.append({"path": str(path.relative_to(PROJECT)),
                              "sha256": sha(path), "bytes": path.stat().st_size})
    record = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "phase": args.phase, "command": command,
        "explicit_build_environment": {key: env[key] for key in [
            "PATH", "MACOSX_DEPLOYMENT_TARGET", "CC", "CXX", "OBJC", "BISON", "i386_CC", "x86_64_CC"]},
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "returncode": returncode, "timeout": timed_out,
        "passed": returncode == 0 and not timed_out,
        "log": str(log.relative_to(PROJECT)), "artifacts": artifacts,
        "scope": "Compilation only; reduced optional Unix dependencies, not a full-feature launcher runtime replacement",
        "protocol_version": 1810,
        "wine_executed": False, "prefixes_accessed": False,
        "active_runtime_modified": False, "installed": False,
        "variant": args.variant,
        "native_LDFLAGS": env.get("LDFLAGS", ""),
        "external_code_dependency": dependency_record,
    }
    owned_path(WORK / (record_prefix + args.phase + "-results.json")).write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({key: record[key] for key in ["phase", "passed", "returncode", "timeout", "elapsed_seconds", "artifacts"]}, indent=2))
    if not record["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
