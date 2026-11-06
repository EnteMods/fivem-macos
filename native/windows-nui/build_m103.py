#!/usr/bin/env python3
"""Build the public M103 NUI component in a fresh directory for V12 ABI checks."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from prepare_cef import ROOT, ensure_plain_path, extract_build_inputs, sha


SOURCE_REVISION = "0105063b0394b1b9d085c917a8dc9c9abf0a620f"
CEF_BUILD = "cef_binary_103.0.0-cfx-m103.2605+g1316dae+chromium-103.0.5060.141_windows64_minimal"
CEF_SHA256 = "4ff20c5e8e0a4286e976a5ca7b8cfe99945e9537a5492cdfe2a4fa6793223511"
CEF_ORIGIN = "https://runtime.fivem.net/build/cef/"
CEF_COMPILER_HEADER = "include/base/cef_compiler_specific.h"
CEF_COMPILER_HEADER_SHA256 = "17b9a7aa2aed2e95fd80b969a0f66c7cdad1a13187b1e1cf37dda912356ff8f3"
COMPONENT = Path("code/components/nui-core")
OLD_BINDING = b"auto& frameUrl = (frame) ? frame->GetURL().ToString() : std::string{};"
OLD_POLL = b"rootWindow->SignalPoll(std::string(frameName.c_str()));"
NEW_POLL = b"std::string frame(frameName.c_str());\r\n\t\trootWindow->SignalPoll(frame);"
OLD_ARGS = b"auto& argList = message->GetArgumentList();"
COMPILER_ADAPTATIONS = {
    Path("src/NUIClient.cpp"): (OLD_BINDING, b"const " + OLD_BINDING),
    Path("src/CefOverlay.cpp"): (OLD_POLL, NEW_POLL),
    Path("src/NUICallbacks_PushEvent.cpp"): (OLD_ARGS, b"const " + OLD_ARGS),
}


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args])


def stage_component(source, destination, resize=False, timing=False):
    files = {}
    tree = git(source, "ls-tree", "-r", "-z", SOURCE_REVISION, "--", str(COMPONENT))
    for row in tree.split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, kind, object_id = metadata.split()
        if mode != b"100644" or kind != b"blob":
            raise SystemExit("Unexpected NUI source entry")
        relative = Path(name.decode()).relative_to(COMPONENT)
        if ".." in relative.parts:
            raise SystemExit("Unexpected NUI source path")
        files[relative] = object_id.decode()
    for required in (*COMPILER_ADAPTATIONS, Path("src/NUIWindow.cpp"), Path("src/NUIRenderHandler.cpp")):
        if required not in files:
            raise SystemExit("Pinned NUI component is incomplete")
    staged = {}
    for relative, object_id in files.items():
        data = (source / COMPONENT / relative).read_bytes()
        object_bytes = b"blob " + str(len(data)).encode() + b"\0" + data
        if hashlib.sha1(object_bytes).hexdigest() != object_id:
            raise SystemExit(f"Checked-out source differs from the pinned tree: {relative}")
        if relative in COMPILER_ADAPTATIONS:
            before, after = COMPILER_ADAPTATIONS[relative]
            if data.count(before) != 1:
                raise SystemExit(f"Unexpected clang-cl adaptation input: {relative}")
            data = data.replace(before, after)
        staged[str(relative)] = data
    if resize:
        from resize_overlay import SOURCE_PINS, apply
        staged.update(apply({name: staged[name] for name in SOURCE_PINS}))
    if timing:
        import timing_overlay
        staged.update(timing_overlay.apply({name: staged[name] for name in timing_overlay.SOURCE_PINS}))
    for relative, data in staged.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return {name: hashlib.sha256(data).hexdigest() for name, data in staged.items()}


def use_stock_msvc_parameter_abi(cef):
    header = cef / CEF_COMPILER_HEADER
    original = header.read_bytes()
    before = b"#if defined(__clang__) && __has_attribute(trivial_abi)"
    if hashlib.sha256(original).hexdigest() != CEF_COMPILER_HEADER_SHA256 or original.count(before) != 1:
        raise SystemExit("Unexpected M103 compiler header")
    # The stock MSVC modules pass scoped_refptr by address. Clang's opt-in
    # trivial ABI passes its payload directly under the same mangled name.
    adapted = original.replace(before, before + b" && !defined(_MSC_VER)")
    header.write_bytes(adapted)
    return {"path": CEF_COMPILER_HEADER, "original": CEF_COMPILER_HEADER_SHA256,
            "adapted": hashlib.sha256(adapted).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Sparse checkout of the pinned official public source")
    parser.add_argument("--resize", action="store_true", help="Build the bounded software resize candidate")
    parser.add_argument("--timing", action="store_true", help="Include the opt-in numeric menu timing diagnostics")
    args = parser.parse_args()
    if args.timing and not args.resize:
        parser.error("--timing requires the resize overlay")
    source = args.source.resolve(strict=True)
    if git(source, "rev-parse", "HEAD").decode().strip() != SOURCE_REVISION:
        raise SystemExit(f"Expected public source {SOURCE_REVISION}")
    if git(source, "show", f"{SOURCE_REVISION}:vendor/cef/cef_build_name.txt").decode().strip() != CEF_BUILD:
        raise SystemExit("CEF package differs from the pinned source")
    setup = git(source, "show", f"{SOURCE_REVISION}:code/tools/ci/psm1/cfxSetupCEF.psm1")
    if CEF_ORIGIN.encode() not in setup:
        raise SystemExit("CEF origin differs from the pinned source")
    archive = ROOT / "downloads/cef" / (CEF_BUILD + ".zip")
    ensure_plain_path(archive)
    if sha(archive) != CEF_SHA256:
        raise SystemExit("CEF package hash mismatch")

    build = Path(tempfile.mkdtemp(prefix="windows-nui-m103-build-", dir=ROOT / "build"))
    print(build, flush=True)
    component = build / "component"
    cef = build / "cef"
    source_files = stage_component(source, component, args.resize, args.timing)
    _, cef_files = extract_build_inputs(archive, cef, CEF_BUILD, {})
    cef_msvc_abi = use_stock_msvc_parameter_abi(cef)
    manifest = {
        "source_revision": SOURCE_REVISION, "component_files": source_files, "resize_overlay": args.resize,
        "cef_origin": CEF_ORIGIN, "cef_archive_sha256": CEF_SHA256, "cef_files": cef_files,
        "cef_msvc_parameter_abi": cef_msvc_abi,
    }
    if args.timing:
        manifest["menu_timing_overlay"] = True
    (build / "inputs.json").write_text(json.dumps(manifest, indent=2) + "\n")
    output = build / "objects"
    configure = [
        "cmake", "-S", str(Path(__file__).resolve().parent), "-B", str(output), "-G", "Ninja",
        "-DCMAKE_TOOLCHAIN_FILE=" + str(ROOT / "native/windows-core/toolchain.cmake"),
        "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        "-DCFX_NUI_COMPONENT_DIR=" + str(component), "-DCFX_CEF_ROOT=" + str(cef),
    ]
    with (build / "configure.log").open("w") as log:
        subprocess.run(configure, stdout=log, stderr=subprocess.STDOUT, check=True)
    with (build / "build.log").open("w") as log:
        result = subprocess.run(
            ["cmake", "--build", str(output), "--target", "NuiCore", "nui_load_probe", "--parallel", "6", "--", "-k", "0"],
            stdout=log, stderr=subprocess.STDOUT,
        )
    print(f"M103 NUI build exit {result.returncode}", flush=True)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
