#!/usr/bin/env python3
"""Load the linked M103 DLL and unchanged V12 providers in a fresh Wine profile."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

from verify_m103_abi import ROOT, STAGE, inventory, manifest_roles, verify


def copy_code(path, target, identity):
    from verify_m103_abi import identity as inspect_identity, stable_file

    before = stable_file(path)
    if inspect_identity(path, before) != identity:
        raise RuntimeError(f"Code identity changed: {path.name}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with path.open("rb") as source, target.open("xb") as output:
        shutil.copyfileobj(source, output)
    if inspect_identity(target, stable_file(target)) != identity or stable_file(path) != before:
        raise RuntimeError(f"Code copy identity changed: {path.name}")


def stage_providers(candidate, stage):
    roles = manifest_roles()
    pending = ["corert.dll", "bin/libcef.dll"]
    seen = {"nui-core.dll"}

    def enqueue(inspection):
        for _, dll in inspection["imports"]:
            if dll in roles:
                pending.append(dll)
            elif f"bin/{dll}" in roles:
                pending.append(f"bin/{dll}")

    enqueue(inventory(candidate))
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        row = roles[name]
        source = STAGE / row["name"]
        pin = row["bytes"], row["sha256"]
        enqueue(inventory(source, pin))
        copy_code(source, stage / row["name"], pin)
    return sorted(seen - {"nui-core.dll"})


def run_probe(stage, executable):
    spec = importlib.util.spec_from_file_location("m103_parity_runner", ROOT / "native/wine-parity-probes/run.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    runtime = runner.runtime
    prefix = ROOT / "prefixes" / ("wine-parity-nui-m103-load-" + uuid.uuid4().hex[:12])
    if prefix.exists() or prefix.is_symlink():
        raise RuntimeError("A fresh probe profile is required")
    runtime.PREFIX = prefix
    env = runtime.environment()
    if env["WINEPREFIX"] != str(prefix):
        raise RuntimeError("Unexpected Wine probe profile")
    del env["DYLD_LIBRARY_PATH"]
    del env["DYLD_FRAMEWORK_PATH"]
    env["DYLD_FALLBACK_LIBRARY_PATH"] = os.pathsep.join(map(str, (
        runtime.ENGINE / "lib/wine/x86_64-unix", runtime.MOLTENVK.parent, runtime.FRAMEWORKS, runtime.GST_LIB,
    )))
    env["DYLD_FALLBACK_FRAMEWORK_PATH"] = str(runtime.FRAMEWORKS)
    wine = runtime.ENGINE / "bin/wine"
    server = runtime.ENGINE / "bin/wineserver"
    result = {"prefix": str(prefix.relative_to(ROOT)), "boot": None, "exit": None, "cleanup": [],
              "probe_timed_out": False}
    with runner.probe_prefix(prefix, root=ROOT, create=True):
        try:
            runner.job_helper.seed_personal_directories(prefix)
            with (stage / "wineboot.log").open("x") as log:
                result["boot"] = subprocess.run(
                    [str(wine), "wineboot", "-i"], cwd=stage, env=env,
                    stdout=log, stderr=subprocess.STDOUT, timeout=60,
                ).returncode
            if result["boot"] != 0:
                raise RuntimeError("Fresh Wine profile initialization failed")
            runner.assert_account_free_prefix(prefix, root=ROOT)
            probe_env = dict(env, WINEDEBUG="-all,err+all,+loaddll")
            with (stage / "probe.log").open("x") as log:
                try:
                    result["exit"] = subprocess.run(
                        [str(wine), str(executable)], cwd=stage, env=probe_env,
                        stdout=log, stderr=subprocess.STDOUT, timeout=75,
                    ).returncode
                except subprocess.TimeoutExpired:
                    result["probe_timed_out"] = True
        finally:
            for flag in ("-k", "-w"):
                result["cleanup"].append(subprocess.run(
                    [str(server), flag], env=env, capture_output=True, timeout=15,
                ).returncode)
            runner.assert_account_free_prefix(prefix, root=ROOT)
    markers = (stage / "probe.log").read_text(errors="replace").splitlines()
    result["markers"] = [line for line in markers if line.startswith("NUI_")]
    result["passed"] = (result["exit"] == 0 and result["cleanup"] == [0, 0]
                        and any(line.startswith("NUI_CEF_API_MATCH version=103 ") for line in markers)
                        and any(line.startswith("NUI_LOAD_PROBE_OK ") for line in markers))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path, help="Isolated M103 build folder")
    build = parser.parse_args().build.absolute()
    if (build.resolve(strict=True) != build or build.parent != ROOT / "build"
            or not build.name.startswith("windows-nui-m103-build-")):
        raise SystemExit("Expected the isolated M103 build folder")
    candidate = build / "objects/nui-core.dll"
    executable = build / "objects/nui-load-probe.exe"
    abi = verify(candidate)
    if not abi["passed_static_provider_contract"] or abi["accessor_mismatches_require_manual_layout_review"]:
        raise SystemExit("M103 DLL failed the V12 static provider or accessor check")
    stage = Path(tempfile.mkdtemp(prefix="load-", dir=build))
    candidate_identity = abi["candidate"]
    copy_code(candidate, stage / candidate.name, (candidate_identity["bytes"], candidate_identity["sha256"]))
    executable_identity = inventory(executable)["identity"]
    copy_code(executable, stage / executable.name, (executable_identity["bytes"], executable_identity["sha256"]))
    providers = stage_providers(candidate, stage)
    result = run_probe(stage, stage / executable.name)
    result.update(candidate=candidate_identity, load_probe=executable_identity, stock_providers=providers,
                  scope="LoadLibrary and both CEF API hashes. No component or browser initialization.")
    report = stage / "result.json"
    report.write_text(json.dumps(result, indent=2) + "\n")
    print(report)
    for marker in result["markers"]:
        print(marker)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
