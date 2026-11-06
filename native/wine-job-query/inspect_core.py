#!/usr/bin/env python3
"""Inspect built file formats/dependencies/symbols without running Wine."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

from common import PROJECT, WORK, PINS, owned_path


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def output(command):
    return subprocess.run(command, capture_output=True, text=True, check=True).stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=["core", "moltenvk"], default="core")
    args = parser.parse_args()
    build_directory = WORK / ("full-x86_64" if args.variant == "moltenvk" else "core-x86_64")
    build_record = WORK / ("wine-moltenvk-all-results.json" if args.variant == "moltenvk" else "wine-core-results.json")
    built = json.loads(build_record.read_text())
    if not built["passed"]:
        raise RuntimeError("Core build did not complete successfully")
    artifacts = []
    for artifact in built["artifacts"]:
        path = PROJECT / artifact["path"]
        if digest(path) != artifact["sha256"]:
            raise RuntimeError("Artifact differs from completed core build")
        item = dict(artifact)
        item["file_description"] = output(["/usr/bin/file", "-b", str(path)])
        if "Mach-O" in item["file_description"]:
            if "x86_64" not in item["file_description"]:
                raise RuntimeError("Unexpected Mach-O architecture")
            item["linked_libraries"] = output(["/usr/bin/otool", "-L", str(path)]).splitlines()[1:]
            item["build_version_load_command"] = output(["/usr/bin/vtool", "-show-build", str(path)]).splitlines()[1:]
            if path.name in ["ntdll.so", "wineserver"]:
                names = ("NtQueryInformationJobObject", "NtSetInformationJobObject") if path.name == "ntdll.so" else ("req_get_job_info", "req_set_job_limits")
                symbols = output(["/usr/bin/nm", "-an", str(path)]).splitlines()
                item["relevant_defined_symbols"] = [line for line in symbols if any("_" + name in line for name in names) and "FUN " not in line]
        elif path.parent.name == "x86_64-windows":
            if "PE32+" not in item["file_description"] or "x86-64" not in item["file_description"]:
                raise RuntimeError("Unexpected AMD64 PE architecture")
        elif path.parent.name == "i386-windows":
            if "PE32 executable" not in item["file_description"] or "Intel 80386" not in item["file_description"]:
                raise RuntimeError("Unexpected i386 PE architecture")
        else:
            raise RuntimeError("Unexpected core artifact format")
        artifacts.append(item)
    protocol = WORK / "source/include/wine/server_protocol.h"
    assertions = WORK / "source/server/request_handlers.h"
    if "#define SERVER_PROTOCOL_VERSION 1810" not in protocol.read_text():
        raise RuntimeError("Unexpected source protocol version")
    if '#include "request_handlers.h"' not in (WORK / "source/server/request.c").read_text():
        raise RuntimeError("Server request implementation lacks generated assertions")
    if not (build_directory / "server/request.o").is_file():
        raise RuntimeError("Server request object missing")
    record = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "build_record": str(build_record.relative_to(PROJECT)),
        "artifacts": artifacts,
        "protocol_version": 1810,
        "protocol_header_sha256": digest(protocol),
        "protocol_assertions_sha256": digest(assertions),
        "get_job_info_reply_limit_flags_offset": 16,
        "get_job_info_reply_bytes": 24,
        "original_generated_C_ASSERTs_compiled_in_server": True,
        "win32_wrapper": {"source": "source/dlls/kernel32/sync.c",
                          "lines": [331, 342],
                          "behavior": "Query/SetInformationJobObject directly map corresponding Nt status through set_ntstatus"},
        "wine_executed": False, "prefixes_accessed": False,
        "runtime_behavior_verified": False,
        "full_feature_engine_equivalence": False,
    }
    output_name = "candidate-artifact-inspection.json" if args.variant == "moltenvk" else "core-artifact-inspection.json"
    owned_path(WORK / output_name).write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"artifacts_inspected": len(artifacts),
                      "mach_o_arch": "x86_64", "pe_archs": ["AMD64", "i386"],
                      "protocol": 1810, "wine_executed": False}, indent=2))


if __name__ == "__main__":
    main()
