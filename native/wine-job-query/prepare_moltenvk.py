#!/usr/bin/env python3
"""Stage only the already pinned original MoltenVK code dependency locally."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

from common import PROJECT, WORK, PINS, owned_path
URL = "https://github.com/gauthierpiarrette/highball/releases/download/engine-components/moltenvk-1.4.2-shadow-import-1-linear-fallback-1-shadow-readback-1-x86_64.tar.gz"
SHA = "7c84c592c023e761994cf4a0f5fb2e0a8a22bac8dfe3f787c4135a735f873e90"
SIZE = 1733593


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    download = owned_path(WORK / "downloads/moltenvk-pinned-x86_64.tar.gz")
    if not download.exists():
        temporary = download.with_suffix(".part")
        request = urllib.request.Request(URL, headers={"User-Agent": "Local-source-build"})
        with urllib.request.urlopen(request, timeout=30) as response, temporary.open("xb") as output:
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > SIZE:
                    raise RuntimeError("Unexpected pinned dependency size")
                output.write(chunk)
        if total != SIZE or digest(temporary) != SHA:
            raise RuntimeError("Pinned dependency download identity mismatch")
        temporary.rename(download)
    if download.stat().st_size != SIZE or digest(download) != SHA:
        raise RuntimeError("Existing dependency archive identity mismatch")
    destination = WORK / "dependencies/moltenvk/libMoltenVK.dylib"
    owned_path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(download, "r:gz") as archive:
        matches = [member for member in archive if member.name in ["libMoltenVK.dylib", "./libMoltenVK.dylib"] and member.isfile()]
        if len(matches) != 1:
            raise RuntimeError("Unexpected original dependency archive layout")
        data = archive.extractfile(matches[0]).read()
    if destination.exists() and destination.read_bytes() != data:
        raise RuntimeError("Refusing to replace existing dependency code")
    if not destination.exists():
        destination.write_bytes(data)
        destination.chmod(0o755)
    description = subprocess.run(["/usr/bin/file", "-b", str(destination)],
                                 capture_output=True, text=True, check=True).stdout.strip()
    if "Mach-O" not in description or "x86_64" not in description:
        raise RuntimeError("Dependency is not the required x86_64 Mach-O")
    symbols = subprocess.run(["/usr/bin/nm", "-gU", str(destination)],
                             capture_output=True, text=True, check=True).stdout
    if " _vkGetInstanceProcAddr" not in symbols:
        raise RuntimeError("Dependency lacks original public Vulkan entry point")
    record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "original_url": URL, "archive_sha256": SHA, "archive_bytes": SIZE,
              "pin_source": "../GTA-V-macOS/docs/matched-engine-r29-upstream.json components.moltenvk",
              "path": str(destination.relative_to(WORK)), "sha256": digest(destination),
              "bytes": len(data), "file_description": description,
              "public_entrypoint_static_check": True,
              "library_loaded_or_executed": False, "renderer_tested": False,
              "active_runtime_modified": False}
    owned_path(WORK / "moltenvk-build-dependency.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({key: record[key] for key in ["path", "sha256", "bytes", "renderer_tested"]}, indent=2))


if __name__ == "__main__":
    main()
