#!/usr/bin/env python3
"""Build the original Bison generator into this isolated build directory."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import urllib.request

from common import PROJECT, WORK, PINS, owned_path
TOOLS = WORK / "tools"
DOWNLOADS = WORK / "downloads"
URL = "https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz"
ANNOUNCEMENT_URL = "https://lists.gnu.org/archive/html/bug-bison/2021-09/msg00056.html"
# Original release announcement encodes its SHA256 in unpadded base64.
SHA = base64.b64decode("m7oCFMz38QecXVkhAEUie89hlRmEDr+oDNOEnP9aW/I=").hex()


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    owned_path(TOOLS)
    owned_path(DOWNLOADS)
    owned_path(WORK / "logs")
    TOOLS.mkdir(exist_ok=True)
    DOWNLOADS.mkdir(exist_ok=True)
    archive = DOWNLOADS / "bison-3.8.2.tar.xz"
    if not archive.exists():
        temporary = archive.with_suffix(".part")
        with urllib.request.urlopen(URL, timeout=30) as response, temporary.open("xb") as output:
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 10 * 1024 * 1024:
                    raise RuntimeError("Unexpected source archive size")
                output.write(chunk)
        if digest(temporary) != SHA:
            raise RuntimeError("Original Bison checksum mismatch")
        temporary.rename(archive)
    if digest(archive) != SHA:
        raise RuntimeError("Existing Bison archive checksum mismatch")
    source = TOOLS / "bison-3.8.2-source"
    owned_path(source)
    if source.exists():
        raise RuntimeError("Refusing to overwrite source directory")
    source.mkdir()
    with tarfile.open(archive, "r:xz") as package:
        for member in package:
            if member.name == "bison-3.8.2":
                continue
            if not member.name.startswith("bison-3.8.2/"):
                raise RuntimeError("Unexpected source member root")
            relative = member.name[len("bison-3.8.2/"):]
            parts = PurePosixPath(relative).parts
            if not parts or relative.startswith("/") or ".." in parts:
                raise RuntimeError("Unsafe source member path")
            path = source.joinpath(*parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                path.parent.mkdir(parents=True, exist_ok=True)
                with package.extractfile(member) as input_stream, path.open("xb") as output:
                    while True:
                        chunk = input_stream.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)
                path.chmod(member.mode & 0o777)
            else:
                raise RuntimeError("Unexpected source link or special member")
    build = TOOLS / "bison-3.8.2-build"
    prefix = TOOLS / "bison-3.8.2"
    owned_path(build)
    owned_path(prefix)
    if prefix.exists():
        raise RuntimeError("Refusing to overwrite an existing local tool prefix")
    build.mkdir()
    env = dict(os.environ)
    env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"
    commands = [[str(source / "configure"), "--disable-nls", "--prefix=" + str(prefix)],
                ["/usr/bin/make", "-j4"], ["/usr/bin/make", "install"]]
    logs = []
    for index, command in enumerate(commands):
        log = WORK / "logs" / ("bison-" + str(index) + ".log")
        with owned_path(log).open("w") as stream:
            result = subprocess.run(command, cwd=build, env=env, stdout=stream,
                                    stderr=subprocess.STDOUT, check=False)
        logs.append({"command": command, "log": str(log.relative_to(WORK)),
                     "returncode": result.returncode})
        if result.returncode:
            owned_path(WORK / "bison-build-failure.json").write_text(json.dumps(logs, indent=2) + "\n")
            raise RuntimeError("Bison build failed; see " + str(log))
    binary = prefix / "bin/bison"
    version = subprocess.run([str(binary), "--version"], text=True,
                             capture_output=True, check=True).stdout.splitlines()[0]
    record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "original_archive_url": URL, "original_archive_sha256": SHA,
              "original_archive_bytes": archive.stat().st_size,
              "checksum_primary_source": ANNOUNCEMENT_URL,
              "announcement_checksum_encoding": "base64 SHA256",
              "binary": str(binary.relative_to(WORK)), "binary_sha256": digest(binary),
              "version": version, "commands": logs, "global_install": False,
              "wine_executed": False, "prefixes_accessed": False}
    owned_path(WORK / "bison-build.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"version": version, "binary": record["binary"],
                      "sha256": record["binary_sha256"], "global_install": False}, indent=2))


if __name__ == "__main__":
    main()
