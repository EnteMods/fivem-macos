#!/usr/bin/env python3
"""Fetch only exact pinned original source/code inputs into an isolated build cache."""
import hashlib
from pathlib import Path, PurePosixPath
import urllib.request

from common import PINS, WORK


def hashes(path):
    value = hashlib.sha256()
    blob = hashlib.sha1(b"blob " + str(path.stat().st_size).encode() + b"\0")
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
            blob.update(chunk)
    return value.hexdigest(), blob.hexdigest()


def fetch(item, destination):
    for ancestor in [destination] + list(destination.parents):
        if ancestor == WORK.parent:
            break
        if ancestor.is_symlink():
            raise RuntimeError("Source download path must not contain symlinks")
    if destination.exists():
        if not destination.is_file():
            raise RuntimeError("Existing pinned input is not a regular file")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".part")
        request = urllib.request.Request(item["url"], headers={"User-Agent": "Local-pinned-source-build"})
        with urllib.request.urlopen(request, timeout=30) as response, temporary.open("xb") as output:
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > item["bytes"]:
                    raise RuntimeError("Pinned source exceeds expected size")
                output.write(chunk)
        if total != item["bytes"] or hashes(temporary)[0] != item["sha256"]:
            raise RuntimeError("Original source download identity mismatch")
        temporary.rename(destination)
    actual, git_blob = hashes(destination)
    if destination.stat().st_size != item["bytes"] or actual != item["sha256"]:
        raise RuntimeError("Pinned original source identity mismatch")
    if "git_blob_sha1" in item and git_blob != item["git_blob_sha1"]:
        raise RuntimeError("Pinned original Git blob identity mismatch")


def main():
    for item in PINS["archives"]:
        fetch(item, WORK / "downloads" / item["filename"])
    for item in PINS["highball"]["files"]:
        relative = PurePosixPath(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("Unsafe pinned original source path")
        fetch(item, WORK / "downloads/highball" / Path(*relative.parts))
    print("Verified 3 pinned archives and 25 original Highball source blobs; no extraction/build/runtime")


if __name__ == "__main__":
    main()
