#!/usr/bin/env python3
"""Prepare an isolated pinned Wine source tree; never launch Wine or use a prefix."""
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

from common import PROJECT, WORK, PINS, owned_path
ARCHIVE = WORK / "downloads/crossover-sources-26.3.0.tar.gz"
ARCHIVE_SHA = "ac99c8ca4b3848f3e81784135f023df266b61c2345726ea55a50b3e030dd6872"
ARCHIVE_BYTES = 149054023
PATCH_CACHE = WORK / "downloads/highball"
SOURCE = WORK / "source"


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command, directory, log):
    with owned_path(log).open("w") as stream:
        result = subprocess.run(command, cwd=directory, stdout=stream,
                                stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise RuntimeError("Command failed with exit {}: {}; see {}".format(
            result.returncode, command[0], log.relative_to(PROJECT)))


def main():
    owned_path(SOURCE)
    owned_path(WORK / "logs")
    if SOURCE.exists():
        raise RuntimeError("Refusing to overwrite an existing source tree")
    if ARCHIVE.stat().st_size != ARCHIVE_BYTES or sha(ARCHIVE) != ARCHIVE_SHA:
        raise RuntimeError("Original source archive identity mismatch")
    tree_sha = PINS["highball"]["tree"]
    blobs = {item["path"]: item["git_blob_sha1"] for item in PINS["highball"]["files"]}
    patches = sorted((PATCH_CACHE / "patches").glob("*.patch"))
    expected = ["0001", "0002", "0003"] + [str(i).zfill(4) for i in range(5, 25)]
    if [path.name.split("-")[0] for path in patches] != expected:
        raise RuntimeError("Unexpected original patch set")
    for path in patches + [PATCH_CACHE / "inputs.json", PATCH_CACHE / ".github/workflows/build.yml"]:
        data = path.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob != blobs[str(path.relative_to(PATCH_CACHE))]:
            raise RuntimeError("Pinned original source blob mismatch")
    proposal = PROJECT / PINS["query_patch"]["path"]
    if sha(proposal) != "51c250d7d05c7a30a816b7cedbe48009240ee29fb5ccb6da12e42fddcfd51127":
        raise RuntimeError("Readback proposal identity mismatch")
    WORK.mkdir(parents=True, exist_ok=True)
    staging = WORK / (".source-staging-" + str(os.getpid()))
    staging.mkdir()
    seen = set()
    regular_bytes = 0
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        for member in archive:
            if not member.name.startswith("sources/wine/"):
                continue
            relative = member.name[len("sources/wine/"):]
            parts = PurePosixPath(relative).parts
            if not parts or relative.startswith("/") or ".." in parts:
                raise RuntimeError("Unsafe source member path")
            target = staging.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or relative in seen:
                raise RuntimeError("Unexpected source member type or duplicate")
            seen.add(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open("xb") as destination:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    destination.write(chunk)
            target.chmod(member.mode & 0o777)
            regular_bytes += member.size
    log_dir = WORK / "logs"
    log_dir.mkdir(exist_ok=True)
    patch_records = []
    for path in patches:
        run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(path)], staging,
            log_dir / (path.stem + ".log"))
        patch_records.append({"path": str(path.relative_to(PROJECT)), "sha256": sha(path)})
    query_inputs = ["dlls/ntdll/unix/sync.c", "server/process.c", "server/protocol.def"]
    matched_hashes = {name: sha(staging / name) for name in query_inputs}
    proposal_audit = {"files": PINS["query_patch"]["source_files"]}
    for item in proposal_audit["files"]:
        if matched_hashes[item["path"]] != item["matched_engine_source_sha256"]:
            raise RuntimeError("Full patch replay differs from reviewed query input")
    generated = ["include/wine/server_protocol.h", "server/request_trace.h", "server/request_handlers.h"]
    before_generator = {name: sha(staging / name) for name in generated}
    run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(proposal)], staging,
        log_dir / "job-query-readback.log")
    for item in proposal_audit["files"]:
        if sha(staging / item["path"]) != item["proposed_sha256"]:
            raise RuntimeError("Applied query source differs from reviewed proposal")
    if sha(staging / "tools/make_requests") != PINS["original_generator"]["sha256"]:
        raise RuntimeError("Original protocol generator identity mismatch")
    if before_generator != PINS["original_generator"]["generated_before_sha256"]:
        raise RuntimeError("Original protocol baseline identity mismatch")
    run(["perl", "tools/make_requests"], staging, log_dir / "make-requests.log")
    after_generator = {name: sha(staging / name) for name in generated}
    if after_generator != PINS["original_generator"]["generated_after_sha256"]:
        raise RuntimeError("Generated protocol differs from reviewed output")
    record = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_archive": str(ARCHIVE.relative_to(PROJECT)),
        "source_archive_sha256": ARCHIVE_SHA,
        "source_archive_bytes": ARCHIVE_BYTES,
        "original_engine_commit": "5d6bbe0c83f4592a8798abba48cc7e8f58feb492",
        "original_engine_tree": tree_sha,
        "source_regular_files": len(seen), "source_regular_bytes": regular_bytes,
        "original_patches": patch_records, "original_patch_fuzz": 0,
        "matched_query_input_sha256": matched_hashes,
        "proposal_sha256": sha(proposal),
        "generated_before_sha256": before_generator,
        "generated_after_sha256": after_generator,
        "source_tree": str(SOURCE.relative_to(PROJECT)),
        "complete_original_wine_source_extracted": True,
        "original_generator_executed": True,
        "compiler_executed": False, "wine_executed": False,
        "runtime_directories_modified": False, "prefixes_accessed": False,
    }
    staging.rename(SOURCE)
    owned_path(WORK / "source-preparation.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"source": record["source_tree"], "files": len(seen),
                      "original_patch_count": len(patches),
                      "original_generator_executed": True, "compiled": False}, indent=2))


if __name__ == "__main__":
    main()
