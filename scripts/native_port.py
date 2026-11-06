#!/usr/bin/env python3
"""Prepare and build the native ARM64 port worktree without touching GTA."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "port/fivem"
PRISTINE = ROOT / "upstream/fivem"
BUILD = ROOT / "build/native-arm64"
MANIFEST = ROOT / "config/native-port.json"


def run(args, cwd=ROOT):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=cwd, check=True)


def verify_patch_digests(config):
    for item in config["patches"]:
        patch = ROOT / item["path"]
        if hashlib.sha256(patch.read_bytes()).hexdigest() != item["sha256"]:
            raise SystemExit("Patch digest mismatch: " + str(patch))


def audit_patch_queue(config, revision, repository=PRISTINE):
    """Replay reviewed patch inputs against a local Git commit in a temporary folder."""
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise SystemExit("Audit requires a full local commit ID.")
    verify_patch_digests(config)

    def git(*args):
        return subprocess.check_output(["git", "-C", str(repository), *args])

    if git("cat-file", "-t", revision).strip() != b"commit":
        raise SystemExit("Audit target must be a commit.")
    final_sources = {}
    for item in config["patches"]:
        final_sources.update(item["source_sha256"])
    paths = sorted(final_sources)
    for path in paths:
        relative = PurePosixPath(path)
        if not relative.parts or relative.is_absolute() or ".." in relative.parts or relative.as_posix() != path:
            raise SystemExit("Invalid patch source path in the manifest.")
    base = config["base_revision"]
    gitlinks = sorted(config.get("submodule_pins", {}))
    report = {
        "base_revision": base,
        "candidate_revision": revision,
        "changed_patched_sources": git("diff", "--name-only", base, revision, "--", *paths).decode().splitlines(),
        "changed_pinned_gitlinks": (git("diff", "--name-only", base, revision, "--", *gitlinks).decode().splitlines()
                                    if gitlinks else []),
        "applied_patches": [],
    }
    with tempfile.TemporaryDirectory(prefix="fivem-patch-audit-") as directory:
        scratch = Path(directory)
        # Give git apply its own root even when TMPDIR is inside a worktree.
        subprocess.run(["git", "init", "-q"], cwd=scratch, check=True)
        for row in git("ls-tree", "-rz", revision, "--", *paths).split(b"\0"):
            if not row:
                continue
            metadata, name = row.split(b"\t", 1)
            mode, kind, digest = metadata.decode().split()
            relative = name.decode()
            if mode not in ("100644", "100755") or kind != "blob" or relative not in final_sources:
                raise SystemExit("Audit requires regular tracked patch inputs.")
            target = scratch / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(git("cat-file", "blob", digest))
            target.chmod(int(mode[-3:], 8))

        for item in config["patches"]:
            patch = ROOT / item["path"]
            applied = subprocess.run(["git", "apply", str(patch)], cwd=scratch, capture_output=True, text=True)
            if applied.returncode:
                report.update(failed_patch=item["path"], patch_error=applied.stderr.strip())
                return report
            report["applied_patches"].append(item["path"])
        report["changed_patched_outputs"] = [
            path for path in paths if not (scratch / path).is_file()
            or hashlib.sha256((scratch / path).read_bytes()).hexdigest() != final_sources[path]
        ]
    return report


def patch_queue_prefix(config, source):
    if source.resolve() == PRISTINE.resolve() or source.is_symlink():
        raise SystemExit("Refusing to patch the pristine source tree.")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if head != config["base_revision"]:
        raise SystemExit("Worktree revision changed. Review/rebase the patch queue explicitly.")
    verify_patch_digests(config)
    expected = {}
    for item in config["patches"]:
        expected.update(dict.fromkeys(item["source_sha256"]))
    if not expected:
        raise SystemExit("Patch queue must pin its source files.")
    actual = {}
    for relative in expected:
        path = PurePosixPath(relative)
        if not path.parts or path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
            raise SystemExit("Invalid patch source path in the manifest.")
        current = source / relative
        if current.resolve() != current.absolute():
            raise SystemExit("Refusing a redirected patch source: " + relative)
        if not current.exists():
            actual[relative] = None
        elif current.is_file():
            actual[relative] = hashlib.sha256(current.read_bytes()).hexdigest()
        else:
            raise SystemExit("Patch source must be a regular file: " + relative)
    rows = subprocess.check_output(["git", "ls-tree", "-rz", head, "--", *expected], cwd=source)
    for row in rows.split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, kind, digest = metadata.decode().split()
        relative = name.decode()
        if mode not in ("100644", "100755") or kind != "blob" or relative not in expected:
            raise SystemExit("Patch base requires regular tracked source files.")
        original = subprocess.check_output(["git", "cat-file", "blob", digest], cwd=source)
        expected[relative] = hashlib.sha256(original).hexdigest()
    matched = 0 if actual == expected else None
    for count, item in enumerate(config["patches"], 1):
        expected.update(item["source_sha256"])
        if actual == expected:
            matched = count
    if matched is None:
        raise SystemExit("Worktree does not match a pinned patch prefix; refusing unrecognized source changes.")
    return matched


def apply_patches(config, source=SOURCE):
    completed = patch_queue_prefix(config, source)
    if completed == len(config["patches"]):
        print("Complete pinned patch queue already applied; all final source bytes match.")
        return
    for item in config["patches"][completed:]:
        patch = ROOT / item["path"]
        run(["git", "apply", "--check", patch], source)
        run(["git", "apply", patch], source)
        for relative, expected in item.get("source_sha256", {}).items():
            if hashlib.sha256((source / relative).read_bytes()).hexdigest() != expected:
                raise SystemExit("Patched source digest mismatch: " + relative)


def prepare(config):
    if not PRISTINE.is_dir():
        raise SystemExit("Missing upstream/fivem checkout. See native/README.md.")
    if not SOURCE.exists():
        SOURCE.parent.mkdir(exist_ok=True)
        run(["git", "worktree", "add", "--detach", SOURCE, config["base_revision"]], PRISTINE)
    apply_patches(config)
    for relative, expected in config.get("submodule_pins", {}).items():
        row = subprocess.check_output(["git", "ls-tree", config["base_revision"], "--", relative],
                                      cwd=SOURCE, text=True).strip()
        if not row.startswith("160000 commit " + expected + "\t"):
            raise SystemExit("Submodule pin differs from base revision: " + relative)
    run(["git", "submodule", "update", "--init", "--depth", "1", "--jobs", "6", "--",
         *config["submodules"]], SOURCE)


def build():
    config = json.loads(MANIFEST.read_text())
    if patch_queue_prefix(config, SOURCE) != len(config["patches"]):
        raise SystemExit("Patch queue incomplete. Prepare the complete pinned source before building.")
    for command in ("cmake", "ninja", "clang++"):
        if not shutil.which(command):
            raise SystemExit("Required developer tool missing: " + command)
    run(["cmake", "-S", ROOT / "native", "-B", BUILD, "-G", "Ninja",
         "-DCFX_SOURCE_DIR=" + str(SOURCE), "-DCMAKE_OSX_ARCHITECTURES=arm64",
         "-DCMAKE_BUILD_TYPE=RelWithDebInfo", "-DCMAKE_POLICY_VERSION_MINIMUM=3.5"])
    run(["cmake", "--build", BUILD, "--parallel", "6"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "build", "test", "audit"))
    parser.add_argument("--revision", help="Full local Git commit ID for the read-only patch audit")
    args = parser.parse_args()
    if (args.action == "audit") != (args.revision is not None):
        parser.error("--revision is required for audit and applies only to audit")
    if args.action == "audit":
        report = audit_patch_queue(json.loads(MANIFEST.read_text()), args.revision)
        print(json.dumps(report, indent=2))
        if "failed_patch" in report:
            raise SystemExit(1)
    elif args.action == "prepare":
        prepare(json.loads(MANIFEST.read_text()))
    elif args.action == "build":
        build()
    else:
        run(["ctest", "--test-dir", BUILD, "--output-on-failure"])
