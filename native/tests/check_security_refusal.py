#!/usr/bin/env python3
import signal
import subprocess
import sys

expected = "Native macOS client initialization is unavailable: required vendor security and game runtime components have not been ported."
result = subprocess.run([sys.argv[1], "--initialize-client"], capture_output=True, text=True, timeout=10)
if result.returncode != -signal.SIGTERM:
    raise SystemExit(f"Expected SIGTERM security refusal, got {result.returncode}: {result.stderr}")
if result.stderr != expected:
    raise SystemExit(f"Unexpected refusal diagnostic: {result.stderr!r}")
print("Native initialization refused with the exact vendor-security diagnostic and SIGTERM.")
