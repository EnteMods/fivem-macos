#!/usr/bin/env python3
"""Compare original RGL's observed FiveM argument pair on the current parity runtime."""
import argparse
import importlib.util
import json
from pathlib import Path

from run_source import select_runtime_profile

ROOT = Path(__file__).resolve().parents[2]
DURATION = 120


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'run'))
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('private_rgl_comparison',
        ROOT / 'native/windows-client/run_rockstar_diagnostic.py')
    original = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original)
    runtime, context = select_runtime_profile('parity')
    base_plan = original.plan

    def plan(*values):
        result = base_plan(*values)
        result.update(runtime_profile='parity',
                      engine_manifest_sha256=context['live_components']['engine']['manifest_sha256'],
                      runtime_selector='native/windows-client/parity_runtime_profile.py',
                      wrapper='native/windows-client/run_rockstar_parity_comparison.py')
        return result

    def load_runtime():
        runtime.before_source_spawn()
        return runtime

    # The old lifecycle remains private to this invocation; its guards and cleanup run unchanged.
    original.plan = plan
    original.load_runtime = load_runtime
    if args.action == 'inspect':
        result = original.inspect(DURATION, True, True, True)
        runtime.before_source_spawn()
        result['runtime_imported'] = True
        result['runtime_started'] = False
        print(json.dumps(result, indent=2))
        return 0
    return original.run(DURATION, True, True, True)


if __name__ == '__main__':
    raise SystemExit(main())
