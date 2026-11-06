#!/usr/bin/env python3
"""Leave the user's original Source-prefix RGL open on the tested parity engine."""
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from run_source import ROOT, PREFIX, select_runtime_profile, use_system_dyld_search
from run_user_rockstar_session import preflight
from source_main_environment import _source_main_file_lock
from rockstar_code_policy import CODE_ROOTS


def main():
    system_dyld_search = sys.argv[1:] == ['--system-dyld-search']
    if sys.argv[1:] and not system_dyld_search:
        raise SystemExit('Usage: run_user_rockstar_parity.py [--system-dyld-search]')
    binding = preflight()
    runtime, context = select_runtime_profile('parity')
    with _source_main_file_lock(PREFIX):
        if preflight() != binding:
            raise RuntimeError('Source-prefix or original Rockstar code identity changed.')
        env = dict(runtime.environment())
        if any(key.lower().startswith('citizenfx_') for key in env):
            raise RuntimeError('Refusing inherited CitizenFX roles during manual Rockstar login.')
        env.update(WINEPREFIX=str(PREFIX), WINESERVER=str(runtime.ENGINE / 'bin/wineserver'), WINEDEBUG='-all')
        for key in ('WINESERVERSOCKET', 'WINELOADER', 'WINELOADERNOEXEC'):
            env.pop(key, None)
        if system_dyld_search:
            use_system_dyld_search(env)
        executable = PREFIX / CODE_ROOTS[0] / 'Launcher.exe'
        label = 'user-rockstar-parity-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        output = ROOT / 'research' / (label + '.json')
        record = dict(binding, at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            prefix='prefixes/fivem-source-main', scope='Original RGL for user manual sign-in before FiveM',
            runtime_profile='parity', controller_pid=os.getpid(), automatic_time_limit_seconds=None,
            system_dyld_search=system_dyld_search,
            automatic_wine_termination=False, authentication_contents_read_or_copied=False,
            stdout_or_stderr_persisted=False, status='starting')
        process = subprocess.Popen([str(runtime.WINE), str(executable)], cwd=executable.parent,
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        record.update(status='manual-login-session-open', native_wine_pid=process.pid)
        with output.open('x') as target:
            json.dump(record, target, indent=2); target.write('\n')
        print('Original Rockstar Launcher open on parity. No automatic close or Wine termination.', flush=True)
        print('Controller PID:', os.getpid(), '; native Wine PID:', process.pid, flush=True)
        print('Session:', output, flush=True)
        try:
            while True:
                process.poll()
                time.sleep(1)
        except KeyboardInterrupt:
            record.update(status='controller-detached-without-terminating-wine',
                          controller_ended_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                          native_wine_parent_exit_on_detach=process.poll())
            output.write_text(json.dumps(record, indent=2) + '\n')
        # Deliberately leave the user's RGL, services and login UI untouched on detach.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
