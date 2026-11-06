#!/usr/bin/env python3
"""Compare an owned DXMT backbuffer with its captured macOS window after Present."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

from PIL import Image

import run as dxgi


TITLE = 'Own DXMT Present Calibration'
MARKERS = {'red': (1, 1, 2, 2), 'green': (5, 1, 7, 2),
           'blue': (1, 5, 2, 7), 'yellow': (6, 6, 7, 7)}


def image_geometry(path):
    with Image.open(path) as image:
        width, height = image.size
        if (width, height) != (960, 640):
            return {'capture_pixels': [width, height], 'fills_client_as_expected': False}
        boxes = {color: [width, height, 0, 0] for color in MARKERS}
        for index, (red, green, blue) in enumerate(image.convert('RGB').getdata()):
            if min(red, green) > 170 and abs(red - green) <= 45 and min(red, green) - blue >= 80:
                color = 'yellow'
            elif red > 170 and red - max(green, blue) >= 80:
                color = 'red'
            elif green > 170 and green - max(red, blue) >= 80:
                color = 'green'
            elif blue > 170 and blue - max(red, green) >= 80:
                color = 'blue'
            else:
                color = None
            if color:
                x, y = index % width, index // width
                left, top, right, bottom = boxes[color]
                boxes[color] = [min(left, x), min(top, y), max(right, x + 1), max(bottom, y + 1)]
        complete = all(box[0] < box[2] and box[1] < box[3] for box in boxes.values())
        expected = {color: [extent * position // 8 for extent, position in zip((width, height) * 2, rect)]
                    for color, rect in MARKERS.items()}
        return {'capture_pixels': [width, height], 'marker_bounds': boxes, 'expected_full_client_bounds': expected,
                'all_markers_visible': complete,
                'fills_client_as_expected': complete and all(abs(a - b) <= 4 for color in MARKERS
                    for a, b in zip(boxes[color], expected[color]))}


def owned_pid(binary):
    processes = subprocess.check_output(['/bin/ps', '-axo', 'pid=,comm='], text=True, timeout=2)
    matches = []
    for row in processes.splitlines():
        fields = row.split(maxsplit=1)
        if len(fields) == 2 and fields[1].replace('\\', '/').removeprefix('Z:') == str(binary):
            matches.append(int(fields[0]))
    return matches[0] if len(matches) == 1 else None


def capture_until_done(binary, helper, image, stop, captured):
    while not stop.is_set():
        try:
            pid = owned_pid(binary)
            if pid is not None:
                raw = subprocess.check_output([str(helper), str(pid)], stderr=subprocess.DEVNULL, timeout=2)
                windows = [window for window in json.loads(raw) if window['title'] == TITLE and
                           window['pid'] == pid and (window['width'], window['height']) == (480, 320)]
                if len(windows) == 1 and owned_pid(binary) == pid:
                    window_id = windows[0]['window_id']
                    subprocess.run([str(helper), str(pid), str(window_id), str(image)], check=True, timeout=2,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    geometry = image_geometry(image)
                    captured.update(geometry, native_pid=pid, native_window_id=window_id,
                                    image=str(image.relative_to(dxgi.ROOT)))
                    if geometry.get('all_markers_visible'):
                        return
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        stop.wait(0.25)


def main():
    graphics = dxgi.graphics()
    runner, runtime = graphics.runner, graphics.runtime
    source = Path(__file__).with_name('present_probe.cpp').resolve()
    build = Path(tempfile.mkdtemp(prefix='windows-dxgi-present-', dir=dxgi.ROOT / 'build'))
    binary = build / 'present_probe.exe'
    helper = dxgi.ROOT / 'build/window-capture/capture-owned-window'
    capture_helper = runner.identity(helper)
    subprocess.run(['/opt/homebrew/bin/x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-Wall', '-Wextra',
                    '-Werror', '-static', str(source), '-o', str(binary), '-ld3d11', '-ld3dcompiler', '-luser32'], check=True)

    search = os.pathsep.join(map(str, (runtime.ENGINE/'lib/wine/x86_64-unix', runtime.MOLTENVK.parent,
                                      runtime.FRAMEWORKS, runtime.GST_LIB)))
    fallback = {'DYLD_FALLBACK_LIBRARY_PATH': search, 'DYLD_FALLBACK_FRAMEWORK_PATH': str(runtime.FRAMEWORKS)}
    validate = runner.validate_environment

    def validate_environment(env):
        if 'DYLD_LIBRARY_PATH' in env or any(env.get(name) != value for name, value in fallback.items()):
            raise ValueError('Require the exact system-first library selection')
        validate({name: value for name, value in env.items() if name not in fallback})

    def environment(verified):
        env = graphics.graphics_environment(verified)
        del env['DYLD_LIBRARY_PATH']
        env.update(fallback)
        return env

    def verify_inputs():
        if runner.identity(helper) != capture_helper:
            raise RuntimeError('Owned window capture helper changed')
        return {'runtime_inputs': [runner.identity(binary)], 'capture_helper': capture_helper,
                'source_inputs': [runner.identity(path) for path in (source, Path(__file__).resolve())],
                'renderer': graphics.verify_renderer(), 'only_test_window_sampled': True, 'fallback': fallback}

    def run_mode(mode, width, height):
        stop, captured = threading.Event(), {}
        image = build / (mode + '.png')
        worker = threading.Thread(target=capture_until_done, args=(binary, helper, image, stop, captured), daemon=True)

        def prepare(verified, env):
            proof = graphics.prepare_prefix(verified, env)
            worker.start()
            return proof

        def output(lines, code):
            stop.set()
            if worker.ident is not None:
                worker.join(timeout=5)
            rows = [json.loads(line) for line in lines]
            ready, complete = rows if len(rows) == 2 else ({}, {})
            verified = (code == 0 and ready.get('event') == 'ready' and ready.get('mode') == mode
                        and ready.get('visible') is True and ready.get('foreground') is False
                        and (ready.get('client_w'), ready.get('client_h')) == (480, 320)
                        and (ready.get('backbuffer_w'), ready.get('backbuffer_h')) == (width, height)
                        and complete.get('event') == 'complete' and complete.get('exit') == 0
                        and complete.get('presented', 0) > 0 and complete.get('window_destroyed') is True
                        and complete.get('class_unregistered') is True)
            return {'passed': verified and captured.get('fills_client_as_expected') is True,
                    'verified_present': verified, 'own_events': rows, 'surface_capture': dict(captured)}

        case = {'name': mode, 'binary': binary, 'cwd': build, 'arguments': (mode,), 'parse_output': output,
                'parse_diagnostics': graphics.parse_provider_diagnostics}
        try:
            return runner.run_cases([case], verify_inputs=verify_inputs, role='dxgi-present-' + mode,
                                    environment_factory=environment, prepare_prefix=prepare)
        finally:
            stop.set()
            if worker.ident is not None:
                worker.join(timeout=5)

    runner.validate_environment = validate_environment
    matched = run_mode('match', 480, 320)
    explicit = run_mode('explicit', 640, 360)
    return max(matched, explicit)


if __name__ == '__main__':
    raise SystemExit(main())
