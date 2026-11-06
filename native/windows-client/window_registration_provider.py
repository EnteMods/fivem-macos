"""Admit the tested User32 provider only for the explicit registration trace."""

import json
import os

from run_main import ROOT, plain, sha


PROVIDER = ROOT/'build/wine-window-registration-hnyy8ikw'
PINS = {
    'native/windows-client/window_registration_trace.py': 'bb920dda58e6d98d065451828f06179649bdbecdad75c34be0c519ed409f3da7',
    'native/windows-client/window_registration_name_trace.py': '45116f1b0ddc398455378ee7eae442af1ec3bcb7599549d97c2158d5fd53e5d8',
    'native/windows-client/window_registration_resolution_trace.py': '1ffe9e95a80074030f7695989203aa8a5c98c0b5840238c0e830f4bb5238438c',
    'build/wine-window-registration-hnyy8ikw/build.json': '5431369816114ca304421f08dff8c65ac67873e57a4ae41b3a334d2bf4e5299b',
    'build/wine-window-registration-hnyy8ikw/x86_64-windows/user32.dll': 'ea44ab7bdd5731d8e3b84eaf4c57b777c2b856616579b47938a8dd3b6e54cdf5',
}
ACTCTX_CONTROL = 'research/wine-parity-window-actctx-resolved-20261104T184825495007Z-results.json'
CONTROLS = {
    'baseline-20261104T184644956794Z': '59c72d50815fd769d63a36adb09bdec581d32b40ee6f9446312adb0795eb7ad0',
    'off-20261104T184658647235Z': 'f5ffb72b01f4651512754073d80a25901855e46a4ccf2e39ca1974456aa226fa',
    'on-20261104T184709841724Z': '48486a021ba075f680e40144195f2a55c6a8b7d9b025bc9d92a847f888c427fb',
}


def verify():
    registrations = {'research/wine-parity-window-reg-resolved-' + label + '-results.json': digest
                     for label, digest in CONTROLS.items()}
    pins = {**PINS, **registrations, ACTCTX_CONTROL: '2f68940af5bce61a0316fa71bfad510eb7af9f6549d5c304dc322c4eb17ca9b6'}
    for relative, digest in pins.items():
        path = ROOT/relative
        plain(path)
        if sha(path) != digest:
            raise RuntimeError('The tested User32 registration provider or its evidence changed')
    allowed = {'build.json', 'cfx_numeric.h', 'class.c', 'class.o', 'window-registration-probe.exe', 'x86_64-windows'}
    if ({path.name for path in PROVIDER.iterdir()} != allowed
            or {path.name for path in (PROVIDER/'x86_64-windows').iterdir()} != {'user32.dll'}):
        raise RuntimeError('Unexpected file in the isolated User32 provider')
    controls = [json.loads((ROOT/relative).read_text()) for relative in (*registrations, ACTCTX_CONTROL)]
    if any(report['passed'] is not True or report['cleanup'] != [{'flag':'-k','exit':0}, {'flag':'-w','exit':0}]
           for report in controls):
        raise RuntimeError('Require all isolated registration and context controls to pass')
    outputs = [[(row['step'], row['ok'], row['error']) for row in report['runs'][0]['events']] for report in controls[:3]]
    if not outputs[0] == outputs[1] == outputs[2] or not controls[2]['runs'][0]['diagnostics']['events']:
        raise RuntimeError('Require unchanged return values and an active registration trace')
    return {'paths_and_sha256': pins, 'control_outputs': outputs[0], 'changed_wine_module': 'user32.dll'}


def apply(environment):
    proof = verify()
    environment['WINEDLLPATH_PREPEND'] = str(PROVIDER) + os.pathsep + environment['WINEDLLPATH_PREPEND']
    environment['WINEDLLOVERRIDES'] += ';user32=b'
    environment['WINEDEBUG'] += ',+cfxwndreg'
    return proof
