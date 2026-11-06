from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from windows_core_loader import classify_loader


FAULT = '\n'.join((
    '0020:0024:trace:loaddll:build_ntdll_module Loaded L"C:\\windows\\ntdll.dll" at 00006FFFFFF30000: builtin',
    '0020:0024:trace:loaddll:build_module Loaded L"Z:\\fixture\\CoreRT.dll" at 00006FFFFF0D0000: native',
    'OWN_LOADER_BEFORE_INIT',
    '0020:0024:trace:seh:dispatch_exception code=c0000005 (EXCEPTION_ACCESS_VIOLATION) flags=0 addr=00006FFFFF0EC471',
    '0020:0024:trace:seh:dispatch_exception  info[0]=0000000000000001',
    '0020:0024:trace:seh:dispatch_exception  info[1]=00006FFFFFF318D8',
))


class WindowsCoreLoaderTests(unittest.TestCase):
    def test_known_fault_requires_exact_image_relative_addresses_and_write(self):
        self.assertEqual(classify_loader(FAULT, 5), 'known_loader_write_fault')
        for expected, replacement in (('F0EC471', 'F0EC472'), ('FF318D8', 'FF318D9'),
                                      ('info[0]=0000000000000001', 'info[0]=0000000000000000'),
                                      ('0020:0024:trace:loaddll:build_ntdll', '00d0:0024:trace:loaddll:build_ntdll')):
            with self.subTest(replacement=replacement):
                self.assertEqual(classify_loader(FAULT.replace(expected, replacement), 5), 'fixture_failed')

    def test_success_requires_exact_fixture_marker_and_exit(self):
        self.assertEqual(classify_loader('OWN_LOADER_COMPONENT_LOADED\n', 0), 'loaded')
        self.assertEqual(classify_loader('OWN_LOADER_COMPONENT_LOADED\n', 5), 'fixture_failed')
        self.assertEqual(classify_loader('OWN_LOADER_BEFORE_INIT\n', None), 'timeout')
