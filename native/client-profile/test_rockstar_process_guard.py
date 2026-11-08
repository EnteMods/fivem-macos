"""The native wrapper must not block normal Rockstar recovery after a crash."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_rockstar_current as launcher


class ProcessGuard(unittest.TestCase):
    def check(self, rows):
        with patch.object(launcher.subprocess, 'run', return_value=SimpleNamespace(stdout=rows)):
            return launcher.no_related_processes()

    def test_idle_native_wrapper_allows_recovery(self):
        self.assertTrue(self.check('/Users/example/Applications/FiveM.app/Contents/MacOS/FiveMLauncher\n/usr/bin/python3\n'))

    def test_windows_client_still_blocks_recovery(self):
        self.assertFalse(self.check('C:\\source-update-game-client\\FiveM.exe\n'))

    def test_wine_and_rockstar_still_block_recovery(self):
        for command in ['/runtime/bin/wineserver', 'C:\\Program Files\\Rockstar Games\\Launcher\\Launcher.exe']:
            with self.subTest(command=command):
                self.assertFalse(self.check(command + '\n'))


if __name__ == '__main__':
    unittest.main()
