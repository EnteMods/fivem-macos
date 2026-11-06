"""Source-controller environment isolation without starting a process or prefix."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'native/windows-client'))
import run_source


class SourceRuntimeEnvironmentTests(unittest.TestCase):
    def test_server_and_prefix_are_rebound_and_foreign_loader_controls_removed(self):
        original = dict(WINEPREFIX='foreign', WINESERVER='foreign-server', WINESERVERSOCKET='foreign-socket',
                        WINELOADER='foreign-loader', WINELOADERNOEXEC='1', PATH='own-path')
        runtime = SimpleNamespace(ENGINE=Path('/own/engine'), environment=lambda: original)
        result = run_source.source_runtime_environment(runtime, 7)
        self.assertIsNot(result, original)
        self.assertEqual(original['WINESERVER'], 'foreign-server')
        self.assertEqual(result['WINEPREFIX'], str(run_source.PREFIX))
        self.assertEqual(result['WINESERVER'], '/own/engine/bin/wineserver')
        self.assertEqual(result['PATH'], 'own-path')
        self.assertEqual(result['CitizenFX_NoTenUI'], '1')
        self.assertEqual(result['WINEDEBUG'], '+loaddll,+seh,+debugstr')
        self.assertFalse({'WINESERVERSOCKET', 'WINELOADER', 'WINELOADERNOEXEC'} & result.keys())

    def test_inherited_client_roles_are_rejected_even_when_empty_or_mixed_case(self):
        for key in ('CitizenFX_NoTenUI', 'citizenfx_tool_mode', 'CITIZENFX_OWN_ROLE'):
            with self.subTest(key=key):
                original = {key: ''}
                runtime = SimpleNamespace(ENGINE=Path('/own/engine'), environment=lambda: original)
                with self.assertRaises(RuntimeError):
                    run_source.source_runtime_environment(runtime, 7)


if __name__ == '__main__':
    unittest.main()
