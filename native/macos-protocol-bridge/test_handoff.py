import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('handoff_contract', Path(__file__).with_name('handoff.py'))
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)


class UriContractTests(unittest.TestCase):
    def test_preserves_normal_opaque_return(self):
        for value in (b'fivem://accept-auth?payload=fixture%2Bdata%3D',
                      b'fivem://accept-auth?payload=fixture'):
            self.assertTrue(handoff.valid_uri(value))

    def test_rejects_wrong_route_and_ambiguous_input(self):
        for value in (b'', b'https://accept-auth?payload=x', b'fivem://connect/x?payload=x',
                      b'fivem://user@accept-auth?payload=x', b'fivem://accept-auth:80?payload=x',
                      b'fivem://accept-auth/path?payload=x', b'fivem://accept-auth?payload=x#fragment',
                      b'fivem://accept-auth/?payload=x', b'fivem://accept-auth?payload=%ZZ',
                      b'fivem://accept-auth?payload=', b'fivem://accept-auth?other=x',
                      b'fivem://accept-auth?payload=x&payload=y',
                      b'fivem://accept-auth?payload=x&other=y', b'fivem://accept-auth?payload=x\n',
                      b'fivem://accept-auth?payload=' + b'x' * 4096,
                      b'fivem://accept-auth?payload=\x00', b'\xff', b'x' * (handoff.MAX_BYTES + 1)):
            with self.subTest(value_length=len(value)):
                self.assertFalse(handoff.valid_uri(value))

    def test_invalid_uri_never_loads_or_launches_candidate(self):
        with patch.object(handoff, 'load_candidate') as load:
            self.assertEqual(handoff.dispatch(b'fivem://connect/fixture'), 2)
            load.assert_not_called()

    def test_inactive_client_does_not_launch(self):
        with patch.object(handoff, 'load_candidate'), patch.object(handoff, 'active_candidate', return_value=False), \
                patch.object(handoff.subprocess, 'Popen') as launch:
            self.assertEqual(handoff.dispatch(b'fivem://accept-auth?payload=fixture'), 3)
            launch.assert_not_called()

    def test_exception_does_not_expose_argument_or_payload(self):
        output = io.StringIO()
        with patch.object(handoff.sys, 'argv', ['handoff.py', '--check']), \
                patch.object(handoff, 'load_candidate', side_effect=ValueError('fixture-sensitive-value')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(handoff.main(), 4)
        self.assertEqual(output.getvalue(), 'CFX_PROTOCOL_HANDOFF code=4\n')

    def test_only_client_processes_admit_normal_handoff(self):
        for name in (r'C:\source-update-game-client\FiveM.exe',
                     r'C:\source-update-game-client\data\cache\subprocess\FiveM_b3889_GameProcess.exe'):
            self.assertIsNotNone(handoff.GAME_PROCESS.fullmatch(name))
        for name in (r'C:\source-update-game-client\data\cache\subprocess\FiveM_DumpServer',
                     r'C:\unrelated\FiveM.exe', 'python3'):
            self.assertIsNone(handoff.GAME_PROCESS.fullmatch(name))


if __name__ == '__main__':
    unittest.main()
