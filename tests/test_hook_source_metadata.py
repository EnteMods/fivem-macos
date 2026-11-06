"""Fixed-field source-client diagnostic parsing; no runtime or user-data access."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'native/windows-client'))
import run_source


class HookSourceMetadataTests(unittest.TestCase):
    def test_both_diagnostic_versions_enable_the_normal_debugstr_channel(self):
        self.assertEqual(run_source.diagnostic_winedebug(4), '+loaddll,+seh')
        for version in (5, 6, 7):
            self.assertEqual(run_source.diagnostic_winedebug(version), '+loaddll,+seh,+debugstr')
            self.assertEqual(run_source.diagnostic_winedebug(version, True), '+loaddll,+seh,+debugstr,+process')

    def test_fixed_status_fields_are_accepted_and_unknown_payloads_are_rejected(self):
        line = '00d0:warn:debugstr:OutputDebugStringA "[CFX_MAPPING_HOOK] pid=204 phase=create.ntdll.NtOpenFile status=0\\n"\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'own.log'
            path.write_text(line + line.replace('debugstr:OutputDebugStringA', 'seh:dispatch_exception')
                            + line.replace('NtOpenFile', 'PRIVATE')
                            + line.replace('status=0', 'status=13')
                            + line.replace('status=0', 'status=0 path=PRIVATE')
                            + 'arbitrary private content\n')
            expected = {'pid': 204, 'phase': 'create.ntdll.NtOpenFile', 'status': 0}
            self.assertEqual(run_source.hook_metadata(path), [expected, expected])

    def test_file_policy_parser_only_accepts_fixed_operations_and_bits(self):
        line = '00d0:warn:debugstr:OutputDebugStringA "[CFX_MAPPING_FILE] pid=204 operation=open allowed=0 canonical_fragment=0 folded_fragment=1 nt_prefix=1\\n"\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'own.log'
            path.write_text(line + line.replace('debugstr:OutputDebugStringA', 'seh:dispatch_exception')
                            + line.replace('operation=open', 'operation=PRIVATE')
                            + line.replace('allowed=0', 'allowed=2')
                            + line.replace('nt_prefix=1', 'nt_prefix=1 path=PRIVATE'))
            expected = {'pid': 204, 'operation': 'open', 'allowed': 0,
                        'canonical_fragment': 0, 'folded_fragment': 1, 'nt_prefix': 1}
            self.assertEqual(run_source.file_policy_metadata(path), [expected, expected])


if __name__ == '__main__':
    unittest.main()
