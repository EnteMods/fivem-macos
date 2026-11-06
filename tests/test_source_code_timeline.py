import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "native/diagnostics/source_code_timeline.py"
SPEC = importlib.util.spec_from_file_location("source_code_timeline", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CodeTimelineTests(unittest.TestCase):
    def test_known_code_load_discards_directory(self):
        events = MODULE.extract(['0100:trace:loaddll:build_module Loaded L"C:\\\\private\\\\socialclub.dll" at 123abc: native\n'])
        self.assertEqual(events, [{"line": 1, "wine_thread_hex": "0100", "kind": "code_load",
                                   "basename": "socialclub.dll", "provider": "native",
                                   "code_location_class": "other-code-location-not-retained"}])
        self.assertNotIn("private", str(events))

    def test_unlisted_names_and_partial_or_multiline_payloads_are_rejected(self):
        lines = ['0100:trace:loaddll:build_module Loaded L"C:\\token.dll" at 123abc: native\n',
                 '0100:trace:loaddll:build_module Loaded L"C:\\socialclub.dll" at 123abc: native credentials\n',
                 '0100:trace:loaddll:build_module Loaded L"C:\\socialclub.dll\nsecret" at 123abc: native\n',
                 '0100:trace:loaddll:build_module Loaded L"C:\\notsocialclub.dll" at 123abc: native\n']
        self.assertEqual(MODULE.extract(lines), [])

    def test_location_class_requires_the_exact_code_path(self):
        installed = 'C:\\\\Program Files\\\\Rockstar Games\\\\Social Club\\\\socialclub.dll'
        staged = 'Z:' + str(MODULE.ROOT / 'build/windows-source-integration/data/game-storage/ros_2090/socialclub.dll')
        self.assertEqual(MODULE.code_location(installed, 'socialclub.dll'), 'source-rockstar-installed')
        self.assertEqual(MODULE.code_location(staged, 'socialclub.dll'), 'source-staged-ros2090')
        for path in (installed + '.other', 'C:/private/socialclub.dll', 'C:/Program Files/Rockstar Games/Social Club/other/socialclub.dll'):
            self.assertEqual(MODULE.code_location(path, 'socialclub.dll'), 'other-code-location-not-retained')

    def test_mapping_accepts_only_complete_fixed_setup_payload(self):
        good = '0100:warn:debugstr:OutputDebugStringA "[CFX_MAPPING] pid=96 phase=setup.complete provider_set=1 provider_called=0 return_changed=0\\n"\n'
        event = MODULE.extract([good])[0]
        self.assertEqual((event['kind'], event['pid'], event['phase']), ('mapping_setup', 96, 'setup.complete'))
        self.assertEqual(MODULE.extract([good.replace('provider_set=1', 'provider_set=token'), good.replace('setup.complete', 'other'), good.rstrip() + ' extra']), [])

    def test_exact_label_is_confined(self):
        self.assertTrue(MODULE.LABEL.fullmatch('client-source-ui-resume-20261102T100748214002Z'))
        for label in ('../logs/private', 'client-source-ui-resume-20261102T100748214002Z/../private', 'client-source-ui-resume-20261102T100748214002Z\n'):
            self.assertIsNone(MODULE.LABEL.fullmatch(label))


if __name__ == '__main__':
    unittest.main()
