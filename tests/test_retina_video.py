from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'native/windows-client'))
import retina_video as video


ORIGINAL = (b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?>\r\n<Settings>\r\n'
            b'  <graphics><ScreenWidth value="72" /></graphics>\r\n'
            b'  <!-- <video><ScreenWidth value="1"/></video> -->\r\n'
            b'  <video>\r\n    <ScreenHeight value=\'982\'/>\r\n    <ScreenWidth\t value = "1512" />\r\n'
            b'    <Windowed value="1" />\r\n    <RefreshRate value="60" />\r\n  </video>\r\n'
            b'  <text>caf\xc3\xa9</text>\r\n</Settings>\r\n')
APPLIED = ORIGINAL.replace(b"'982'", b"'1964'").replace(b'"1512"', b'"3024"')


class RetinaVideoTests(unittest.TestCase):
    def test_exact_byte_transform_and_round_trip(self):
        original = video.parse(ORIGINAL)
        self.assertEqual(original, video.VideoState(1512, 982, 1))
        self.assertEqual(video.transform(ORIGINAL, 3024, 1964), APPLIED)
        self.assertEqual(video.transform(ORIGINAL, 1512, 982), ORIGINAL)
        applied = video.parse(APPLIED)
        self.assertEqual(applied, video.VideoState(3024, 1964, 1))
        self.assertEqual(video.restore(APPLIED, original, applied), ORIGINAL)
        self.assertEqual(video.restore(ORIGINAL, original, applied), ORIGINAL)

    def test_restore_preserves_unrelated_later_edits(self):
        def later(data):
            return data.replace(b'value="60"', b'value="120"').replace(b'<graphics>', b'<graphics>\n')

        self.assertEqual(video.restore(later(APPLIED), video.parse(ORIGINAL), video.parse(APPLIED)), later(ORIGINAL))

    def test_requires_windowed_mode_and_refuses_partial_or_conflicting_restore(self):
        original, applied = video.parse(ORIGINAL), video.parse(APPLIED)
        for mode in (b'0', b'2'):
            changed = ORIGINAL.replace(b'<Windowed value="1"', b'<Windowed value="' + mode + b'"')
            self.assertEqual(video.parse(changed).windowed, int(mode))
            with self.assertRaises(ValueError):
                video.transform(changed, 3024, 1964)
        for changed in (APPLIED.replace(b'"3024"', b'"1512"'), APPLIED.replace(b"'1964'", b"'1080'"),
                        APPLIED.replace(b'<Windowed value="1"', b'<Windowed value="2"')):
            with self.assertRaises(ValueError):
                video.restore(changed, original, applied)

    def test_refuses_duplicate_ambiguous_or_nonliteral_values(self):
        for extra in (b'<ScreenWidth value="1512"/>', b'<Windowed value="1"/>'):
            with self.assertRaises(ValueError):
                video.parse(ORIGINAL.replace(b'</video>\r\n', extra + b'</video>\r\n'))
        with self.assertRaises(ValueError):
            video.parse(ORIGINAL.replace(b'</Settings>', b'<video/></Settings>'))
        for field in (b'<ScreenWidth value="01512"/>', b'<ScreenWidth value="&#49;512"/>',
                      b'<ScreenWidth value="1512" value="1512"/>', b'<ScreenWidth value="1512">1</ScreenWidth>'):
            with self.assertRaises(ValueError):
                video.parse(ORIGINAL.replace(b'<ScreenWidth\t value = "1512" />', field))

    def test_refuses_doctype_malformed_xml_and_invalid_size(self):
        for data in (ORIGINAL.replace(b'<Settings>', b'<!DOCTYPE Settings SYSTEM "file:///unused"><Settings>'),
                     ORIGINAL.replace(b'</Settings>', b'</Unclosed>'), b' ' * (256 * 1024 + 1)):
            with self.assertRaises(ValueError):
                video.parse(data)
        for extent in (0, -1, True, 16385, '3024'):
            with self.assertRaises(ValueError):
                video.transform(ORIGINAL, extent, 1964)


if __name__ == '__main__':
    unittest.main()
