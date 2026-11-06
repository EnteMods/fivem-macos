import unittest
import read_lifecycle_trace as reader


class LifecycleTests(unittest.TestCase):
    def line(self, component=b'sticky', phase=b'callback.after', suffix=b''):
        return (b'00ac:trace:debugstr:OutputDebugStringA "[CFX_SOURCE_COMPONENT] pid=12 tid=16 '
                b'phase=citigame.pre-resume.' + phase + b' component=' + component + suffix + b'\\n"\n')

    def test_existing_wine_format_numeric_projection(self):
        self.assertEqual(reader.parse_debug_line(self.line()), dict(pid=12, tid=16, phase=5, component=1))

    def test_unselected_and_free_text_not_exported(self):
        self.assertIsNone(reader.parse_debug_line(self.line(component=b'other-component')))
        self.assertIsNone(reader.parse_debug_line(self.line(suffix=b' token=private')))
        self.assertIsNone(reader.parse_debug_line(self.line(phase=b'unknown')))

    def test_invalid_pid_duplicate_and_size(self):
        self.assertIsNone(reader.parse_debug_line(self.line().replace(b'pid=12', b'pid=0')))
        self.assertIsNone(reader.parse_debug_line(self.line() + self.line()))
        self.assertIsNone(reader.parse_debug_line(b'x' * 4097 + self.line()))

    def test_complete_branch_and_incomplete_calls(self):
        rows = [dict(pid=12, tid=16, phase=p, component=1) for p in range(1, 7)]
        self.assertEqual(reader.summarize(rows)['groups'][0]['state'], 'CALLBACK_RETURNED')
        self.assertEqual(reader.summarize(rows[:4])['groups'][0]['state'], 'UNKNOWN')
        self.assertEqual(reader.summarize([rows[i] for i in (0, 1, 2, 5)])['groups'][0]['state'], 'NO_CALLBACK_BRANCH')

    def test_process_thread_and_repeat_not_conflated(self):
        rows = [dict(pid=12, tid=16, phase=p, component=1) for p in range(1, 7)]
        extra = [{**row, 'tid': 20} for row in rows]
        self.assertEqual(len(reader.summarize(rows + extra)['groups']), 2)
        self.assertEqual(reader.summarize(rows + rows)['groups'][0]['state'], 'UNKNOWN')

    def test_schema_does_not_accept_extra_values(self):
        with self.assertRaises(ValueError):
            reader.summarize([dict(pid=12, tid=16, phase=1, component=1, payload='private')])


if __name__ == '__main__':
    unittest.main()
