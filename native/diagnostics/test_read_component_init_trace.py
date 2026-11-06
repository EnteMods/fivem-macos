import importlib.util
import io
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    'init_trace', Path(__file__).with_name('read_component_init_trace.py')
)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def row(seq, event, component=1, ordinal=0, call=0, value=1, pid=100, tid=10):
    return dict(zip(reader.KEYS, (seq, event, pid, tid, component, ordinal, call, value)))


def line(record):
    return reader.MARKER + ' '.join(
        '{}={}'.format(key, record[key]) for key in reader.KEYS
    ).encode() + b'\n'


class InitializationTraceTests(unittest.TestCase):
    def test_false_return_is_not_auth_failure_or_success(self):
        records = [row(1, 1), row(2, 2, ordinal=1, call=2),
                   row(3, 3, ordinal=1, call=2, value=0), row(4, 4, component=0)]
        process = reader.summarize(records)['processes'][0]
        self.assertTrue(process['observation_complete'])
        self.assertEqual(process['calls'][0]['state'], 'RETURNED')
        self.assertIs(process['calls'][0]['return_value'], False)

    def test_multiple_processes_and_out_of_order_delivery(self):
        records = [row(2, 3, ordinal=1, call=1), row(1, 2, ordinal=1, call=1),
                   row(2, 3, ordinal=1, call=1, value=0, pid=200),
                   row(1, 2, ordinal=1, call=1, pid=200)]
        processes = reader.summarize(records)['processes']
        self.assertIs(processes[0]['calls'][0]['return_value'], True)
        self.assertIs(processes[1]['calls'][0]['return_value'], False)

    def test_thread_mismatch_does_not_create_a_pair(self):
        result = reader.summarize([
            row(1, 2, ordinal=1, call=1), row(2, 3, ordinal=1, call=1, tid=20),
        ])
        self.assertEqual([item['state'] for item in result['processes'][0]['calls']],
                         ['UNKNOWN', 'UNKNOWN'])

    def test_missing_return_and_budget_are_unknown(self):
        result = reader.summarize([
            row(127, 2, ordinal=1, call=127), row(128, 5, component=0),
        ])['processes'][0]
        self.assertTrue(result['budget_exhausted'])
        self.assertFalse(result['observation_complete'])
        self.assertIsNone(result['calls'][0]['return_value'])

    def test_classification_failure_does_not_imply_absence(self):
        result = reader.summarize([row(1, 6, component=0), row(2, 4, component=0, value=0)])
        process = result['processes'][0]
        self.assertTrue(process['classification_failed'])
        self.assertFalse(process['observation_complete'])
        self.assertEqual(process['component_observations'], [])

    def test_conflicting_sequence_keeps_result_unknown(self):
        result = reader.summarize([
            row(1, 2, ordinal=1, call=1), row(2, 3, ordinal=1, call=1),
            row(2, 3, ordinal=1, call=1, value=0),
        ])['processes'][0]
        self.assertTrue(result['conflicting_sequence'])
        self.assertEqual(result['calls'][0]['state'], 'UNKNOWN')

    def test_shared_seen_mask_is_not_a_per_run_result(self):
        result = reader.summarize([
            row(1, 1), row(2, 4, component=0),
            row(3, 1, component=3), row(4, 4, component=0, value=5),
        ])['processes'][0]
        self.assertEqual([item['cumulative_seen_mask'] for item in result['loop_complete_markers']], [1, 5])
        self.assertNotIn('absent', result)

    def test_only_fixed_fields_survive_wine_wrapper(self):
        record = row(1, 1)
        wrapped = b'0014:warn:debugstr:OutputDebugStringA "' + line(record).rstrip(b'\n') + b'\\n"\n'
        self.assertEqual(reader.parse_debug_line(wrapped), record)
        injected = line(record).rstrip(b'\n') + b' ticket=PRIVATE_VALUE\n'
        self.assertIsNone(reader.parse_debug_line(injected))
        summary = reader.read_stream(io.BytesIO(wrapped + injected))
        self.assertEqual(summary['malformed_marker_rows'], 1)
        self.assertNotIn('PRIVATE_VALUE', json.dumps(summary))

    def test_partial_long_lines_and_reader_limit(self):
        stream = io.BytesIO(b'x' * 9000 + b'\n' + line(row(1, 1)) + line(row(2, 4, component=0)))
        summary = reader.read_stream(stream, max_records=1)
        self.assertEqual(summary['dropped_marker_rows'], 1)
        self.assertFalse(summary['processes'][0]['observation_complete'])
        summary = reader.read_stream(io.BytesIO(line(row(1, 1)).rstrip(b'\n')))
        self.assertEqual(summary['malformed_marker_rows'], 1)
        self.assertEqual(summary['processes'], [])

    def test_bad_marker_fields_are_rejected(self):
        for bad in [row(128, 1), row(1, 2, ordinal=1, call=2),
                    row(1, 3, ordinal=1, call=1), row(1, 1, pid=0),
                    row(1, 4, component=0, value=64)]:
            self.assertIsNone(reader.parse_debug_line(line(bad)))
        record = row(1, 1)
        record['value'] = True
        with self.assertRaises(ValueError):
            reader.summarize([record])


if __name__ == '__main__':
    unittest.main()
