"""Own OS pipes and inert output doubles; no client, Wine or profile access."""
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'native/windows-client'))
from window_creation_stream import MAX_LINE_BYTES, WindowCreationStream
from window_creation_trace import Collector


class Output:
    def __init__(self, failure=None):
        self.text, self.closed, self.flushed, self.failure = '', False, False, failure

    def write(self, line):
        if self.failure == 'write': raise OSError('PRIVATE_WRITE_ERROR_TITLE')
        if self.closed: raise ValueError('closed output')
        self.text += line

    def flush(self):
        self.flushed = True
        if self.failure == 'flush': raise OSError('PRIVATE_FLUSH_ERROR_TITLE')

    def close(self):
        self.closed = True


class WindowCreationStreamTests(unittest.TestCase):
    def start(self, output=None, collector=None):
        read_fd, write_fd = os.pipe()
        pipe = os.fdopen(read_fd, 'rb', buffering=0)
        self.addCleanup(lambda: pipe.close() if not pipe.closed else None)
        self.addCleanup(lambda: self.close_fd(write_fd))
        output = output or Output()
        stream = WindowCreationStream(collector or Collector())
        stream.attach(SimpleNamespace(stdout=pipe), output)
        return stream, output, write_fd

    @staticmethod
    def close_fd(fd):
        try: os.close(fd)
        except OSError: pass

    def feed(self, data, **kwargs):
        stream, output, fd = self.start(**kwargs)
        os.write(fd, data)
        os.close(fd)
        stream.finish_after_wineserver_cleanup()
        return stream, output

    def test_win_titles_never_persist_but_numeric_events_and_baseline_lines_remain(self):
        baseline = '0024:trace:loaddll:build_module OWN_BASELINE\n'
        data = (baseline + '0020:0024:trace:win:NtUserCreateWindowEx created window 0x1234\n'
            + '0020:0024:trace:win:NtUserCreateWindowEx PRIVATE_WINDOW_TITLE\n'
            + 'bad:prefix:warn:win:unknown PRIVATE_WINDOW_TITLE\n').encode()
        stream, output = self.feed(data)
        result = stream.result()
        self.assertEqual(output.text, baseline)
        self.assertTrue(output.closed and output.flushed)
        self.assertNotIn('PRIVATE_WINDOW_TITLE', repr(result))
        self.assertEqual(result['numeric_window_trace']['accepted_events'], 1)
        self.assertEqual(result['stream_stats']['dropped_win_lines'], 3)
        self.assertTrue(result['capture_complete'])
        stream.finish_after_wineserver_cleanup()

    def test_stream_rejects_win_passthrough_even_if_collector_is_wrong(self):
        collector = SimpleNamespace(accept=lambda *a, **k: 'passthrough', summary=lambda: {})
        stream, output = self.feed(b'123:TRACE:WIN:any PRIVATE_TITLE\n', collector=collector)
        self.assertEqual(output.text, '')
        self.assertEqual(stream.result()['stream_stats']['dropped_win_lines'], 1)

    def test_oversized_line_dropped_whole_and_next_baseline_line_preserved(self):
        data = b'0024:trace:win:PRIVATE_TITLE' + b'x' * (MAX_LINE_BYTES + 100) + b'\nOWN_BASELINE\n'
        stream, output = self.feed(data)
        self.assertEqual(output.text, 'OWN_BASELINE\n')
        self.assertEqual(stream.result()['stream_stats']['oversized_lines'], 1)
        self.assertFalse(stream.result()['capture_complete'])
        self.assertNotIn('PRIVATE_TITLE', repr(stream.result()))

    def test_collector_cap_below_transport_cap_marks_capture_incomplete(self):
        stream, output = self.feed(b'OWN_BASELINE_' + b'x' * 5000 + b'\n')
        result = stream.result()
        self.assertEqual(output.text, '')
        self.assertEqual(result['stream_stats']['oversized_lines'], 0)
        self.assertEqual(result['numeric_window_trace']['oversized_lines'], 1)
        self.assertFalse(result['capture_complete'])

    def test_unterminated_eof_fragment_is_dropped(self):
        for data in (b'0024:trace:win:PRIVATE_TITLE', b'OWN_UNFINISHED_BASELINE'):
            with self.subTest(data=data):
                stream, output = self.feed(data)
                self.assertEqual(output.text, '')
                self.assertEqual(stream.result()['stream_stats']['incomplete_lines'], 1)
                self.assertFalse(stream.result()['capture_complete'])

    def test_output_is_open_until_explicit_after_cleanup_finish(self):
        stream, output, fd = self.start()
        os.write(fd, b'OWN_BASELINE\n');os.close(fd)
        stream.thread.join(timeout=1)
        self.assertFalse(output.closed)
        self.assertFalse(stream.result()['finished_after_cleanup'])
        stream.finish_after_wineserver_cleanup()
        self.assertTrue(output.closed)
        self.assertTrue(stream.result()['capture_complete'])

    def test_open_writer_cannot_hold_finish_until_eof(self):
        stream, output, _ = self.start()
        stream.finish_after_wineserver_cleanup()
        self.assertTrue(stream.result()['reader_thread_stopped'])
        self.assertFalse(stream.result()['eof_observed'])
        self.assertFalse(stream.result()['capture_complete'])
        self.assertTrue(output.closed)

    def test_writer_and_flush_errors_keep_only_types_and_close_after_cleanup(self):
        for failure in ('write', 'flush'):
            with self.subTest(failure=failure):
                stream, output = self.feed(b'OWN_BASELINE\n', output=Output(failure))
                result = stream.result()
                self.assertEqual(result['error_types'][failure], 'OSError')
                self.assertFalse(result['capture_complete'])
                self.assertNotIn('PRIVATE_', repr(result))
                self.assertTrue(output.closed)

    def test_collector_exception_and_start_exception_never_retain_error_text(self):
        collector = SimpleNamespace(accept=mock.Mock(side_effect=ValueError('PRIVATE_TITLE')), summary=lambda: {})
        stream, output = self.feed(b'0024:trace:win:PRIVATE_TITLE\n', collector=collector)
        self.assertEqual(output.text, '')
        self.assertEqual(stream.result()['error_types']['collector'], 'ValueError')
        self.assertNotIn('PRIVATE_TITLE', repr(stream.result()))
        r, w = os.pipe();self.addCleanup(lambda: self.close_fd(w))
        pipe = os.fdopen(r, 'rb', buffering=0)
        stream, output = WindowCreationStream(Collector()), Output()
        with mock.patch('window_creation_stream.threading.Thread.start', side_effect=RuntimeError('PRIVATE_START')):
            with self.assertRaises(RuntimeError): stream.start(SimpleNamespace(stdout=pipe), output)
        self.assertFalse(output.closed)
        stream.finish_after_wineserver_cleanup()
        self.assertTrue(output.closed and pipe.closed)
        self.assertNotIn('PRIVATE_START', repr(stream.result()))


if __name__ == '__main__':
    unittest.main()
