"""Pure filtering and own OS-pipe checks; no Wine, prefixes or child programs."""
import importlib.util
import io
import json
import os
from pathlib import Path
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_exit_relay', ROOT / 'native/diagnostics/exit_relay.py')
relay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relay)


def call(api='kernel32.ExitProcess', status='00000000', handle='ffffffffffffffff', pid='0030', tid='0034'):
    args = handle + ',' + status if api == 'ntdll.NtTerminateProcess' else status
    return f'{pid}:{tid}:Call {api}({args}) ret=0000000180123456\n'.encode()


class ExitRelayTests(unittest.TestCase):
    def test_configuration_has_only_fixed_own_or_explicit_source_selector(self):
        self.assertEqual(relay.RELAY_INCLUDE,
                         'kernel32.ExitProcess;ntdll.RtlExitUserProcess;ntdll.NtTerminateProcess')
        self.assertEqual(relay.relay_debug(), '-all,+pid,named_pipe_probe.exe:trace+relay')
        self.assertEqual(relay.relay_debug('NAMED_PIPE_PROBE.EXE'), relay.relay_debug())
        for name in ('named_pipe_probe', 'FiveM_ROSLauncher', 'FiveM_ROSLauncher.exe', 'evil:trace+all', '/tmp/own'):
            with self.assertRaises(ValueError):
                relay.relay_debug(name)
        self.assertTrue(relay.source_selector_candidate('fivem_roslauncher'))
        self.assertFalse(relay.source_selector_candidate('FiveM_ROSLauncher.exe'))
        self.assertEqual(relay.relay_debug('FiveM_ROSLauncher', source_authorized=True),
                         '-all,+pid,FiveM_ROSLauncher:trace+relay')

    def test_three_calls_keep_only_numeric_exit_fields_and_never_handle(self):
        stream = relay.RelayFilter()
        rows = stream.feed(call() + call('ntdll.RtlExitUserProcess', '00000011')
                           + call('ntdll.NtTerminateProcess', 'ffffffffc0000005', '123456789abcdef0'))
        self.assertEqual([row['api'] for row in rows], ['ExitProcess', 'RtlExitUserProcess', 'NtTerminateProcess'])
        self.assertEqual([row['status'] for row in rows], [0, 17, 0xc0000005])
        for row in rows:
            self.assertEqual(set(row), {'kind', 'api', 'pid', 'tid', 'status', 'caller_address'})
            self.assertEqual((row['kind'], row['pid'], row['tid'], row['caller_address']),
                             ('exit_api_call', 48, 52, 0x180123456))
        self.assertNotIn('123456789abcdef0', json.dumps(rows))
        self.assertFalse(stream.finish()['exit_cause_established'])

    def test_module_case_varies_but_function_case_stays_exact_and_nt_handle_is_discarded(self):
        raw = [call().replace(b'kernel32.', b'KERNEL32.'),
               call('ntdll.RtlExitUserProcess', '00000011').replace(b'ntdll.', b'NtDlL.'),
               call('ntdll.NtTerminateProcess', 'ffffffffc0000005', '89abcdef12345678')
                   .replace(b'ntdll.', b'NTDLL.')]
        stream = relay.RelayFilter()
        rows = stream.feed(b''.join(raw))
        self.assertEqual([row['api'] for row in rows], ['ExitProcess', 'RtlExitUserProcess', 'NtTerminateProcess'])
        self.assertEqual([row['status'] for row in rows], [0, 17, 0xc0000005])
        self.assertTrue(all(set(row) == {'kind', 'api', 'pid', 'tid', 'status', 'caller_address'} for row in rows))
        self.assertNotIn('89abcdef12345678', json.dumps(rows))
        self.assertNotIn(str(0x89abcdef12345678), json.dumps(rows))
        self.assertEqual(stream.finish()['accepted_records'], 3)
        wrong = [raw[0].replace(b'.ExitProcess', b'.exitProcess'),
                 raw[1].replace(b'.RtlExitUserProcess', b'.RTLEXITUSERPROCESS'),
                 raw[2].replace(b'.NtTerminateProcess', b'.ntTerminateProcess')]
        rejected = relay.RelayFilter()
        self.assertEqual(rejected.feed(b''.join(wrong)), [])
        self.assertEqual(rejected.finish()['rejected_candidate_lines'], 3)

    def test_every_byte_boundary_preserves_complete_records(self):
        raw = call('ntdll.NtTerminateProcess', '00000011')
        expected = relay.RelayFilter().feed(raw)
        for boundary in range(len(raw) + 1):
            stream = relay.RelayFilter()
            self.assertEqual(stream.feed(raw[:boundary]) + stream.feed(raw[boundary:]), expected)
            self.assertEqual(stream.finish()['discarded_partial_lines'], 0)
        stream = relay.RelayFilter()
        self.assertEqual([record for byte in raw for record in stream.feed(bytes([byte]))], expected)

    def test_other_calls_tls_callbacks_and_return_lines_are_not_persisted(self):
        stream = relay.RelayFilter()
        rows = stream.feed(b'0030:0034:Call wininet.HttpSendRequestW(PRIVATE_TICKET) ret=1234\n'
                           b'0030:0034:Call TLS callback (proc=1234,context=PRIVATE)\n'
                           b'0030:0034:Ret  ntdll.NtTerminateProcess() retval=00000000 ret=180123456\n'
                           b'0030:0034:trace:relay:load_list L"RelayInclude" = L"kernel32.ExitProcess"\n')
        self.assertEqual(rows, [])
        summary = stream.finish()
        self.assertEqual(summary['discarded_other_lines'], 4)
        self.assertEqual(summary['rejected_candidate_lines'], 0)
        self.assertNotIn('PRIVATE', json.dumps(summary))

    def test_malformed_selected_calls_fail_closed(self):
        invalid = [call(pid='0000'), call(tid='100000000'), call().replace(b'ret=0000000180123456', b'ret=0'),
                   call().replace(b'(00000000)', b'(0,1)'),
                   call('ntdll.NtTerminateProcess').replace(b'(ffffffffffffffff,00000000)', b'(00000000)'),
                   call().replace(b'00000000)', b'PRIVATE)'), call().replace(b'\n', b' EXTRA\n'),
                   b'0034:Call kernel32.ExitProcess(0) ret=180123456\n',
                   b'0030:0034:Call kernel32.ExitProcess(0) ret=10000000000000000\n']
        for raw in invalid:
            stream = relay.RelayFilter()
            self.assertEqual(stream.feed(raw), [])
            self.assertEqual(stream.finish()['rejected_candidate_lines'], 1)

    def test_oversized_partial_and_limited_streams_are_explicitly_incomplete(self):
        stream = relay.RelayFilter()
        self.assertEqual(stream.feed(b'PRIVATE' * 1000), [])
        self.assertLessEqual(len(stream.pending), relay.MAX_LINE_BYTES)
        rows = stream.feed(b'\n' + call() + b'PRIVATE_PARTIAL')
        self.assertEqual(len(rows), 1)
        summary = stream.finish()
        self.assertEqual((summary['oversized_lines'], summary['discarded_partial_lines']), (1, 1))
        self.assertNotIn('PRIVATE', json.dumps(summary))
        self.assertEqual(stream.finish(), summary)
        with self.assertRaises(ValueError):
            stream.feed(b'')
        stream = relay.RelayFilter()
        self.assertEqual(len(stream.feed(call() * (relay.MAX_RECORDS + 1))), relay.MAX_RECORDS)
        self.assertTrue(stream.finish()['record_limit_reached'])

    def test_pump_persists_only_safe_records_until_eof(self):
        reader, writer = os.pipe()
        try:
            os.write(writer, call() + b'PRIVATE_AUTH_PAYLOAD\n' + call('ntdll.NtTerminateProcess', '11'))
            os.close(writer)
            writer = None
            sink = io.BytesIO()
            summary = relay.pump(reader, sink, stop_event=threading.Event(), timeout_seconds=1)
            self.assertEqual(summary['termination_reason'], 'eof')
            self.assertEqual(summary['accepted_records'], 2)
            self.assertTrue(os.get_blocking(reader))
            rows = [json.loads(row) for row in sink.getvalue().splitlines()]
            self.assertEqual([row['status'] for row in rows], [0, 17])
            self.assertNotIn(b'PRIVATE', sink.getvalue())
        finally:
            os.close(reader)
            if writer is not None:
                os.close(writer)

    def test_open_inherited_writer_does_not_hold_stop_or_timeout(self):
        for stop_now in (True, False):
            reader, writer = os.pipe()
            try:
                os.write(writer, call('ntdll.RtlExitUserProcess', '11'))
                stop = threading.Event()
                if stop_now:
                    stop.set()
                sink = io.BytesIO()
                start = time.monotonic()
                summary = relay.pump(reader, sink, stop_event=stop, timeout_seconds=0.04)
                self.assertLess(time.monotonic() - start, 1)
                self.assertEqual(summary['termination_reason'], 'stop' if stop_now else 'timeout')
                self.assertFalse(summary['eof_observed'])
                self.assertEqual(summary['accepted_records'], 1)
                os.write(writer, b'still-owned-and-open')
            finally:
                os.close(reader)
                os.close(writer)

    def test_active_writer_cannot_prevent_finite_thread_stop(self):
        reader, writer = os.pipe()
        os.set_blocking(writer, False)
        stop = threading.Event()
        writer_stop = threading.Event()
        sink = io.BytesIO()
        result = []
        def keepalive():
            while not writer_stop.is_set():
                try:
                    os.write(writer, b'PRIVATE_KEEPALIVE\n')
                except BlockingIOError:
                    writer_stop.wait(0.001)
        def capture():
            result.append(relay.pump(reader, sink, stop_event=stop, timeout_seconds=1))
        producer = threading.Thread(target=keepalive)
        consumer = threading.Thread(target=capture)
        producer.start()
        consumer.start()
        try:
            time.sleep(0.02)
            stop.set()
            consumer.join(1)
            self.assertFalse(consumer.is_alive())
            self.assertEqual(result[0]['termination_reason'], 'stop')
            self.assertEqual(sink.getvalue(), b'')
        finally:
            stop.set()
            writer_stop.set()
            producer.join(1)
            consumer.join(1)
            os.close(reader)
            os.close(writer)


if __name__ == '__main__':
    unittest.main()
