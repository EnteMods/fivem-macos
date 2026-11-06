import io
import unittest
from read_auth_trace import parse_event, summarize


class AuthTraceTests(unittest.TestCase):
    def test_all_original_fixed_observations(self):
        rows = (
            'after_create_notification=1 handler_present=0',
            'idle_status_query=1 handler_present=0',
            'attempt=1 handler_present=1', 'attempt=1 dispatch_return=0',
            'attempt=1 callback=1 success=1 additional_cfxTicket2_present=0',
            'attempt=1 perform_request=1',
        )
        data = ''.join('[1] [b3889_GameProc] MainThrd/ [cfx-auth-trace] ' + row + '\n' for row in rows).encode()
        result = summarize(io.BytesIO(data))
        self.assertEqual(len(result['records']), 6)
        self.assertEqual(result['records'][0], {'phase': 'after_create_notification', 'handler_present': 0})
        self.assertEqual(result['records'][1], {'phase': 'idle_status_query', 'handler_present': 0})
        self.assertEqual(result['records'][4]['additional_cfxTicket2_present'], 0)
        self.assertFalse(result['url_token_or_payload_values_exported'])

    def test_rejects_extra_values_unknown_fields_and_bad_booleans(self):
        for message in ('attempt=1 handler_present=0 token=fixture-sensitive',
                        'attempt=1 handler_present=2', 'attempt=4294967296 perform_request=1',
                        'url=https://fixture.invalid/', 'attempt=1 post_cfxTicket2_present=1'):
            self.assertIsNone(parse_event('[cfx-auth-trace] ' + message))

    def test_output_never_contains_unrelated_or_malformed_values(self):
        data = b'fixture-secret\n[cfx-auth-trace] attempt=1 handler_present=0 token=fixture-secret\n'
        result = summarize(io.BytesIO(data))
        self.assertEqual(result['records'], [])
        self.assertEqual(result['malformed_marker_rows'], 1)
        self.assertNotIn('fixture-secret', str(result))

    def test_oversized_lines_cannot_inject_tail_events(self):
        data = b'x' * 8192 + b'[cfx-auth-trace] attempt=1 perform_request=1\n'
        result = summarize(io.BytesIO(data))
        self.assertEqual(result['records'], [])

    def test_reader_bounds_and_flags_output_without_inventing_missing_events(self):
        row = b'[cfx-auth-trace] attempt=1 perform_request=1\n'
        result = summarize(io.BytesIO(row * 520))
        self.assertEqual(len(result['records']), 512)
        self.assertEqual(result['reader_dropped_records'], 8)
        self.assertTrue(result['source_output_limit_may_have_been_reached'])


if __name__ == '__main__':
    unittest.main()
