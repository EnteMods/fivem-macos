"""Fixed wire-schema checks; never start Wine or inspect a target process."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_source_code_records',
    ROOT / 'native/windows-client/code_observer_bridge.py')
schema = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(schema)


class SourceCodeRecordTests(unittest.TestCase):
    def setUp(self):
        self.records = schema.SourceCodeRecords()
        self.ready = dict(event='ready', mode='source', pid=32, duration_ms=600000,
                          rva=0x3203b0, length=64, poll_ms=250, record_limit=20)
        self.module = dict(event='module', time_ms=1, pid=64, creation=123456789012345678,
                           base=0x140000000, size=0x35d0000)
        self.code = dict(event='code', time_ms=2, pid=64, creation=self.module['creation'],
                         sample=1, rva=0x3203b0, length=64, hex='90' * 64)

    def accept(self, row):
        return self.records.accept(json.dumps(row))

    def begin(self):
        self.assertEqual(self.accept(self.ready), self.ready)
        self.assertEqual(self.accept(self.module), self.module)

    def test_complete_source_wire_keeps_exact_creation_and_requires_module_before_bytes(self):
        self.begin()
        self.assertEqual(self.accept(self.code), self.code)
        ended = dict(event='process_completed', time_ms=3, pid=64, creation=self.module['creation'],
                     polls=1, read_calls=1, code_records=1, record_limit_reached=False)
        self.assertEqual(self.accept(ended), ended)
        done = dict(event='completed', mode='source', polls=2, processes=1, failures=0, exit=0)
        self.assertEqual(self.accept(done), done)
        self.assertTrue(self.records.summary()['native_completion_observed'])
        self.assertIsNone(self.accept(self.code))
        self.assertEqual(self.records.events[1]['creation'], 123456789012345678)

    def test_code_cannot_precede_known_module_or_borrow_a_reused_pid(self):
        self.assertIsNone(self.accept(self.code))
        self.begin()
        self.assertIsNone(self.accept({**self.code, 'creation': self.module['creation'] + 1}))
        self.assertEqual(self.records.summary()['code_records'], 0)

    def test_private_fields_unbounded_or_noncode_payload_never_enter_persistable_records(self):
        self.begin()
        for change in ({'ticket': 'PRIVATE_SENTINEL'}, {'hex': 'PRIVATE_SENTINEL'},
                       {'hex': '90' * 65}, {'length': 65}, {'rva': 0x3203b1}):
            with self.subTest(change=change):
                self.assertIsNone(self.accept({**self.code, **change}))
        self.assertIsNone(self.records.accept('PRIVATE_SENTINEL' * 300))
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(self.records.events))
        self.assertEqual(self.records.summary()['code_records'], 0)

    def test_source_role_rejects_fixture_mode_or_modified_window(self):
        for change in ({'mode': 'fixture'}, {'rva': 4096}, {'length': 32}, {'poll_ms': 1},
                       {'record_limit': 21}, {'duration_ms': 600001}, {'pid': True}):
            with self.subTest(change=change):
                self.assertIsNone(self.accept({**self.ready, **change}))
        self.assertFalse(self.records.ready)

    def test_guard_denial_is_metadata_only_and_does_not_claim_code_capture(self):
        self.begin()
        denied = dict(event='denied', time_ms=2, pid=64, creation=self.module['creation'],
                      probe=0, reason=3, state=4096, protect=32, type=131072,
                      allocation_base=0x140320000, read_attempted=False, error=0)
        self.assertEqual(self.accept(denied), denied)
        self.assertIsNone(self.accept({**denied, 'probe': 1}))
        self.assertFalse(self.records.summary()['actual_ros_exit_caller_or_cause_claim'])
        self.assertEqual(self.records.summary()['code_records'], 0)

    def test_sample_sequence_and_twenty_record_bound_are_enforced(self):
        self.begin()
        self.assertIsNone(self.accept({**self.code, 'sample': 2}))
        for index in range(1, 21):
            self.assertIsNotNone(self.accept({**self.code, 'sample': index, 'hex': f'{index:02x}' * 64}))
        self.assertIsNone(self.accept({**self.code, 'sample': 21}))
        self.assertEqual(self.records.summary()['code_records'], 20)

    def test_module_bounds_and_false_completion_counts_cannot_validate_capture(self):
        self.assertIsNotNone(self.accept(self.ready))
        self.assertIsNone(self.accept({**self.module, 'size': 63}))
        self.assertIsNone(self.accept({**self.module, 'base': 0xffffffffffffffff}))
        self.assertIsNotNone(self.accept(self.module))
        self.assertIsNone(self.accept(dict(event='process_completed', time_ms=3, pid=64,
            creation=self.module['creation'], polls=1, read_calls=1, code_records=1,
            record_limit_reached=False)))

    def test_duplicate_keys_and_unhashable_event_are_bounded_rejections(self):
        self.assertIsNone(self.records.accept('{"event":"ready","event":"module"}'))
        for event in ([], {}, 32, None):
            self.assertIsNone(self.accept({'event': event}))
        self.assertEqual(self.records.events, [])

    def test_denial_needs_a_live_known_module_and_actual_read_semantics(self):
        self.begin()
        row = dict(event='denied', time_ms=2, pid=64, creation=self.module['creation'],
                   probe=0, reason=5, state=4096, protect=4, type=16777216,
                   allocation_base=self.module['base'], read_attempted=False, error=0)
        for change in ({'creation': self.module['creation'] + 1}, {'reason': 0},
                       {'reason': 999}, {'read_attempted': True}, {'reason': 7}):
            self.assertIsNone(self.accept({**row, **change}))
        self.assertIsNotNone(self.accept(row))
        self.assertIsNotNone(self.accept({**row, 'reason': 7, 'read_attempted': True, 'error': 299}))

    def test_unchanged_code_is_not_a_new_changed_frame(self):
        self.begin()
        self.assertIsNotNone(self.accept(self.code))
        self.assertIsNone(self.accept({**self.code, 'sample': 2}))
        self.assertEqual(self.records.summary()['code_records'], 1)

    def test_completion_does_not_hide_failure_or_missing_process_summaries(self):
        self.begin()
        done = dict(event='completed', mode='source', polls=2, processes=1, failures=0, exit=0)
        self.assertIsNone(self.accept(done))
        end = dict(event='process_completed', time_ms=3, pid=64, creation=self.module['creation'],
                   polls=1, read_calls=0, code_records=0, record_limit_reached=False)
        self.assertIsNone(self.accept({**end, 'read_calls': 2}))
        self.assertIsNone(self.accept({**end, 'record_limit_reached': True}))
        self.assertIsNotNone(self.accept(end))
        self.assertIsNone(self.accept({**done, 'exit': 777, 'failures': 99}))
        self.assertIsNone(self.accept({**done, 'exit': 0, 'failures': 99}))
        self.assertIsNotNone(self.accept({**done, 'exit': 3, 'failures': 1}))
        self.assertTrue(self.records.summary()['native_completion_observed'])
        self.assertFalse(self.records.summary()['native_completion_succeeded'])

    def test_equal_counts_cannot_replace_the_identity_of_an_unfinished_module(self):
        self.begin()
        end = dict(event='process_completed', time_ms=3, pid=999, creation=999,
                   polls=1, read_calls=0, code_records=0, record_limit_reached=False)
        self.assertIsNone(self.accept({**end, 'read_calls': 1}))
        self.assertIsNotNone(self.accept(end))
        self.assertIsNone(self.accept(dict(event='completed', mode='source', polls=2,
            processes=1, failures=0, exit=0)))
        self.assertFalse(self.records.completed)

    def test_module_limit_is_enforced_before_the_sixty_fifth_record_is_persistable(self):
        self.assertIsNotNone(self.accept(self.ready))
        for index in range(64):
            self.assertIsNotNone(self.accept({**self.module, 'pid': index + 64}))
        self.assertIsNone(self.accept({**self.module, 'pid': 128}))
        self.assertEqual(self.records.summary()['module_records'], 64)


if __name__ == '__main__':
    unittest.main()
