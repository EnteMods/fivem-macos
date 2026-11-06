import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'native/wine-numeric-diagnostics/numeric_contract.py'
SPEC = importlib.util.spec_from_file_location('own_numeric_contract', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def row(api, status=0, access=0, pid=32, tid=36):
    return f'{tid:04x}:[CFX_WINE_API] pid={pid} tid={tid} api={api} status={status} access={access}\n'


class NumericContractTests(unittest.TestCase):
    def test_nested_calls_and_false_error_zero_are_distinct(self):
        parsed = MODULE.parse_lines([row(84), row(88), row(90), row(86)])
        self.assertEqual(parsed['completed_call_pairs'], 2)
        self.assertTrue(parsed['all_observed_begins_paired'])
        self.assertEqual([x['status'] for x in parsed['failure_status_counts']], [0, 0])

    def test_errno_is_not_inferred_from_success_or_failure(self):
        parsed = MODULE.parse_lines([row(48, access=0x80000000), row(50, 2, 0x80000000)])
        self.assertTrue(parsed['fixed_record_syntax_and_budget_valid'])
        self.assertEqual(parsed['failure_status_counts'][0]['operation'], 'CreateFileA')
        self.assertFalse(parsed['ros_failure_cause_established'])

    def test_foreign_and_partial_payloads_are_discarded(self):
        parsed = MODULE.parse_lines(['secret=not-retained\n', row(40).rstrip() + ' token=secret\n',
                                     row(40).replace('pid=32', 'pid=secret'), row(40).replace('api=40', 'api=999')])
        self.assertEqual(parsed['records'], [])
        self.assertEqual(parsed['rejected_marker_lines'], 3)
        self.assertNotIn('secret', str(parsed))

    def test_prefix_and_dword_bounds(self):
        valid = row(44, access=0xffffffff)
        parsed = MODULE.parse_lines(['0020:' + valid, valid.replace('0024:', '0030:'), row(40, status=1),
                                     row(42, status=2**32), row(52, access=1)])
        self.assertEqual(parsed['accepted_records'], 1)
        self.assertEqual(parsed['rejected_marker_lines'], 4)

    def test_pending_return_is_only_incomplete_observation(self):
        parsed = MODULE.parse_lines([row(92)])
        self.assertEqual(len(parsed['pending_observed_calls']), 1)
        self.assertFalse(parsed['all_observed_begins_paired'])
        self.assertFalse(parsed['ros_failure_cause_established'])

    def test_cap_is_per_group_and_active_return_survives(self):
        lines = [row(40)]
        for _ in range(MODULE.CALL_LIMIT - 1):
            lines.extend([row(40), row(41)])
        lines.extend([row(0xf001, status=MODULE.CALL_LIMIT), row(41)])
        parsed = MODULE.parse_lines(lines)
        self.assertTrue(parsed['fixed_record_syntax_and_budget_valid'])
        self.assertTrue(parsed['all_observed_begins_paired'])
        self.assertTrue(parsed['output_budget_was_reached'])
        self.assertEqual(parsed['completed_call_pairs'], MODULE.CALL_LIMIT)

    def test_empty_output_is_not_a_complete_trace_claim(self):
        parsed = MODULE.parse_lines([])
        self.assertFalse(parsed['observed_any_records'])
        self.assertFalse(parsed['all_actual_api_calls_observed_claim'])

    def test_reordered_returns_are_reported(self):
        parsed = MODULE.parse_lines([row(40), row(48), row(41), row(49)])
        self.assertEqual(len(parsed['unmatched_returns']), 1)
        self.assertFalse(parsed['all_observed_begins_paired'])


if __name__ == '__main__':
    unittest.main()
