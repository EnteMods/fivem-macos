"""Resolved class roles must remain scoped to the Windows process that registered them."""

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'native/windows-client'))

from window_registration_name_trace import Collector


class WindowRegistrationNameTraceTests(unittest.TestCase):
    def test_versioned_registration_and_miss_have_an_ordered_pid_local_lifetime(self):
        collector = Collector()
        lines = [
            '0020:0024:trace:cfxwndreg:trace_registration phase=1 ok=0 error=0',
            '0020:0024:trace:cfxwndreg:trace_registration phase=2 ok=0 error=0',
            '0020:0024:trace:class:NtUserRegisterClassExWOW name=L"grcWindow"->L"4.3.2.1!grcWindow" '
            'atom=c030 wndproc=0x1 hinst=0x2 bg=0x0 style=00000000 clsExt=0 winExt=0 class=0xdeadbeef',
            '0020:0024:trace:cfxwndreg:trace_registration phase=4 ok=1 error=0',
            '0020:0024:trace:cfxwndreg:trace_registration phase=5 ok=1 error=0',
            '0030:0034:trace:class:NtUserUnregisterClass 0xdeadbeef',
            '0020:0024:trace:win:WIN_CreateWindowEx L"grcWindow" 0x0 -> not found',
            '0020:0024:trace:class:NtUserUnregisterClass 0xdeadbeef',
        ]
        self.assertNotIn('passthrough', [collector.accept(line + '\n') for line in lines])
        report = collector.summary()
        names = report['resolved_name_events']
        self.assertEqual([(v['event'], v['name_kind'], v['trace_line']) for v in names],
                         [('register_success', 'versioned', 3), ('unregistered', 'versioned', 8)])
        self.assertEqual(report['events'][0]['trace_line'], 7)
        self.assertTrue(report['registration_api']['grc_window_events'][1]['success'])
        self.assertNotIn('deadbeef', repr(report))
        self.assertNotIn('4.3.2.1', repr(report))


if __name__ == '__main__':
    unittest.main()
