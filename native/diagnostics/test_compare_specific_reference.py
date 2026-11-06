import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).with_name('compare_specific_reference.py')
MARKERS = ('fresh_start', 'menu_ready', 'join_result')


class ComparisonTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.client = self.root / 'client'
        (self.client / 'bin').mkdir(parents=True)
        (self.client / 'bin/libcef.dll').write_bytes(b'cef')
        (self.client / 'libcef.dll').write_bytes(b'wrong-location')
        self.archive = self.root / 'reference.zip'
        self.output = self.root / 'output.json'
        self.sha = hashlib.sha256(b'cef').hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def records(self):
        return {m: {'schema': 1, 'marker': m, 'process_scan': 'ok', 'tcp_scan': 'ok',
                    'truncation': [], 'rockstar_scope_unknown': 0,
                    'processes': [{'name': 'FiveM.exe', 'pid': 11, 'modules_status': 'ok',
                                   'modules': [{'name': 'libcef.dll', 'sha256': self.sha}]},
                                  {'name': 'Game.exe', 'pid': 22, 'modules_status': 'unknown', 'modules': []}],
                    'tcp': [{'pid': 11, 'state': 'CloseWait', 'remote_address': '192.0.2.10', 'remote_port': 30120}]} for m in MARKERS}

    def write_zip(self, records, extra=None):
        with zipfile.ZipFile(self.archive, 'w') as z:
            for name, value in records.items():
                z.writestr(name + '.json', json.dumps(value))
            if extra:
                z.writestr(extra, '{}')

    def run_tool(self):
        return subprocess.run([sys.executable, str(SCRIPT), '--archive', str(self.archive), '--client-dir', str(self.client), '--output', str(self.output), '--target-ip', '192.0.2.10'], capture_output=True, text=True)

    def test_explicit_cef_and_per_process(self):
        self.write_zip(self.records())
        before = self.archive.read_bytes()
        self.assertEqual(self.run_tool().returncode, 0)
        data = json.loads(self.output.read_text())
        self.assertEqual(self.archive.read_bytes(), before)
        self.assertEqual(data['mac_disk']['libcef.dll']['relative_path'], 'bin/libcef.dll')
        self.assertEqual(data['snapshots'][0]['processes'][0]['modules'][0]['mac_disk_comparison'], 'MATCH')
        self.assertEqual(data['snapshots'][0]['processes'][1]['modules'], [])
        self.assertEqual(data['snapshots'][0]['target_tcp_rows'][0]['state'], 'CloseWait')
        self.assertNotIn('192.0.2.10', self.output.read_text())

    def test_unknown_hash_and_missing_file(self):
        records = self.records()
        records['fresh_start']['processes'][0]['modules'] = [{'name': 'libcef.dll', 'sha256': None}, {'name': 'net.dll', 'sha256': self.sha}]
        self.write_zip(records)
        self.assertEqual(self.run_tool().returncode, 0)
        data = json.loads(self.output.read_text())
        self.assertEqual([m['mac_disk_comparison'] for m in data['snapshots'][0]['processes'][0]['modules']], ['UNKNOWN', 'UNKNOWN'])
        self.assertEqual(data['mac_disk']['net.dll']['status'], 'missing')

    def test_extra_and_missing_members_rejected(self):
        self.write_zip(self.records(), 'extra.json')
        self.assertNotEqual(self.run_tool().returncode, 0)
        self.assertFalse(self.output.exists())
        records = self.records()
        del records['join_result']
        self.write_zip(records)
        self.assertNotEqual(self.run_tool().returncode, 0)

    def test_duplicate_member_rejected(self):
        self.write_zip(self.records())
        with zipfile.ZipFile(self.archive, 'a') as z:
            z.writestr('fresh_start.json', '{}')
        self.assertNotEqual(self.run_tool().returncode, 0)

    def test_malformed_and_over_limit_rejected(self):
        for mutation in ('digest', 'count', 'name', 'marker'):
            records = self.records()
            p = records['fresh_start']['processes'][0]
            if mutation == 'digest': p['modules'][0]['sha256'] = 'not-a-hash'
            elif mutation == 'count': records['fresh_start']['tcp'] = [{}] * 1001
            elif mutation == 'name': p['modules'][0]['name'] = 'other.dll'
            else: records['fresh_start']['marker'] = 'join_result'
            self.write_zip(records)
            self.assertNotEqual(self.run_tool().returncode, 0, mutation)
            self.assertFalse(self.output.exists())

    def test_target_ip_is_required_and_must_be_ipv4(self):
        self.write_zip(self.records())
        command = [sys.executable, str(SCRIPT), '--archive', str(self.archive),
                   '--client-dir', str(self.client), '--output', str(self.output)]
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        self.assertNotEqual(subprocess.run(command + ['--target-ip', '::1'], capture_output=True).returncode, 0)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_not_overwritten(self):
        self.write_zip(self.records())
        self.output.write_text('keep')
        self.assertNotEqual(self.run_tool().returncode, 0)
        self.assertEqual(self.output.read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
