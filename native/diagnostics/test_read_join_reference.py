import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
spec = importlib.util.spec_from_file_location('reader', Path(__file__).with_name('read_join_reference.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

def encoded(rows):
    return ''.join((json.dumps(x, separators=(',', ':')) + '\n' for x in rows)).encode()

def fixture(status='complete', target=True):
    events = [{'type': 'collector', 'state': 'started', 'elapsed_ms': 0}, {'type': 'process_scan', 'status': 'ok', 'elapsed_ms': 1}]
    if target:
        events += [{'type': 'process', 'name': 'FiveM_GTAProcess.exe', 'pid': 7, 'ppid': 3, 'elapsed_ms': 2}, {'type': 'module', 'pid': 7, 'name': 'net.dll', 'status': 'ok', 'sha256': 'a' * 64, 'elapsed_ms': 3}, {'type': 'tcp', 'pid': 7, 'local_address': '127.0.0.1', 'local_port': 1000, 'remote_address': '192.0.2.10', 'remote_port': 443, 'state': 'Established', 'elapsed_ms': 4}, {'type': 'udp', 'pid': 7, 'local_address': '192.168.1.20', 'local_port': 30120, 'elapsed_ms': 5}]
    events.append({'type': 'collector', 'state': 'stopped', 'elapsed_ms': 6})
    raw = encoded(events)
    state = {'state': 'stopped', 'rows': len(events), 'bytes': len(raw), 'successful_scans': 1, 'targets_seen': int(target), 'tcp_scans': int(target), 'udp_scans': int(target), 'unknown_count': 0}
    summary = {'status': status, 'job_state': 'Completed', 'collector_state': 'stopped'}
    marks = [{'type': 'marker', 'marker': 'join', 'elapsed_ms': 5}]
    return {'events.jsonl': raw, 'markers.jsonl': encoded(marks), 'collector-status.json': json.dumps(state).encode(), 'collection-summary.json': json.dumps(summary).encode()}

def pack(path, data):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for (n, b) in data.items():
            z.writestr(n, b)

class Tests(unittest.TestCase):

    def test_valid_private_summary(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'input.zip'
            pack(path, fixture())
            out = r.analyze(r.read_zip(path))
            raw = json.dumps(out)
            self.assertEqual(out['collection']['status'], 'complete')
            self.assertEqual(out['markers'][0]['origin'], 'user_reported')
            self.assertEqual(out['modules'][0]['basename'], 'net.dll')
            tcp = next(item for item in out['network_counts'] if item['protocol'] == 'tcp')
            udp = next(item for item in out['network_counts'] if item['protocol'] == 'udp')
            self.assertEqual(tcp['remote_port'], 443)
            self.assertNotIn('local_port', tcp)
            self.assertEqual(udp['local_port'], 30120)
            self.assertNotIn('remote_port', udp)
            for secret in ('192.0.2.10', '192.168.1.20', 'FiveM_GTAProcess.exe'):
                self.assertNotIn(secret, raw)

    def test_windows_utf8_bom(self):
        data = fixture()
        for name in ('markers.jsonl', 'collector-status.json', 'collection-summary.json'):
            data[name] = b'\xef\xbb\xbf' + data[name]
        out = r.analyze(data)
        self.assertEqual(out['collection']['status'], 'complete')
        self.assertEqual(out['markers'][0]['marker'], 'join')

    def test_capped_and_failed(self):
        for (state_name, job) in [('capped', 'Completed'), ('failed', 'Failed')]:
            data = fixture('incomplete')
            state = json.loads(data['collector-status.json'])
            state['state'] = state_name
            data['collector-status.json'] = json.dumps(state).encode()
            data['collection-summary.json'] = json.dumps({'status': 'incomplete', 'job_state': job, 'collector_state': state_name}).encode()
            self.assertEqual(r.analyze(data)['collection']['collector_state'], state_name)

    def test_stale_incomplete_snapshot_remains_useful(self):
        data = fixture('incomplete')
        state = json.loads(data['collector-status.json'])
        state.update(state='ready', rows=1, bytes=1)
        data['collector-status.json'] = json.dumps(state).encode()
        data['collection-summary.json'] = json.dumps({'status': 'incomplete', 'job_state': 'Stopped', 'collector_state': 'ready'}).encode()
        out = r.analyze(data)
        self.assertFalse(out['collection']['snapshot_counts_match'])
        self.assertEqual(out['processes'][0]['pid'], 7)

    def test_interrupted_snapshot_does_not_discard_later_unknown_access(self):
        data = fixture('incomplete')
        data['events.jsonl'] += encoded([
            {'type': 'modules', 'pid': 7, 'status': 'unknown', 'elapsed_ms': 7},
        ])
        state = json.loads(data['collector-status.json'])
        state.update(state='ready', unknown_count=0)
        data['collector-status.json'] = json.dumps(state).encode()
        data['collection-summary.json'] = json.dumps({
            'status': 'incomplete', 'job_state': 'Stopped', 'collector_state': 'ready',
        }).encode()

        out = r.analyze(data)

        self.assertEqual(out['collection']['status'], 'incomplete')
        self.assertEqual(out['collection']['observed_unknown_count'], 1)
        self.assertEqual(out['collection']['reported_unknown_count'], 0)
        self.assertFalse(out['collection']['unknown_count_matches'])
        self.assertFalse(out['collection']['snapshot_counts_match'])
        self.assertEqual(out['unknown_access_counts'], {'modules': 1})
        self.assertEqual(out['modules'][0]['basename'], 'net.dll')

    def test_no_targets(self):
        out = r.analyze(fixture('incomplete', False))
        self.assertEqual(out['processes'], [])
        self.assertEqual(out['modules'], [])

    def test_short_unobserved_is_not_absent(self):
        data = fixture()
        events = [x for x in data['events.jsonl'].splitlines() if json.loads(x).get('type') != 'module']
        raw = b'\n'.join(events) + b'\n'
        state = json.loads(data['collector-status.json'])
        state.update(rows=len(events), bytes=len(raw))
        data['events.jsonl'] = raw
        data['collector-status.json'] = json.dumps(state).encode()
        out = r.analyze(data)
        self.assertEqual(out['modules'], [])
        self.assertTrue(any(('not evidence of absence' in x for x in out['limitations'])))

    def test_complete_cannot_hide_unknown(self):
        data = fixture()
        event = {'type': 'modules', 'pid': 7, 'status': 'unknown', 'elapsed_ms': 6}
        raw = data['events.jsonl'] + encoded([event])
        state = json.loads(data['collector-status.json'])
        state.update(rows=state['rows'] + 1, bytes=len(raw))
        data['events.jsonl'] = raw
        data['collector-status.json'] = json.dumps(state).encode()
        with self.assertRaises(r.Invalid):
            r.analyze(data)

    def test_missing_and_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'a.zip'
            data = fixture()
            del data['collector-status.json']
            pack(p, data)
            with self.assertRaises(r.Invalid):
                r.read_zip(p)
            data = fixture()
            data['../events.jsonl'] = data.pop('events.jsonl')
            pack(p, data)
            with self.assertRaises(r.Invalid):
                r.read_zip(p)

    def test_duplicate(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'a.zip'
            pack(p, fixture())
            with zipfile.ZipFile(p, 'a') as z:
                with self.assertWarns(UserWarning):
                    z.writestr('events.jsonl', b'')
            with self.assertRaises(r.Invalid):
                r.read_zip(p)

    def test_zipbomb_size(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'a.zip'
            data = fixture()
            data['markers.jsonl'] = b'x' * (r.LIMITS['markers.jsonl'] + 1)
            pack(p, data)
            with self.assertRaises(r.Invalid):
                r.read_zip(p)

    def test_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'a.zip'
            data = fixture()
            with zipfile.ZipFile(p, 'w') as z:
                for (n, b) in data.items():
                    if n == 'events.jsonl':
                        info = zipfile.ZipInfo(n)
                        info.create_system = 3
                        info.external_attr = 41471 << 16
                        z.writestr(info, b)
                    else:
                        z.writestr(n, b)
            with self.assertRaises(r.Invalid):
                r.read_zip(p)

    def test_secret_rejected_without_echo(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'a.zip'
            data = fixture()
            event = json.loads(data['events.jsonl'].splitlines()[0])
            event['secret'] = 'PRIVATE_TOKEN_123'
            lines = data['events.jsonl'].splitlines()
            lines[0] = json.dumps(event).encode()
            raw = b'\n'.join(lines) + b'\n'
            state = json.loads(data['collector-status.json'])
            state['bytes'] = len(raw)
            data['events.jsonl'] = raw
            data['collector-status.json'] = json.dumps(state).encode()
            pack(p, data)
            result = subprocess.run([sys.executable, str(Path(r.__file__)), '--input', str(p), '--output', str(Path(d) / 'out.json')], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('PRIVATE_TOKEN_123', result.stdout + result.stderr)

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'a.zip'
            out = Path(d) / 'out.json'
            out.write_text('sentinel')
            pack(p, fixture())
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                result = r.main(['--input', str(p), '--output', str(out)])
            self.assertEqual(result, 1)
            self.assertEqual(json.loads(captured.getvalue())['status'], 'FAIL')
            self.assertEqual(out.read_text(), 'sentinel')
if __name__ == '__main__':
    unittest.main()
