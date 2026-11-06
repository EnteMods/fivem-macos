import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import hashlib
from types import SimpleNamespace
from unittest.mock import patch

import observe

reader = observe.load_pinned(observe.READER, observe.READER_SHA, 'test_lifecycle_reader')
helper = observe.load_pinned(observe.HELPER, observe.HELPER_SHA, 'test_lifecycle_helper')


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()

    def text(self):
        return ('prefix "[CFX_SOURCE_COMPONENT] pid=12 tid=16 '
                'phase=citigame.pre-resume.callback.after component=sticky\\n"\n')

    def test_original_phase_stream_unchanged_and_known_rows_selected(self):
        text = self.text() + '[CFX_SOURCE_PHASE] pid=12 tid=16 phase=main.real.enter value=0\n'
        text += 'secret private payload without known marker\n'
        source = io.StringIO(text)
        target = self.directory / 'phases.ndjson'
        observe.interpose(helper.phase_log, reader)(source, target)
        self.assertEqual(json.loads(target.read_text()), dict(pid=12, tid=16, phase='main.real.enter', value=0))
        self.assertEqual(json.loads((self.directory / 'lifecycle-callbacks.ndjson').read_text()),
                         dict(pid=12, tid=16, phase=5, component=1))
        self.assertNotIn('private', ''.join(p.read_text() for p in self.directory.iterdir()))
        self.assertTrue(json.loads((self.directory / 'lifecycle-collector.json').read_text())['collection_complete'])

    def test_partial_stream_stays_incomplete(self):
        source = observe.LifecycleStream(io.StringIO(self.text() * 2), self.directory, reader)
        with source:
            next(source)
        self.assertFalse(source.status['collection_complete'])

    def test_exception_stays_incomplete(self):
        source = observe.LifecycleStream(io.StringIO(self.text()), self.directory, reader)
        with self.assertRaises(RuntimeError):
            with source:
                raise RuntimeError('private exception text')
        self.assertFalse(source.status['collection_complete'])
        self.assertNotIn('private', (self.directory / 'lifecycle-collector.json').read_text())

    def test_budget_does_not_stop_original_stream(self):
        with observe.LifecycleStream(io.StringIO(self.text() * (observe.LIMIT + 3)), self.directory, reader) as source:
            self.assertEqual(len(list(source)), observe.LIMIT + 3)
        self.assertEqual(source.status['accepted_rows'], observe.LIMIT)
        self.assertEqual(source.status['dropped_rows'], 3)
        self.assertFalse(source.status['collection_complete'])

    def test_existing_output_never_replaced(self):
        path = self.directory / 'lifecycle-callbacks.ndjson'
        path.write_text('previous')
        with self.assertRaises(FileExistsError):
            observe.LifecycleStream(io.StringIO(), self.directory, reader)
        self.assertEqual(path.read_text(), 'previous')

    def test_write_failure_does_not_change_stream(self):
        source = observe.LifecycleStream(io.StringIO(self.text()), self.directory, reader)
        source.output.close()
        with source:
            self.assertEqual(list(source), [self.text()])
        self.assertTrue(source.status['collector_failed'])
        self.assertFalse(source.status['collection_complete'])

    def test_modified_pinned_input_refused(self):
        path = self.directory / 'reader.py'
        marker = self.directory / 'executed'
        path.write_text('open(' + repr(str(marker)) + ', "w").write("executed")')
        with self.assertRaises(RuntimeError):
            observe.load_pinned(path, observe.READER_SHA, 'bad_input')
        self.assertFalse(marker.exists())


class VendorGenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.prefix = self.root / 'prefix'
        self.prefix.mkdir()
        self.rows = [dict(path='code-' + str(i), bytes=1, sha256='fixed') for i in range(145)]
        self.old = self.root / 'old.json'
        self.manifest = self.root / 'manifest.json'
        self.review = self.root / 'review.json'
        self.old.write_text(json.dumps(dict(roots=['code'], files=self.rows)))
        self.review.write_text(json.dumps(dict(prefix='prefix')))
        self.data = dict(roots=['code'], files=self.rows,
            excluded_account_profiles_registry_sessions=True,
            prefix_binding=dict(prefix='prefix', device=self.prefix.stat().st_dev, inode=self.prefix.stat().st_ino),
            source_evidence=dict(path='review.json', sha256=self.sha(self.review)),
            previous_manifest=dict(sha256=self.sha(self.old)))
        self.verified = []
        self.helper = SimpleNamespace(game=SimpleNamespace(PREFIX=self.prefix), reuse=SimpleNamespace(
            MANIFEST=self.old, MANIFEST_SHA=self.sha(self.old), inventory=lambda: self.rows,
            verify=lambda path, rows: self.verified.append((path, len(rows)))))

    def sha(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def configure(self):
        self.manifest.write_text(json.dumps(self.data))
        with patch.multiple(observe, ROOT=self.root, VENDOR_MANIFEST=self.manifest,
                            VENDOR_MANIFEST_SHA=self.sha(self.manifest), VENDOR_REVIEW=self.review,
                            VENDOR_REVIEW_SHA=self.sha(self.review)):
            return observe.configure_vendor_generation(self.helper)

    def test_new_generation_keeps_all_vendor_checks(self):
        result = self.configure()
        self.assertEqual(self.verified, [(self.prefix, 145)])
        self.assertEqual(result['verified_program_files'], 145)
        self.assertEqual(self.helper.reuse.MANIFEST, self.manifest)

    def test_new_path_is_not_admitted(self):
        self.data['files'] = self.rows[:-1] + [dict(path='unreviewed', bytes=1, sha256='fixed')]
        with self.assertRaises(RuntimeError):
            self.configure()
        self.assertEqual(self.verified, [])

    def test_other_prefix_is_not_admitted(self):
        self.data['prefix_binding']['inode'] += 1
        with self.assertRaises(RuntimeError):
            self.configure()
        self.assertEqual(self.verified, [])

    def test_vendor_byte_failure_propagates(self):
        def fail(path, rows):
            raise RuntimeError('vendor bytes changed')
        self.helper.reuse.verify = fail
        with self.assertRaises(RuntimeError):
            self.configure()


if __name__ == '__main__':
    unittest.main()
