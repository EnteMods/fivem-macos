"""Check local dependency output guards without network, compilers or Wine."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import prepare


class OwnDependencyPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / 'project'
        self.work = self.root / 'build/wine-job-query-parity'
        self.work.mkdir(parents=True)
        for name, value in (('ROOT', self.root), ('WORK', self.work)):
            patch = mock.patch.object(prepare, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def test_new_output_and_identical_existing_payload_are_accepted(self):
        path = self.work / 'dev/include/own.h'
        prepare.put(path, b'own header')
        prepare.put(path, b'own header')
        self.assertEqual(path.read_bytes(), b'own header')

    def test_different_existing_payload_is_preserved(self):
        path = self.work / 'own.h'
        path.write_bytes(b'preserve')
        with self.assertRaises(RuntimeError):
            prepare.put(path, b'changed')
        self.assertEqual(path.read_bytes(), b'preserve')

    def test_traversal_and_outside_paths_are_rejected(self):
        for path in (self.work / '../foreign', self.root / 'foreign'):
            with self.subTest(path=path):
                with self.assertRaises((RuntimeError, ValueError)):
                    prepare.own(path)

    def test_symlinked_ancestor_is_rejected(self):
        external = self.root.parent / 'external'
        external.mkdir()
        (self.work / 'dev').symlink_to(external, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            prepare.put(self.work / 'dev/foreign', b'must not write')
        self.assertEqual(list(external.iterdir()), [])

    def test_hardlinked_output_is_rejected_before_overwriting(self):
        sentinel = self.root.parent / 'sentinel'
        sentinel.write_bytes(b'preserve')
        path = self.work / 'own.h'
        os.link(sentinel, path)
        with self.assertRaises(RuntimeError):
            prepare.put(path, b'changed')
        self.assertEqual(sentinel.read_bytes(), b'preserve')

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'Requires POSIX FIFO support')
    def test_special_file_is_rejected_before_read_or_write(self):
        path = self.work / 'own.h'
        os.mkfifo(path)
        with self.assertRaises(RuntimeError):
            prepare.put(path, b'must not block')


if __name__ == '__main__':
    unittest.main()
