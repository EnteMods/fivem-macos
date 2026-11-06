"""Check configure parser adaptation and feature guards without compiling Wine."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import build
import prepare


class BuildBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / 'project'
        self.work = self.root / 'build/wine-job-query-parity'
        self.output = self.work / 'full-x86_64'
        self.source = self.root / 'original-source'
        self.output.mkdir(parents=True)
        self.source.mkdir()
        for module, values in ((prepare, {'ROOT': self.root, 'WORK': self.work}),
                               (build, {'ROOT': self.root, 'WORK': self.work, 'BUILD': self.output, 'SOURCE': self.source})):
            for key, value in values.items():
                patch = mock.patch.object(module, key, value)
                patch.start()
                self.addCleanup(patch.stop)

    def test_parser_copy_changes_only_darwin_line_and_preserves_original(self):
        original = ('#!/bin/sh\n'
                    + r'    dylib) ac_cv_lib_soname_demo=`echo text | sed -e "s/^.*\/\(libdemo\.[0-9A-Za-z.]*dylib\).*$/\1/"` ;;'
                    + '\nother original logic\n')
        path = self.source / 'configure'
        path.write_text(original)
        copied = build.patched_configure()
        self.assertEqual(path.read_text(), original)
        self.assertIn(r's/^.*[\/[:space:]]\(libdemo', copied.read_text())
        self.assertIn('other original logic', copied.read_text())
        self.assertEqual(copied.stat().st_mode & 0o777, 0o755)

    def test_real_sed_parser_derives_bare_and_path_qualified_ids(self):
        expression = r's/^.*[\/[:space:]]\(libdemo\.[0-9A-Za-z.]*dylib\).*$/\1/;2,$d'
        for value in ('libdemo.dylib', '@rpath/libdemo.1.dylib', '/own/prefix/libdemo.1.2.dylib'):
            with self.subTest(value=value):
                output = subprocess.check_output(['/usr/bin/sed', '-e', expression],
                    input='\t' + value + ' (compatibility version 1.0.0, current version 1.2.0)\n', text=True)
                self.assertEqual(output.strip(), Path(value).name)

    def config(self, soname):
        directory = self.output / 'include'
        directory.mkdir(exist_ok=True)
        (directory / 'config.h').write_text('\n'.join([
            '#define HAVE_GNUTLS_CIPHER_INIT 1', '#define HAVE_FT2BUILD_H 1', '#define HAVE_SDL_H 1',
            '#define HAVE_FFMPEG 1', '#define SONAME_LIBGNUTLS "' + soname + '"',
            '#define SONAME_LIBFREETYPE "libfreetype.dylib"', '#define SONAME_LIBSDL2 "libSDL2-2.0.0.dylib"',
            '#define SONAME_LIBVULKAN "libMoltenVK.dylib"']))
        (self.output / 'Makefile').write_text('DISABLED_SUBDIRS = dlls/unused\nGSTREAMER_LIBS = -lgstreamer-1.0\nCOREAUDIO_LIBS = -framework CoreAudio\n')

    def test_whole_otool_line_cannot_pass_soname_guard(self):
        self.config('libgnutls.dylib (compatibility version 1.0.0, current version 1.2.0)')
        with self.assertRaisesRegex(RuntimeError, 'genuine library basename'):
            build.verify_configuration()
        self.config('libgnutls.dylib')
        build.verify_configuration()

    def test_multiline_disabled_gstreamer_is_rejected(self):
        self.config('libgnutls.dylib')
        path = self.output / 'Makefile'
        path.write_text(path.read_text().replace('dlls/unused', 'dlls/unused \\\n  dlls/winegstreamer'))
        with self.assertRaisesRegex(RuntimeError, 'disabled the required GStreamer'):
            build.verify_configuration()

    def test_proposed_shell_quotes_are_removed_and_roles_not_inherited(self):
        with mock.patch.dict(os.environ, {'WINEPREFIX': '/productive', 'CitizenFX_ToolMode': '1',
                                          'DYLD_INSERT_LIBRARIES': '/foreign'}, clear=False):
            value = build.environment({'suggested_configure_environment_not_yet_run': {
                'GNUTLS_CFLAGS': "'-I/own/[sources]/include'"}})
        self.assertEqual(value['GNUTLS_CFLAGS'], '-I/own/[sources]/include')
        self.assertNotIn("'", value['LDFLAGS'])
        for name in ('WINEPREFIX', 'CitizenFX_ToolMode', 'DYLD_INSERT_LIBRARIES'):
            self.assertNotIn(name, value)


if __name__ == '__main__':
    unittest.main()
