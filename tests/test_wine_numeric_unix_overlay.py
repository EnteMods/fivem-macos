"""Own numeric Unix-sink overlays and host doubles, without Wine or network."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_numeric_unix_overlay',
    ROOT / 'native/wine-numeric-diagnostics/unix_debug_overlay.py')
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)


class NumericUnixOverlayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = (ROOT / 'build/wine-job-query/source' / overlay.SOURCE).read_bytes()

    def test_exact_inventory_and_original_hash_required(self):
        for invalid in ({}, {'../private': b'x'}, {overlay.SOURCE: self.original, 'extra': b'x'},
                        {overlay.SOURCE: bytearray(self.original)}, {overlay.SOURCE: self.original + b'\n'}):
            with self.subTest(keys=tuple(invalid)), self.assertRaises(RuntimeError):
                overlay.apply_all(invalid)

    def test_exact_reversible_two_sinks_without_changing_other_debug_output(self):
        patched, proof = overlay.apply_all({overlay.SOURCE: self.original})
        self.assertEqual(set(patched), {overlay.SOURCE})
        self.assertEqual(overlay.strip(overlay.SOURCE, patched[overlay.SOURCE]), self.original)
        self.assertEqual(proof['original']['sha256'], overlay.SOURCE_SHA256)
        self.assertEqual(proof['patched']['sha256'], hashlib.sha256(patched[overlay.SOURCE]).hexdigest())
        self.assertEqual(proof['edits']['return_wrappers'], 2)
        self.assertFalse(proof['native_ntdll_debug_output_changed'])
        self.assertFalse(proof['build_or_runtime_or_prefix_or_network_actions'])
        self.assertIn(b'write( 2, info->output, info->out_pos );', patched[overlay.SOURCE])

    def test_changed_foreign_or_duplicate_overlay_refused(self):
        patched = overlay.apply_all({overlay.SOURCE: self.original})[0][overlay.SOURCE]
        with self.assertRaises(RuntimeError):
            overlay.apply_all({overlay.SOURCE: patched})
        for path, data in (('../private', patched), (overlay.SOURCE, patched + b'\n'),
                           (overlay.SOURCE, patched.replace(b'if (preserve)', b'if (1)', 1)),
                           (overlay.SOURCE, overlay.HELPER + patched)):
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                overlay.strip(path, data)

    def test_scope_helpers_have_no_dynamic_queries_or_payload_output(self):
        for forbidden in (b'GetLastError', b'SetLastError', b'GetEnvironmentVariable', b'getenv',
                          b'malloc(', b'calloc(', b'strlen(', b'memcmp(', b'printf(', b'NtQuery',
                          b'NtRead', b'NtWrite', b'write( 1,'):
            self.assertNotIn(forbidden, overlay.HELPER)
        self.assertEqual(overlay.HELPER.count(b'write( 2, str, len )'), 1)
        self.assertIn(b'str != info->output', overlay.HELPER)
        self.assertIn(b'len > sizeof(info->output)', overlay.HELPER)

    def test_native_owned_buffer_numeric_scope_errno_and_single_write(self):
        harness = br'''
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef int32_t NTSTATUS;
struct debug_info { char output[1020]; };
static struct debug_info info;
static struct debug_info *get_info(void) { return &info; }
static int calls, write_error, write_return;
static const char *written_pointer;
static unsigned int written_len;
static NTSTATUS fake_write(int descriptor, const char *str, unsigned int len)
{
    if (descriptor != 2) return -99;
    ++calls; written_pointer = str; written_len = len;
    errno = write_error;
    return write_return;
}
#define write fake_write
''' + overlay.HELPER + br'''
#undef write
static int check(int condition, int line)
{
    if (!condition) { fprintf(stderr, "own native fixture failure at %d\n", line); return 1; }
    return 0;
}
#define CHECK(c) do { if (check((c), __LINE__)) return 1; } while (0)
int main(void)
{
    static const char *valid[] = {
      "00ab:[CFX_WINE_API] pid=1 tid=2 api=80 status=0 access=0\n",
      "12ABCDEF:0001:[CFX_WINE_API] pid=4294967295 tid=2 api=61441 status=4096 access=4294967295\n"
    };
    static const char *invalid[] = {
      "00ab:[CFX_WINE_API] pid=1 tid=2 api=80 status=4294967296 access=0\n",
      "00ab:[CFX_WINE_API] pid=1 tid=2 api=80 status=-1 access=0\n",
      "00ab:[CFX_WINE_API] pid=1 tid=2 api=80 status=0 access=0\nEXTRA",
      "00ab:[CFX_WINE_API] pid=1 tid=2 api=80 status=0 access=0\n\n",
      "00ab:trace:wininet:private [CFX_WINE_API] pid=1 tid=2 api=80 status=0 access=0\n",
      "00ab:[CFX_WINE_API] pid=1 tid=2 api=80 status=0 access=0 path=PRIVATE\n",
      "00ab:[CFX_OTHER] pid=1 tid=2 api=80 status=0 access=0\n",
      "[CFX_WINE_API] pid=1 tid=2 api=80 status=0 access=0\n",
      "000000001:[CFX_WINE_API] pid=1 tid=2 api=80 status=0 access=0\n",
      "0001:0002:0003:[CFX_WINE_API] pid=1 tid=2 api=80 status=0 access=0\n",
      "00ab:[CFX_WINE_API] pid=1 tid=2 api=80 status=0 access=\n",
      "00ab:[CFX_WINE_API] pid=1 tid=2 api=80 status=0 access=0"
    };
    unsigned int i, j, len;
    for (i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
    {
        strcpy(info.output, valid[i]); len = strlen(info.output);
        CHECK(cfx_numeric_unix_record(info.output, len));
        CHECK(!cfx_numeric_unix_record(valid[i], strlen(valid[i])));
        for (j = 0; j < 3; ++j)
        {
            calls = 0; write_error = 117; write_return = j == 0 ? -1 : j == 1 ? len : 3;
            errno = 73;
            CHECK(cfx_numeric_unix_write(info.output, len) == write_return);
            CHECK(errno == 73 && calls == 1 && written_pointer == info.output && written_len == len);
        }
    }
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        strcpy(info.output, invalid[i]); len = strlen(info.output);
        CHECK(!cfx_numeric_unix_record(info.output, len));
        calls = 0; write_error = 118; write_return = -1; errno = 74;
        CHECK(cfx_numeric_unix_write(info.output, len) == -1);
        CHECK(errno == 118 && calls == 1);
    }
    memset(info.output, '1', sizeof(info.output));
    CHECK(!cfx_numeric_unix_record(info.output, sizeof(info.output)));
    CHECK(!cfx_numeric_unix_record(info.output, sizeof(info.output) + 1));
    CHECK(!cfx_numeric_unix_record(info.output, 0));
    CHECK(!cfx_numeric_unix_record((const char *)(uintptr_t)1, 20));
    CHECK(!cfx_numeric_unix_record(NULL, 20));
    calls = 0; write_error = 119; write_return = -1; errno = 75;
    CHECK(cfx_numeric_unix_write((const char *)(uintptr_t)1, 20) == -1);
    CHECK(errno == 119 && calls == 1);
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='own-numeric-unix-test-') as temp:
            directory = Path(temp)
            source = directory / 'own_sink.c'
            executable = directory / 'own_sink'
            source.write_bytes(harness)
            compiled = subprocess.run(['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-fsanitize=address,undefined', str(source), '-o', str(executable)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ran = subprocess.run([str(executable)], capture_output=True, text=True, timeout=15)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            self.assertEqual(ran.stdout, '')


if __name__ == '__main__':
    unittest.main()
