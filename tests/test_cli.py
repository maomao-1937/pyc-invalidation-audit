"""Exercise the public command with disposable CPython caches and sources."""

from importlib.util import MAGIC_NUMBER, source_hash
import json
import os
from pathlib import Path
import py_compile
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "pyc_invalidation_audit.py"
LIMIT = 8 * 1024 * 1024
INVALID = {"status": "invalid"}
MODES = ((py_compile.PycInvalidationMode.TIMESTAMP, 0, "timestamp"),
         (py_compile.PycInvalidationMode.UNCHECKED_HASH, 1, "unchecked_hash"),
         (py_compile.PycInvalidationMode.CHECKED_HASH, 3, "checked_hash"))
STAMP = 1_700_000_000_100_000_000


def encode(report):
    return json.dumps(report, separators=(",", ":")).encode("ascii") + b"\n"


class CliTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.cache = self.root / "private-cache.pyc"
        self.source = self.root / "private-source.py"
        self.source.write_bytes(b"raise RuntimeError('private-do-not-execute')\n")
        os.utime(self.source, ns=(STAMP, STAMP))

    def compile_cache(self, mode):
        py_compile.compile(str(self.source), cfile=str(self.cache), doraise=True, invalidation_mode=mode)
        return self.cache.read_bytes()

    def header(self, flags, tail):
        self.cache.write_bytes(MAGIC_NUMBER + struct.pack("<I", flags) + tail)

    def run_cli(self, *args, **kwargs):
        return subprocess.run([sys.executable, "-B", str(SCRIPT), *map(str, args)],
                              cwd=self.root, timeout=10, **kwargs)

    def expect(self, code, report, *args):
        result = self.run_cli(*(args or (self.cache, self.source)), capture_output=True)
        output = encode(report) if isinstance(report, dict) else report
        self.assertEqual((result.returncode, result.stdout, result.stderr), (code, output, b""))

    def import_subject(self):
        sys.path.insert(0, str(ROOT))
        self.addCleanup(sys.path.pop, 0)
        import pyc_invalidation_audit as subject
        return subject

    def test_actual_py_compile_caches_in_all_three_modes(self):
        for mode, flags, label in MODES:
            with self.subTest(mode=label):
                cache = self.compile_cache(mode)
                self.assertEqual(cache[:8], MAGIC_NUMBER + struct.pack("<I", flags))
                fields = {"mtime_match": True, "size_match": True} if flags == 0 else {"hash_match": True}
                self.expect(0, {"status": "match", "mode": label, **fields})
                self.assertEqual(self.cache.read_bytes(), cache)

    def test_clock_dollar_stem_is_a_regular_filename(self):
        clock_source = self.root / "CLOCK$.py"
        clock_cache = self.root / "CLOCK$.pyc"
        self.source.rename(clock_source)
        py_compile.compile(str(clock_source), cfile=str(clock_cache), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)
        report = {"status": "match", "mode": "checked_hash", "hash_match": True}
        self.expect(0, report, clock_cache, clock_source)

    def test_timestamp_matches_same_second_and_size_after_source_edit(self):
        original = self.source.read_bytes()
        self.compile_cache(py_compile.PycInvalidationMode.TIMESTAMP)
        self.source.write_bytes(original.replace(b"execute", b"changed"))
        os.utime(self.source, ns=(STAMP, STAMP + 600_000_000))
        self.assertEqual(int(self.source.stat().st_mtime), STAMP // 1_000_000_000)
        self.assertNotEqual(self.source.read_bytes(), original)
        self.expect(0, {"status": "match", "mode": "timestamp", "mtime_match": True, "size_match": True})

    def test_hash_modes_report_same_size_edited_source_even_when_unchecked(self):
        original = self.source.read_bytes()
        for mode, flags, label in MODES[1:]:
            with self.subTest(mode=label):
                self.source.write_bytes(original)
                self.compile_cache(mode)
                self.source.write_bytes(original.replace(b"execute", b"changed"))
                os.utime(self.source, ns=(STAMP, STAMP))
                self.expect(1, {"status": "mismatch", "mode": label, "hash_match": False})

    def test_timestamp_identifies_mtime_and_size_independently(self):
        source = self.source.stat()
        mtime, size = int(source.st_mtime), source.st_size
        for stored_mtime, stored_size, mtime_ok, size_ok in (
            (mtime + 1, size, False, True), (mtime, size + 1, True, False), (mtime + 1, size + 1, False, False),
        ):
            self.header(0, struct.pack("<II", stored_mtime, stored_size))
            self.expect(1, {"status": "mismatch", "mode": "timestamp", "mtime_match": mtime_ok, "size_match": size_ok})

    def test_timestamp_uses_truncation_and_low_bits_without_reading_source(self):
        subject = self.import_subject()
        real_fstat, real_read = os.fstat, os.read
        size = self.source.stat().st_size
        for timestamp, stored in ((2**32 + 2.75, 2), (-1.75, 2**32 - 1)):
            self.header(0, struct.pack("<II", stored, size))
            reads = []

            def fstat(descriptor):
                info = real_fstat(descriptor)
                if info.st_size == size:
                    return SimpleNamespace(st_size=size, st_mtime=timestamp, st_mode=info.st_mode)
                return info

            def read(descriptor, count):
                reads.append((real_fstat(descriptor).st_size, count))
                return real_read(descriptor, count)

            with patch.object(subject.os, "fstat", side_effect=fstat), \
                 patch.object(subject.os, "read", side_effect=read), \
                 patch.object(subject, "emit", return_value=0) as emit:
                self.assertEqual(subject.main(list(map(str, (self.cache, self.source)))), 0)
                self.assertEqual(emit.call_args.args, (encode({"status": "match", "mode": "timestamp",
                                                               "mtime_match": True, "size_match": True}), 0))
            self.assertEqual(reads, [(16, 16)])

    def test_exact_magic_full_header_and_canonical_flags(self):
        real = self.compile_cache(py_compile.PycInvalidationMode.TIMESTAMP)
        wrong_magic = bytes([real[0] ^ 1]) + real[1:16]
        invalid_flags = (2, 4, 5, 7, 0x80000000)
        for payload in (wrong_magic, *(real[:length] for length in (0, 4, 8, 15)),
                        *(real[:4] + struct.pack("<I", flags) + real[8:16] for flags in invalid_flags)):
            self.cache.write_bytes(payload)
            self.expect(2, INVALID)

    def test_payload_remains_opaque_and_header_reads_never_cross_16_bytes(self):
        subject = self.import_subject()
        cache = self.compile_cache(py_compile.PycInvalidationMode.TIMESTAMP)
        report = {"status": "match", "mode": "timestamp", "mtime_match": True, "size_match": True}
        for suffix in (b"", b"\xff\x00private-opaque-payload\n" * (LIMIT // 8)):
            self.cache.write_bytes(cache[:16] + suffix)
            self.expect(0, report)
        real_read = os.read
        calls = []

        def short_read(descriptor, count):
            calls.append(count)
            return real_read(descriptor, min(3, count))

        with patch.object(subject.os, "read", side_effect=short_read), \
             patch.object(subject, "emit", return_value=0) as emit:
            self.assertEqual(subject.main(list(map(str, (self.cache, self.source)))), 0)
            self.assertEqual(emit.call_args.args, (encode(report), 0))
        self.assertEqual(calls, [16, 13, 10, 7, 4, 1])

    def test_hash_uses_exact_bytes_and_both_modes_cap_source(self):
        source = b"\xef\xbb\xbf\x00\xff\r\n" + b"x" * (LIMIT - 7)
        self.source.write_bytes(source)
        self.header(3, source_hash(source))
        self.expect(0, {"status": "match", "mode": "checked_hash", "hash_match": True})
        timestamp_cache = MAGIC_NUMBER + struct.pack("<III", 0, int(self.source.stat().st_mtime), len(source))
        hash_cache = self.cache.read_bytes()
        self.cache.write_bytes(timestamp_cache)
        self.expect(0, {"status": "match", "mode": "timestamp", "mtime_match": True, "size_match": True})
        with self.source.open("ab") as stream:
            stream.write(b"x")
        for cache in (timestamp_cache, hash_cache):
            self.cache.write_bytes(cache)
            self.expect(2, INVALID)

    def test_hash_rejects_source_metadata_change_on_open_descriptor(self):
        subject = self.import_subject()
        self.compile_cache(py_compile.PycInvalidationMode.CHECKED_HASH)
        size = self.source.stat().st_size
        real_fstat = os.fstat
        for size_delta, time_delta in ((1, 0), (0, 1)):
            changes = []

            def fstat(descriptor):
                info = real_fstat(descriptor)
                if info.st_size != size:
                    return info
                changes.append(descriptor)
                if len(changes) == 1:
                    return info
                return SimpleNamespace(st_size=size + size_delta, st_mtime_ns=info.st_mtime_ns + time_delta)

            with patch.object(subject.os, "fstat", side_effect=fstat), \
                 patch.object(subject, "emit", return_value=2) as emit:
                self.assertEqual(subject.main(list(map(str, (self.cache, self.source)))), 2)
                self.assertEqual(emit.call_args.args, (encode(INVALID), 2))
            self.assertEqual(len(changes), 2)
            self.assertEqual(changes[0], changes[1])

    def test_hash_read_stays_bounded_when_metadata_underreports_growth(self):
        subject = self.import_subject()
        self.header(1, source_hash(b""))
        self.source.write_bytes(b"x" * (LIMIT + 2))
        real_stat, real_fstat, real_read = os.stat, os.fstat, os.read
        reads = []

        def smaller(info):
            return SimpleNamespace(st_size=0, st_mode=info.st_mode, st_mtime_ns=info.st_mtime_ns)

        def fake_stat(path):
            return smaller(real_stat(path)) if path == str(self.source) else real_stat(path)

        def fake_fstat(descriptor):
            info = real_fstat(descriptor)
            return smaller(info) if info.st_size == LIMIT + 2 else info

        def read(descriptor, count):
            if real_fstat(descriptor).st_size == LIMIT + 2:
                reads.append(count)
            return real_read(descriptor, count)

        with patch.object(subject.os, "stat", side_effect=fake_stat), \
             patch.object(subject.os, "fstat", side_effect=fake_fstat), \
             patch.object(subject.os, "read", side_effect=read), \
             patch.object(subject, "emit", return_value=2) as emit:
            self.assertEqual(subject.main(list(map(str, (self.cache, self.source)))), 2)
            self.assertEqual(emit.call_args.args, (encode(INVALID), 2))
        self.assertEqual(sum(reads), LIMIT + 1)
        self.assertLess(max(reads), LIMIT)

    def test_lexical_rejection_for_either_argument_precedes_access(self):
        subject = self.import_subject()
        unsafe = ("https://private-host/file", "file:///private/file", r"/\host/share", r"\/host/share",
                  r"\Device\file", r"\??\file", r"\Global??\file", r"\a\..\SystemRoot\file",
                  "/./DosDevices/file", "/a/../gLoBaLrOoT/file", "C:relative", "C:/sample:stream",
                  "x/LPT³.py", "x/CON .py", "x. /file", "x/.. /file", "x/file.py/", "-")
        for spelling in unsafe:
            for index in (0, 1):
                paths = list(map(str, (self.cache, self.source)))
                paths[index] = spelling
                with patch.object(subject.os, "stat", side_effect=AssertionError("stat called")), \
                     patch.object(subject.os, "open", side_effect=AssertionError("open called")), \
                     patch.object(subject, "emit", return_value=2) as emit:
                    self.assertEqual(subject.main(paths), 2)
                    self.assertEqual(emit.call_args.args, (encode(INVALID), 2))

    def test_nonregular_replaced_descriptor_is_closed_before_read(self):
        subject = self.import_subject()
        self.compile_cache(py_compile.PycInvalidationMode.CHECKED_HASH)
        real_open, real_read = os.open, os.read
        for target in (self.cache, self.source):
            replaced = []

            def open_file(path, flags):
                if path == str(target):
                    replaced.append(real_open(os.devnull, flags))
                    return replaced[0]
                return real_open(path, flags)

            def read(descriptor, count):
                self.assertNotIn(descriptor, replaced)
                return real_read(descriptor, count)

            with patch.object(subject.os, "open", side_effect=open_file), \
                 patch.object(subject.os, "read", side_effect=read), \
                 patch.object(subject, "emit", return_value=2) as emit:
                self.assertEqual(subject.main(list(map(str, (self.cache, self.source)))), 2)
                self.assertEqual(emit.call_args.args, (encode(INVALID), 2))
            self.assertEqual(len(replaced), 1)
            with self.assertRaises(OSError):
                os.fstat(replaced[0])

    def test_usage_missing_and_nonregular_inputs(self):
        self.expect(2, INVALID, self.cache)
        self.expect(2, INVALID, self.cache, self.source, self.cache)
        self.expect(2, INVALID)
        self.expect(2, INVALID, self.root, self.source)
        self.compile_cache(py_compile.PycInvalidationMode.TIMESTAMP)
        self.expect(2, INVALID, self.cache, self.root)
        self.expect(0, b"Usage: python pyc_invalidation_audit.py PYC SOURCE\n", "--help")
        if hasattr(os, "mkfifo"):
            fifo = self.root / "private-fifo"
            os.mkfifo(fifo)
            self.expect(2, INVALID, self.cache, fifo)
            self.expect(2, INVALID, fifo, self.source)

    def test_closed_stdout_is_quiet_for_data_error_and_help(self):
        self.compile_cache(py_compile.PycInvalidationMode.TIMESTAMP)
        for args in ((self.cache, self.source), (self.cache,), ("--help",), ("-h",)):
            reader, writer = os.pipe()
            os.close(reader)
            with os.fdopen(writer, "wb") as pipe:
                result = self.run_cli(*args, stdout=pipe, stderr=subprocess.PIPE)
            self.assertEqual((result.returncode, result.stderr), (2, b""))


if __name__ == "__main__":
    unittest.main()
