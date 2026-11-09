"""Compare a PEP 552 cache header with an explicitly supplied source file."""

from contextlib import contextmanager
from importlib.util import MAGIC_NUMBER, source_hash
import json
import os
import posixpath
import re
import stat
import struct
import sys


HEADER_SIZE = 16
SOURCE_LIMIT = 8 * 1024 * 1024
BLOCK_SIZE = 64 * 1024
MODES = {0: "timestamp", 1: "unchecked_hash", 3: "checked_hash"}
INVALID = b'{"status":"invalid"}\n'
DEVICE = re.compile(r"CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[0-9¹²³]")
NATIVE_ROOTS = {"??", "device", "dosdevices", "global??", "systemroot", "globalroot"}


def require_local(path):
    spelling = path.replace("\\", "/")
    if not spelling or spelling == "-" or spelling.startswith("//") or spelling.endswith("/"):
        raise ValueError
    if any(ord(char) < 32 for char in path):
        raise ValueError
    if spelling.startswith("/"):
        for form in (spelling, posixpath.normpath(spelling)):
            root = form[1:].partition("/")[0].rstrip(" .").lower()
            if root in NATIVE_ROOTS:
                raise ValueError
    tail = spelling[2:] if re.match(r"^[A-Za-z]:/", spelling) else spelling
    if ":" in tail:
        raise ValueError
    for part in tail.split("/"):
        if part in {"", ".", ".."}:
            continue
        stem = part.partition(".")[0].rstrip(" ").upper()
        if part.endswith((" ", ".")) or DEVICE.fullmatch(stem):
            raise ValueError


def require_regular(info, limit):
    if not stat.S_ISREG(info.st_mode) or info.st_size < 0:
        raise ValueError
    if limit is not None and info.st_size > limit:
        raise ValueError


@contextmanager
def open_regular(path, limit=None):
    require_regular(os.stat(path), limit)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        require_regular(info, limit)
        yield descriptor, info
    finally:
        os.close(descriptor)


def read_prefix(descriptor, limit):
    data = bytearray()
    while len(data) < limit:
        chunk = os.read(descriptor, min(BLOCK_SIZE, limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return data


def read_header(path):
    with open_regular(path) as (descriptor, _):
        header = read_prefix(descriptor, HEADER_SIZE)
    if len(header) != HEADER_SIZE or header[:4] != MAGIC_NUMBER:
        raise ValueError
    flags, = struct.unpack_from("<I", header, 4)
    if flags not in MODES:
        raise ValueError
    return flags, header[8:]


def compare(source, flags, stored):
    with open_regular(source, SOURCE_LIMIT) as (descriptor, before):
        if flags == 0:
            mtime, size = struct.unpack("<II", stored)
            return {
                "mtime_match": mtime == (int(before.st_mtime) & 0xffffffff),
                "size_match": size == (before.st_size & 0xffffffff),
            }

        data = read_prefix(descriptor, SOURCE_LIMIT + 1)
        after = os.fstat(descriptor)
        if len(data) > SOURCE_LIMIT or len(data) != before.st_size or before.st_size != after.st_size:
            raise ValueError
        if before.st_mtime_ns != after.st_mtime_ns:
            raise ValueError
        return {"hash_match": stored == source_hash(data)}


def emit(data, code):
    remaining = memoryview(data)
    try:
        while remaining:
            written = os.write(1, remaining)
            if written <= 0:
                return 2
            remaining = remaining[written:]
    except OSError:
        return 2
    return code


def main(args):
    if args in (["--help"], ["-h"]):
        return emit(b"Usage: python pyc_invalidation_audit.py PYC SOURCE\n", 0)
    try:
        if sys.implementation.name != "cpython" or sys.version_info < (3, 11):
            raise ValueError
        cache, source = args
        require_local(cache)
        require_local(source)
        flags, stored = read_header(cache)
        fields = compare(source, flags, stored)
    except (OSError, ValueError):
        return emit(INVALID, 2)

    match = all(fields.values())
    report = {"status": "match" if match else "mismatch", "mode": MODES[flags], **fields}
    data = json.dumps(report, separators=(",", ":")).encode("ascii") + b"\n"
    return emit(data, int(not match))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
