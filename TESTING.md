# Testing

From the repository root, run `python -m unittest discover -s tests -v` and `python ci_checks.py` on CPython 3.11 or later. The test workflow runs both on Ubuntu and Windows.

The tests build real caches with each `py_compile` invalidation mode, then exercise the same-second same-size timestamp limitation, low-bit comparisons, unsupported flags, exact magic, opaque payloads and exact byte hashing. Other cases cover the source cap, mocked concurrent size and mtime changes, unsafe path spelling before input access, real descriptor substitution and quiet failure on closed stdout.

The example checker builds fixtures with the current interpreter, then verifies exact stdout, empty stderr and the documented exits. Generated caches live in `examples/generated`.
