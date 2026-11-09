# Research

PEP 552 specifies the four-word header, the timestamp form and the checked and unchecked hash modes. `py_compile` can produce all three with an explicit invalidation mode. The cache magic is interpreter-specific, so the bundled examples generate caches locally. [PEP 552](https://peps.python.org/pep-0552/), [Python `py_compile` documentation](https://docs.python.org/3/library/py_compile.html)

A CPython issue reproduces an edited module whose code stays cached when both the file size and whole-second modification time match. The timestamp example in this project's tests deliberately changes equal-size source content within the same second. A uv issue concerns different compiled output bytes. That highlights a separate comparison boundary because this tool checks the header's relationship to one source file. [CPython issue 120932](https://github.com/python/cpython/issues/120932), [uv issue 10619](https://github.com/astral-sh/uv/issues/10619)
