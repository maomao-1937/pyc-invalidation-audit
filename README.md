# pyc-invalidation-audit

Compare the first 16 bytes of a CPython `.pyc` cache with its source. See whether the cache uses a timestamp, checked hash or unchecked hash, then share a JSON report containing only the mode and match results.

## Quickstart

Use the same CPython 3.11 or later version that generated the cache. The command uses the Python standard library.

```sh
python examples/make_fixtures.py
python pyc_invalidation_audit.py examples/generated/timestamp.pyc examples/sample.py
python pyc_invalidation_audit.py examples/generated/checked.pyc examples/sample.py
python pyc_invalidation_audit.py examples/generated/unchecked.pyc examples/generated/changed.py
python pyc_invalidation_audit.py examples/generated/invalid.pyc examples/sample.py
```

The fixture generator runs `py_compile` with each invalidation mode. The comparison commands exit `0`, `0`, `1`, and `2`. The unchecked-hash example produces this report.

```json
{"status":"mismatch","mode":"unchecked_hash","hash_match":false}
```

For your own cache, run `python pyc_invalidation_audit.py PYC SOURCE` with both file paths.

| Exit | Standard output |
| --- | --- |
| `0` | `match` JSON when the checked header fields agree. `--help` prints usage. |
| `1` | `mismatch` JSON when an mtime, size or hash check differs. |
| `2` | `{"status":"invalid"}` for invalid arguments, unreadable or unsupported input, or detected source changes during a hash read. Unavailable stdout returns `2` quietly. |

## What the comparison checks

- `timestamp` uses the source descriptor's whole-second modification time and size, each reduced to its low 32 bits. The `mtime_match` and `size_match` fields describe each check. A same-second source edit that preserves file size can still match.
- `checked_hash` and `unchecked_hash` use `importlib.util.source_hash` on the exact source bytes. Both modes report `hash_match` because this is an explicit offline comparison. An import may use a different hash-check policy. [PEP 552](https://peps.python.org/pep-0552/)
- Both inputs must be local regular files. The source limit is 8 MiB in every mode. Hash mode checks the source descriptor's size and nanosecond mtime before and after a bounded read to detect obvious changes.
- Cache headers must contain this interpreter's exact magic and use flag values `0`, `1`, or `3`. The audit reads only the header and treats the payload as opaque. It opens the inputs as data, and a `match` describes header consistency.
- Reports omit paths, timestamps, sizes, raw hashes and source content. The path checks apply to the spelling supplied on the command line. The filesystem resolves links and mounts.

## 中文说明

这个工具核对 CPython `.pyc` 文件前 16 字节和指定源码，输出缓存的失效模式及比较结果。使用与生成缓存时相同的 CPython 版本，最低 3.11。运行 `python pyc_invalidation_audit.py PYC SOURCE`，也可以用上面的命令生成并测试三种示例缓存。

时间戳模式比较源码修改时间的整数秒和字节数，使用两者的低 32 位。同一秒内修改源码且保持文件大小时，仍可能匹配。检查哈希和不检查哈希两种模式都会对源码原始字节计算哈希，因为这里做的是一次显式离线核对。两类输入必须是常规文件，源码上限为 8 MiB。

退出码 `0` 表示匹配或成功显示帮助，`1` 表示比较不匹配，`2` 表示输入、读取或输出失败。报告省略原始路径、时间戳、大小和哈希。源码按数据读取，缓存头之后的字节保留为不透明内容。

[测试](TESTING.md) · [调研](RESEARCH.md) · [MIT 许可证](LICENSE)
