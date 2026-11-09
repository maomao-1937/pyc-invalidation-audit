"""Verify the documented examples and their exact output."""

import json
from pathlib import Path
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parent
    checks = json.loads((root / "checks.json").read_text(encoding="utf-8"))
    for check in checks:
        result = subprocess.run([sys.executable, *check["args"]], cwd=root, capture_output=True, timeout=15)
        expected = b""
        if "report" in check:
            expected = json.dumps(check["report"], separators=(",", ":")).encode("ascii") + b"\n"
        if (result.returncode, result.stdout, result.stderr) != (check["exit"], expected, b""):
            print(f"FAIL {check['name']} (exit {result.returncode})", file=sys.stderr)
            return 1
        print(f"PASS {check['name']} (exit {result.returncode})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
