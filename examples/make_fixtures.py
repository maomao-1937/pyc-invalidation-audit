"""Create examples with the running CPython's exact cache magic."""

from pathlib import Path
import py_compile
import struct


def main():
    directory = Path(__file__).resolve().parent
    source = directory / "sample.py"
    generated = directory / "generated"
    generated.mkdir(exist_ok=True)

    for name, mode in (
        ("timestamp", py_compile.PycInvalidationMode.TIMESTAMP),
        ("checked", py_compile.PycInvalidationMode.CHECKED_HASH),
        ("unchecked", py_compile.PycInvalidationMode.UNCHECKED_HASH),
    ):
        cache = generated / (name + ".pyc")
        py_compile.compile(str(source), cfile=str(cache), doraise=True, invalidation_mode=mode)

    generated.joinpath("changed.py").write_bytes(source.read_bytes().replace(b"41", b"42"))
    header = generated.joinpath("timestamp.pyc").read_bytes()[:16]
    generated.joinpath("invalid.pyc").write_bytes(header[:4] + struct.pack("<I", 2) + header[8:])


if __name__ == "__main__":
    main()
