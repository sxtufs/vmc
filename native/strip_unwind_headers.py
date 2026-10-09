#!/usr/bin/env python3
"""Neutralize unwind program headers after release section stripping.

llvm-objcopy removes the section payloads but preserves PT_GNU_EH_FRAME and
PT_ARM_EXIDX program-header records. Once the corresponding sections have been
removed, those records must become PT_NULL as well; otherwise readelf and the
Android loader still see an unwind segment.
"""

from pathlib import Path
import struct
import sys

PT_NULL = 0
PT_GNU_EH_FRAME = 0x6474E550
PT_ARM_EXIDX = 0x70000001
ELF_MAGIC = b"\x7fELF"


def read_header(data: bytearray) -> tuple[int, int, int]:
    if data[:4] != ELF_MAGIC:
        raise ValueError("not an ELF file")
    if data[5] != 1:
        raise ValueError("only little-endian ELF files are supported")

    elf_class = data[4]
    if elf_class == 1:
        phoff = struct.unpack_from("<I", data, 28)[0]
        phentsize = struct.unpack_from("<H", data, 42)[0]
        phnum = struct.unpack_from("<H", data, 44)[0]
    elif elf_class == 2:
        phoff = struct.unpack_from("<Q", data, 32)[0]
        phentsize = struct.unpack_from("<H", data, 54)[0]
        phnum = struct.unpack_from("<H", data, 56)[0]
    else:
        raise ValueError(f"unsupported ELF class: {elf_class}")

    return phoff, phentsize, phnum


def strip_unwind_headers(path: Path) -> int:
    data = bytearray(path.read_bytes())
    phoff, phentsize, phnum = read_header(data)
    if phentsize < 4:
        raise ValueError("invalid ELF program-header size")

    removed = 0
    for index in range(phnum):
        start = phoff + index * phentsize
        end = start + phentsize
        if start < 0 or end > len(data):
            raise ValueError("program header extends beyond the ELF file")
        p_type = struct.unpack_from("<I", data, start)[0]
        if p_type in (PT_GNU_EH_FRAME, PT_ARM_EXIDX):
            data[start:end] = b"\0" * phentsize
            removed += 1

    if removed:
        path.write_bytes(data)
    return removed


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} ELF", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    try:
        removed = strip_unwind_headers(path)
    except (OSError, ValueError, struct.error) as exc:
        print(f"ERROR: {path}: {exc}", file=sys.stderr)
        return 1

    print(f"{path}: neutralized {removed} unwind program header(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
