"""Dump ELF function symbols as nm -S style lines: "<addr> <size> T <name>".

A streaming, low-memory research aid for large chrome.debug files. Names remain
mangled so Chromium identifiers can be searched without demangling and sorting
the entire file. The native auto patcher does not use these symbols.

    python scripts/symbols_from_elf.py <elf-with-symbols> [out.txt]"""

import struct
import sys
from pathlib import Path

STT_FUNC = 2


def sections(data):
    """{name: {type, off, size, link, entsize, idx}} plus (shoff, shentsize)."""
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    hdr = shoff + shstrndx * shentsize
    str_off = struct.unpack_from("<Q", data, hdr + 0x18)[0]
    str_size = struct.unpack_from("<Q", data, hdr + 0x20)[0]
    strtab = data[str_off:str_off + str_size]
    out = {}
    for i in range(shnum):
        sh = shoff + i * shentsize
        no = struct.unpack_from("<I", data, sh)[0]
        name = strtab[no:strtab.find(b"\x00", no)].decode("latin1")
        out[name] = {
            "type": struct.unpack_from("<I", data, sh + 4)[0],
            "off": struct.unpack_from("<Q", data, sh + 0x18)[0],
            "size": struct.unpack_from("<Q", data, sh + 0x20)[0],
            "link": struct.unpack_from("<I", data, sh + 0x28)[0],
            "entsize": struct.unpack_from("<Q", data, sh + 0x38)[0],
            "idx": i,
        }
    return out, shoff, shentsize


def dump(path, out_path=None):
    data = Path(path).read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not a little-endian ELF64")
    secs, shoff, shentsize = sections(data)

    sym = secs.get(".symtab") or secs.get(".dynsym")
    if not sym:
        raise ValueError("no .symtab/.dynsym section")

    # the symbol table's sh_link names its associated string table
    lh = shoff + sym["link"] * shentsize
    st_off = struct.unpack_from("<Q", data, lh + 0x18)[0]
    st_size = struct.unpack_from("<Q", data, lh + 0x20)[0]
    strs = data[st_off:st_off + st_size]

    lines = []
    for i in range(sym["size"] // 24):
        e = sym["off"] + i * 24
        name_off, info = struct.unpack_from("<IB", data, e)
        if info & 0xF != STT_FUNC:
            continue
        value, size = struct.unpack_from("<QQ", data, e + 8)
        if not value:
            continue
        name = strs[name_off:strs.find(b"\x00", name_off)].decode("latin1")
        if name:
            lines.append(f"{value:016x} {size:016x} T {name}")

    text = "\n".join(lines) + "\n"
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
        print(f"{len(lines)} FUNC symbols -> {out_path}")
    else:
        sys.stdout.write(text)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    try:
        dump(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
