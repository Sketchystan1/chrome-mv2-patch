#!/usr/bin/env python3
"""macho_insert_dylib.py - add or remove an LC_LOAD_DYLIB in a Mach-O binary.

Used by mv2-mem-patch-mac/install.sh to make Chrome's main executable load the
in-process MV2 patch dylib. It edits EVERY 64-bit slice of a thin or fat (universal)
Mach-O IN PLACE, writing the new load command into the zero padding that sits
between the end of the existing load commands and the first section's file data,
then bumping the header's ncmds / sizeofcmds. Because the edit stays inside a
slice's existing bytes, slice lengths never change and the fat table needs no
rewrite.

Only the target binary is ever modified; nothing else in the bundle is touched
(the installer keeps the Chrome Framework byte-for-byte stock for DRM). The edit
invalidates the code signature on purpose - install.sh re-signs afterwards.

    macho_insert_dylib.py insert  <dylib-load-path> <binary>
    macho_insert_dylib.py remove  <dylib-load-path> <binary>
    macho_insert_dylib.py present <dylib-load-path> <binary>   # exit 0 if present
    macho_insert_dylib.py --self-test

Stdlib only (Python 3.8+), same conventions as chrome-mv2.py's Mach-O parser.
"""
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF          # thin 64-bit, little-endian
FAT_MAGIC = 0xCAFEBABE            # fat header (big-endian), 32-bit offsets
FAT_MAGIC_64 = 0xCAFEBABF         # fat header (big-endian), 64-bit offsets
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
# zero-fill section types carry no file bytes; their `offset` must not bound the
# header-padding region we insert into.
_ZEROFILL_TYPES = {0x1, 0xC, 0x11}  # S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL


class MachoError(Exception):
    pass


def _u32(b, off):
    return int.from_bytes(b[off:off + 4], "little")


def _set_u32(b, off, val):
    struct.pack_into("<I", b, off, val)


def _build_load_dylib(path):
    """Bytes of one LC_LOAD_DYLIB command for `path` (cmdsize 8-byte aligned)."""
    name = path.encode("utf-8") + b"\x00"
    name_off = 24                                   # header fields before the string
    cmdsize = (name_off + len(name) + 7) & ~7       # pad to 8 for 64-bit Mach-O
    cmd = bytearray(cmdsize)
    struct.pack_into("<IIIIII", cmd, 0,
                     LC_LOAD_DYLIB, cmdsize, name_off,
                     2,   # timestamp
                     0,   # current_version
                     0)   # compatibility_version
    cmd[name_off:name_off + len(name)] = name
    return bytes(cmd)


def _iter_slices(buf):
    """Yield the absolute file offset of every 64-bit thin Mach-O slice.

    Handles thin (FEEDFACF) and fat (CAFEBABE / CAFEBABF) files. 32-bit and
    big-endian slices are skipped - Chrome is 64-bit only."""
    if len(buf) < 4:
        raise MachoError("file too small to be Mach-O")
    be = int.from_bytes(buf[0:4], "big")
    le = int.from_bytes(buf[0:4], "little")
    if be in (FAT_MAGIC, FAT_MAGIC_64):
        is64 = be == FAT_MAGIC_64
        nfat = int.from_bytes(buf[4:8], "big")
        if nfat < 1 or nfat > 32:
            raise MachoError("implausible fat arch count")
        entry = 32 if is64 else 20
        off = 8
        for _ in range(nfat):
            if off + entry > len(buf):
                break
            soff = (int.from_bytes(buf[off + 8:off + 16], "big") if is64
                    else int.from_bytes(buf[off + 8:off + 12], "big"))
            off += entry
            if soff + 4 <= len(buf) and _u32(buf, soff) == MH_MAGIC_64:
                yield soff
    elif le == MH_MAGIC_64:
        yield 0
    else:
        raise MachoError("not a Mach-O (or 32-bit / big-endian, which Chrome isn't)")


def _slice_info(buf, base):
    """(ncmds, sizeofcmds, min_content_off_abs, existing_load_paths[list of (cmd_off, cmdsize, path)]).

    min_content_off_abs is the absolute file offset of the first real section
    data - the upper bound of the header-padding region."""
    ncmds = _u32(buf, base + 16)
    sizeofcmds = _u32(buf, base + 20)
    min_content = None
    loads = []
    p = base + 32
    end = base + 32 + sizeofcmds
    for _ in range(ncmds):
        if p + 8 > len(buf):
            raise MachoError("truncated load commands")
        cmd = _u32(buf, p)
        cmdsize = _u32(buf, p + 4)
        if cmdsize < 8 or p + cmdsize > len(buf):
            raise MachoError("bad load-command size")
        if cmd == LC_SEGMENT_64:
            nsects = _u32(buf, p + 64)
            sp = p + 72
            for _ in range(nsects):
                if sp + 80 > len(buf):
                    raise MachoError("truncated sections")
                sec_off = _u32(buf, sp + 48)
                sec_type = _u32(buf, sp + 64) & 0xFF
                if sec_off > 0 and sec_type not in _ZEROFILL_TYPES:
                    abs_off = base + sec_off
                    if min_content is None or abs_off < min_content:
                        min_content = abs_off
                sp += 80
        elif cmd == LC_LOAD_DYLIB:
            name_off = _u32(buf, p + 8)
            raw = buf[p + name_off:p + cmdsize]
            nul = raw.find(b"\x00")
            path = (raw[:nul] if nul >= 0 else raw).decode("utf-8", "replace")
            loads.append((p, cmdsize, path))
        p += cmdsize
    if min_content is None:
        min_content = end                           # no file-backed sections: no room
    return ncmds, sizeofcmds, min_content, loads, end


def insert(buf, dylib_path):
    """Insert an LC_LOAD_DYLIB into every 64-bit slice. Idempotent per slice.
    Returns the number of slices actually modified."""
    cmd = _build_load_dylib(dylib_path)
    changed = 0
    for base in _iter_slices(buf):
        ncmds, sizeofcmds, min_content, loads, lc_end = _slice_info(buf, base)
        if any(path == dylib_path for _, _, path in loads):
            continue                                # already present - idempotent
        free = min_content - lc_end
        if free < len(cmd):
            raise MachoError(
                "no room for a load command in slice @0x%X (need %d bytes of "
                "header padding, have %d)" % (base, len(cmd), free))
        buf[lc_end:lc_end + len(cmd)] = cmd
        _set_u32(buf, base + 16, ncmds + 1)
        _set_u32(buf, base + 20, sizeofcmds + len(cmd))
        changed += 1
    return changed


def remove(buf, dylib_path):
    """Remove matching LC_LOAD_DYLIB commands from every slice. Returns count."""
    changed = 0
    for base in _iter_slices(buf):
        ncmds, sizeofcmds, _min, loads, lc_end = _slice_info(buf, base)
        match = next(((o, sz) for o, sz, path in loads if path == dylib_path), None)
        if not match:
            continue
        cmd_off, cmdsize = match
        # shift the trailing load commands up over the removed one, zero the tail
        tail = bytes(buf[cmd_off + cmdsize:lc_end])
        buf[cmd_off:cmd_off + len(tail)] = tail
        buf[lc_end - cmdsize:lc_end] = b"\x00" * cmdsize
        _set_u32(buf, base + 16, ncmds - 1)
        _set_u32(buf, base + 20, sizeofcmds - cmdsize)
        changed += 1
    return changed


def present(buf, dylib_path):
    for base in _iter_slices(buf):
        _n, _s, _m, loads, _e = _slice_info(buf, base)
        if any(path == dylib_path for _, _, path in loads):
            return True
    return False


# --------------------------------------------------------------------------- #
def _self_test():
    """Round-trip against the repo's synthetic fat Mach-O fixture."""
    import os
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _testutil as T  # noqa

    tmp = str(T.REPO / "_scratch" / "insert_dylib_selftest.macho")
    Path(tmp).parent.mkdir(parents=True, exist_ok=True)
    T.make_fat_macho(tmp)
    path = "@executable_path/../Frameworks/mv2/mv2-mem-patch.dylib"

    raw = bytearray(Path(tmp).read_bytes())
    slices_before = list(_iter_slices(raw))
    assert len(slices_before) == 2, "fixture should have 2 slices"

    n = insert(raw, path)
    assert n == 2, f"expected 2 slices patched, got {n}"
    assert present(raw, path), "path should be present after insert"
    # ncmds bumped and slice still parses cleanly in every slice
    for base in _iter_slices(raw):
        nc, sc, mc, loads, end = _slice_info(raw, base)
        assert any(p == path for _, _, p in loads), "load cmd missing in slice"
        assert end <= mc, "load commands overran section data"
    # idempotent: a second insert changes nothing
    assert insert(raw, path) == 0, "insert should be idempotent"
    # __text bytes (the fixture's gate) must be untouched by the edit
    orig = bytearray(Path(tmp).read_bytes())
    for base in _iter_slices(orig):
        # section data starts at slice+0x200 in the fixture
        assert raw[base + 0x200:base + 0x260] == orig[base + 0x200:base + 0x260], \
            "section data was disturbed"

    # remove restores ncmds and drops the command
    assert remove(raw, path) == 2, "remove should touch 2 slices"
    assert not present(raw, path), "path should be gone after remove"
    for base in _iter_slices(raw):
        nc, sc, mc, loads, end = _slice_info(raw, base)
        assert not any(p == path for _, _, p in loads)

    os.remove(tmp)
    print("self-test OK: insert (x2, idempotent), section data intact, remove")


def main(argv):
    if len(argv) == 2 and argv[1] == "--self-test":
        _self_test()
        return 0
    if len(argv) != 4 or argv[1] not in ("insert", "remove", "present"):
        sys.stderr.write(__doc__)
        return 2
    mode, dylib_path, binary = argv[1], argv[2], argv[3]
    with open(binary, "rb") as f:
        buf = bytearray(f.read())
    try:
        if mode == "present":
            return 0 if present(buf, dylib_path) else 1
        n = insert(buf, dylib_path) if mode == "insert" else remove(buf, dylib_path)
    except MachoError as e:
        sys.stderr.write(f"error: {e}\n")
        return 3
    if n:
        with open(binary, "wb") as f:
            f.write(buf)
    print(f"{mode}: {n} slice(s) changed in {binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
