#!/usr/bin/env python3
"""macho_insert_dylib.py - add or remove an LC_LOAD_DYLIB in a Mach-O binary.

Used by mv2-mem-patch-mac/install.sh to make Chrome's main executable load the
in-process MV2 patch dylib. It edits EVERY 64-bit slice of a thin or fat (universal)
Mach-O IN PLACE, writing the new load command into the zero padding that sits
between the end of the existing load commands and the first section's file data,
then bumping the header's ncmds / sizeofcmds. Because the edit stays inside a
slice's existing bytes, slice lengths never change and the fat table needs no
rewrite.

Chrome's main executable is a tiny stub with very little header padding (as little
as 24 bytes) - not enough for a full LC_LOAD_DYLIB (the 24-byte struct plus the
~53-char @executable_path path pads to ~80 bytes). When the padding is too small,
insert() RECLAIMS space by dropping load commands the stub does not need to run
(LC_SOURCE_VERSION, LC_UUID, LC_FUNCTION_STARTS, LC_DATA_IN_CODE - in that order,
least-useful first), compacting the load-command region after each drop. The stub
only maps the framework and jumps in; these commands carry symbolication/debug
metadata, not execution semantics, and the binary is re-signed ad-hoc afterwards
anyway. remove() does NOT restore them - install.sh keeps a stock backup for undo.

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
LC_REQ_DYLD = 0x80000000
# zero-fill section types carry no file bytes; their `offset` must not bound the
# header-padding region we insert into.
_ZEROFILL_TYPES = {0x1, 0xC, 0x11}  # S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL

# Load commands the main-exe stub does not need at runtime, safe to drop to reclaim
# header padding for our LC_LOAD_DYLIB. Value = drop priority (lower drops first);
# ordered least-useful → most, so we sacrifice the least metadata to make room.
LC_UUID = 0x1B
LC_SOURCE_VERSION = 0x2A
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
_DROPPABLE = {LC_SOURCE_VERSION: 0, LC_UUID: 1, LC_FUNCTION_STARTS: 2, LC_DATA_IN_CODE: 3}
_LC_NAME = {LC_UUID: "LC_UUID", LC_SOURCE_VERSION: "LC_SOURCE_VERSION",
            LC_FUNCTION_STARTS: "LC_FUNCTION_STARTS", LC_DATA_IN_CODE: "LC_DATA_IN_CODE"}


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


def _iter_commands(buf, base):
    """Yield (cmd_type_without_LC_REQ_DYLD, cmdsize, abs_offset) for each load
    command in the slice at `base`, in file order."""
    ncmds = _u32(buf, base + 16)
    sizeofcmds = _u32(buf, base + 20)
    p = base + 32
    end = base + 32 + sizeofcmds
    for _ in range(ncmds):
        if p + 8 > len(buf):
            raise MachoError("truncated load commands")
        cmd = _u32(buf, p)
        cmdsize = _u32(buf, p + 4)
        if cmdsize < 8 or p + cmdsize > end:
            raise MachoError("bad load-command size")
        yield cmd & ~LC_REQ_DYLD, cmdsize, p
        p += cmdsize


def _pick_droppable(buf, base):
    """Return (offset, cmdsize, cmd_type) of the best spare command to drop for
    space (lowest _DROPPABLE priority present), or None if the slice has none."""
    best = None
    for ctype, cmdsize, off in _iter_commands(buf, base):
        rank = _DROPPABLE.get(ctype)
        if rank is None:
            continue
        if best is None or rank < best[0]:
            best = (rank, off, cmdsize, ctype)
    return None if best is None else (best[1], best[2], best[3])


def _drop_command(buf, base, off, sz):
    """Delete the load command at absolute offset `off` (size `sz`): shift the
    trailing commands up over it, zero the freed tail, decrement ncmds/sizeofcmds.
    This shrinks lc_end, growing the header padding available for insertion."""
    ncmds = _u32(buf, base + 16)
    sizeofcmds = _u32(buf, base + 20)
    lc_end = base + 32 + sizeofcmds
    tail = bytes(buf[off + sz:lc_end])
    buf[off:off + len(tail)] = tail
    buf[lc_end - sz:lc_end] = b"\x00" * sz
    _set_u32(buf, base + 16, ncmds - 1)
    _set_u32(buf, base + 20, sizeofcmds - sz)


def insert(buf, dylib_path, notes=None):
    """Insert an LC_LOAD_DYLIB into every 64-bit slice. Idempotent per slice.
    If a slice lacks header padding, reclaim it by dropping non-essential load
    commands (see _DROPPABLE) before inserting; human-readable drop notes are
    appended to `notes` if given. Returns the number of slices actually modified."""
    cmd = _build_load_dylib(dylib_path)
    changed = 0
    for base in _iter_slices(buf):
        ncmds, sizeofcmds, min_content, loads, lc_end = _slice_info(buf, base)
        if any(path == dylib_path for _, _, path in loads):
            continue                                # already present - idempotent
        free = min_content - lc_end
        while free < len(cmd):
            victim = _pick_droppable(buf, base)     # highest-priority spare command
            if victim is None:
                raise MachoError(
                    "no room for a load command in slice @0x%X (need %d bytes of "
                    "header padding, have %d) and no spare load commands remain to "
                    "reclaim space" % (base, len(cmd), free))
            off, sz, ctype = victim
            _drop_command(buf, base, off, sz)
            if notes is not None:
                notes.append("slice @0x%X: dropped %s to reclaim %d bytes"
                             % (base, _LC_NAME.get(ctype, hex(ctype)), sz))
            ncmds, sizeofcmds, min_content, loads, lc_end = _slice_info(buf, base)
            free = min_content - lc_end
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

    _self_test_reclaim()


def _thin_tight(text_off, extra_cmds, text=b"\x90" * 0x40):
    """A thin arm64 MH64 whose first section starts at `text_off`, with `extra_cmds`
    (list of pre-built command byte blobs) after the __TEXT segment - used to force
    the header-padding-too-small path. Returns the file bytes."""
    MH64, SEG, ARM, VM = 0xFEEDFACF, 0x19, 0x0100000C, 0x100000000
    seg_sz = 72 + 80
    sect = struct.pack("<16s16sQQIIIIIII4x", b"__text", b"__TEXT", VM, len(text),
                       text_off, 4, 0, 0, 0, 0, 0)
    seg = struct.pack("<II16sQQQQiiII", SEG, seg_sz, b"__TEXT", VM, 0x1000, 0,
                      text_off + len(text), 7, 5, 1, 0)
    body = seg + sect + b"".join(extra_cmds)
    ncmds = 1 + len(extra_cmds)
    hdr = struct.pack("<IiiIIIII", MH64, ARM, 0, 2, ncmds, len(body), 0, 0)
    out = bytearray(hdr + body)
    if len(out) > text_off:
        raise AssertionError("fixture load commands overran text_off")
    out += b"\x00" * (text_off - len(out)) + text
    return bytes(out)


def _self_test_reclaim():
    """Insert must reclaim header space by dropping spare commands when padding is
    too small, and must fail cleanly when nothing can be reclaimed."""
    path = "@executable_path/../Frameworks/mv2/mv2-mem-patch.dylib"
    need = len(_build_load_dylib(path))          # ~80 bytes for this path

    uuid = struct.pack("<II", LC_UUID, 24) + b"\xAB" * 16
    srcv = struct.pack("<II", LC_SOURCE_VERSION, 16) + struct.pack("<Q", 0x10000)
    fnst = struct.pack("<IIII", LC_FUNCTION_STARTS, 16, 0, 0)
    dinc = struct.pack("<IIII", LC_DATA_IN_CODE, 16, 0, 0)
    spare = 24 + 16 + 16 + 16                     # total reclaimable

    # lc_end = 32 (hdr) + 152 (seg+sect) + spare; leave only 8 bytes of padding.
    text_off = 32 + 152 + spare + 8
    raw = bytearray(_thin_tight(text_off, [uuid, srcv, fnst, dinc]))
    text = bytes(raw[text_off:text_off + 0x40])
    assert not present(raw, path)

    notes = []
    assert insert(raw, path, notes) == 1, "reclaim insert should touch the slice"
    assert notes, "reclaim should have recorded at least one dropped command"
    assert present(raw, path), "load command should be present after reclaim"
    # Slice still parses, load commands do not overrun section data, __text intact.
    for base in _iter_slices(raw):
        nc, sc, mc, loads, end = _slice_info(raw, base)
        assert end <= mc, "load commands overran section data after reclaim"
        assert any(p == path for _, _, p in loads)
    assert raw[text_off:text_off + 0x40] == text, "__text disturbed by reclaim"
    # Idempotent even after reclaim.
    assert insert(raw, path, []) == 0, "second insert should be a no-op"

    # Only what was necessary was dropped: 8 free + 16 (srcv) + 24 (uuid) = 48 < need,
    # + 16 (fnst) = 64 >= need(80)? need is ~80 → also drops DATA_IN_CODE. Assert the
    # highest-priority survivor is dropped last: SOURCE_VERSION always goes first.
    assert "LC_SOURCE_VERSION" in notes[0], "least-useful command should drop first"

    # No spare commands + zero padding → clean MachoError, buffer left usable.
    raw2 = bytearray(_thin_tight(32 + 152, []))   # text right after seg, 0 padding
    try:
        insert(raw2, path)
        raise AssertionError("expected MachoError when nothing can be reclaimed")
    except MachoError as e:
        assert "no spare load commands" in str(e), f"unexpected error text: {e}"

    print("self-test OK: reclaim (priority order, text intact, idempotent), "
          "no-space error path")


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
    notes = []
    try:
        if mode == "present":
            return 0 if present(buf, dylib_path) else 1
        n = insert(buf, dylib_path, notes) if mode == "insert" else remove(buf, dylib_path)
    except MachoError as e:
        sys.stderr.write(f"error: {e}\n")
        return 3
    for line in notes:
        sys.stderr.write(f"note: {line}\n")
    if n:
        with open(binary, "wb") as f:
            f.write(buf)
    print(f"{mode}: {n} slice(s) changed in {binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
