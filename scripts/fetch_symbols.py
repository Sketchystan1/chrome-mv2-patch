"""Fetch the debug symbols matching a Chrome binary, for MV2 gate derivation.

Dispatches on the target's own file magic:

  PE  (chrome.dll) -> derive the RSDS CodeView key and download the matching PDB
                      from the Chromium symbol server. Handles PE32 (x86) and
                      PE32+ (x64).
  ELF (chrome)     -> read build-id + .gnu_debuglink, stream debug-info/
                      chrome.debug out of the per-version debug-info zip via HTTP
                      range requests, and verify build-id + CRC both ways.
  Mach-O (macOS)   -> for each slice, stream the per-arch dSYM archive from
                      dl.google.com/chrome/mac/{channel}/dsym/, keep ONLY its
                      LC_SYMTAB (not the multi-GB DWARF), verify the slice
                      LC_UUID, and emit nm-style `addr type name` lines. dSYMs
                      are UUID-matched to CONSUMER Chrome (unwrap the .dmg), not
                      Chrome for Testing. Needs --chrome-version.

Downloads land in _scratch/ by default (gitignored) — override with --out. Only
the one wanted zip member (ELF) / the symtab slice (Mach-O) is kept; nothing is
buffered whole. Pure stdlib: no unzip, no requests, no external modules.

Usage:
    python scripts/fetch_symbols.py <chrome.dll|chrome> [--out DIR] [--chrome-version V]
    python scripts/fetch_symbols.py "<Google Chrome Framework>" --chrome-version 151.0.7922.138

Then feed the result to the rest of the pipeline:
    Windows: python scripts/symbols_from_pdb.py <chrome.dll> --symdir _scratch --json _scratch/syms.json
    Linux:   python scripts/symbols_from_elf.py _scratch/chrome.debug _scratch/syms.txt
    macOS:   fetch_symbols writes _scratch/mac-<arch>-syms.txt directly
    all   -> python scripts/derive_milestone.py <binary> --symbols … --name <ver> --json
"""

import argparse
import binascii
import bz2
import io
import re
import struct
import sys
import tarfile
import urllib.error
import urllib.request
import zlib
from pathlib import Path, PureWindowsPath

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "_scratch"

PDB_SYMBOL_BASE = "https://chromium-browser-symsrv.commondatastorage.googleapis.com"

# These payloads are gigabytes (a win-arm64 chrome.dll.pdb is over 5 GB, and
# chrome.debug inflates to ~1.4 GiB), so a dropped connection part-way through is
# routine rather than exceptional. Resume instead of restarting.
MAX_RESUME_ATTEMPTS = 12
DEBUG_SYMBOL_BASE = "https://edgedl.me.gvt1.com/chrome/linux/symbols"
DEBUG_MEMBER = "debug-info/chrome.debug"

# ===========================================================================
# Mach-O (macOS) -> dSYM symbol table
# ===========================================================================
DSYM_BASE = "https://dl.google.com/chrome/mac/{channel}/dsym/googlechrome-{version}-{arch}-dsym.tar.bz2"
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
LC_SYMTAB = 0x2
LC_UUID_ = 0x1B
CPU_BY_ARCH = {"arm64": 0x0100000C}
GATE_KW = ("isextensionaffected", "shouldblockextension", "onextensionsystemready",
           "maybereenableextension", "usermayinstall", "mustremaindisabled")


def _macho_slices(data):
    """[(container, arch, base, uuid)] for a fat or thin Mach-O file's slices."""
    be = struct.unpack_from(">I", data, 0)[0]
    heads = []
    if be in (FAT_MAGIC, FAT_MAGIC_64):
        is64 = be == FAT_MAGIC_64
        nfat = struct.unpack_from(">I", data, 4)[0]
        entry = 32 if is64 else 20
        off = 8
        for _ in range(nfat):
            cpu = struct.unpack_from(">I", data, off)[0]
            base = struct.unpack_from(">Q" if is64 else ">I", data, off + 8)[0]
            heads.append((cpu, base))
            off += entry
    else:
        heads.append((struct.unpack_from("<I", data, 4)[0], 0))
    out = []
    for cpu, base in heads:
        arch = next((a for a, c in CPU_BY_ARCH.items() if c == cpu), None)
        if arch is None:
            continue
        out.append(("macho-arm64", arch, base,
                    _macho_slice_uuid(data, base)))
    return out


def _macho_slice_uuid(data, base):
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    p = base + 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, p)
        if cmd == LC_UUID_:
            return data[p + 8:p + 24].hex()
        p += cmdsize
    return None


def _read_exact(f, n):
    b = bytearray()
    while len(b) < n:
        c = f.read(n - len(b))
        if not c:
            break
        b += c
    return bytes(b)


def _dsym_symbols(version, arch, expect_uuid, out_path, channel="stable"):
    """Stream the dSYM, keep only the DWARF Mach-O's LC_SYMTAB, and write nm-style
    lines for the gate functions. Returns True on success."""
    url = DSYM_BASE.format(channel=channel, version=version, arch=arch)
    print(f"Streaming dSYM: {url}")
    want_cpu = CPU_BY_ARCH[arch]
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=300)
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        print(f"  dSYM download failed: {e}")
        return False
    with resp:
        tar = tarfile.open(fileobj=resp, mode="r|bz2")
        member = next((m for m in tar if m.isfile() and "/DWARF/" in m.name), None)
        if member is None:
            print("  no DWARF member in dSYM"); return False
        print(f"  member: {member.name} ({member.size} B)")
        f = tar.extractfile(member)
        head = _read_exact(f, 8192)
        pos = len(head)
        be = struct.unpack_from(">I", head, 0)[0]
        base = 0
        if be in (FAT_MAGIC, FAT_MAGIC_64):
            is64 = be == FAT_MAGIC_64
            nfat = struct.unpack_from(">I", head, 4)[0]
            entry = 32 if is64 else 20
            o = 8
            for _ in range(nfat):
                cpu = struct.unpack_from(">I", head, o)[0]
                soff = struct.unpack_from(">Q" if is64 else ">I", head, o + 8)[0]
                if cpu == want_cpu:
                    base = soff
                o += entry
        return _dsym_parse_symtab(f, head, pos, base, expect_uuid, arch, out_path)


def _dsym_parse_symtab(f, head, pos, base, expect_uuid, arch, out_path):
    def stream_to(target):
        nonlocal pos
        while pos < target:
            c = f.read(min(1 << 20, target - pos))
            if not c:
                raise ValueError("stream ended early while skipping")
            pos += len(c)

    if base >= len(head):
        stream_to(base)
        hdr = _read_exact(f, 32); pos += 32; have = b""
    else:
        hdr = head[base:base + 32]; have = head[base + 32:]
    if struct.unpack_from("<I", hdr, 0)[0] != MH_MAGIC_64:
        print("  dSYM slice is not a 64-bit Mach-O"); return False
    ncmds, sizeofcmds = struct.unpack_from("<II", hdr, 16)
    need = sizeofcmds - len(have)
    extra = _read_exact(f, need) if need > 0 else b""
    lc = (have + extra)[:sizeofcmds]
    pos = base + 32 + sizeofcmds if base >= len(head) else len(head) + len(extra)

    uuid = None; symoff = nsyms = stroff = strsize = 0
    p = 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", lc, p)
        if cmd == LC_UUID_:
            uuid = lc[p + 8:p + 24].hex()
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", lc, p + 8)
        p += cmdsize
    print(f"  dSYM uuid={uuid} (expect {expect_uuid}); nsyms={nsyms}")
    if expect_uuid and uuid != expect_uuid:
        print("  [-] dSYM UUID does not match the target framework slice; refusing.")
        return False

    sym_abs = (base + symoff, base + symoff + nsyms * 16)
    str_abs = (base + stroff, base + stroff + strsize)
    hi = max(sym_abs[1], str_abs[1])
    symbuf = bytearray(nsyms * 16); strbuf = bytearray(strsize)
    while pos < hi:
        chunk = f.read(min(1 << 20, hi - pos))
        if not chunk:
            raise ValueError("stream ended early before symtab/strtab")
        cs, ce = pos, pos + len(chunk)
        for (a, b), buf in ((sym_abs, symbuf), (str_abs, strbuf)):
            s = max(a, cs); e = min(b, ce)
            if s < e:
                buf[s - a:e - a] = chunk[s - cs:e - cs]
        pos = ce

    def name_at(strx):
        end = strbuf.find(b"\x00", strx)
        return bytes(strbuf[strx:end]).decode("latin1", "replace") if end >= 0 else ""

    rows = []
    for i in range(nsyms):
        strx, _t, _s, _d, n_value = struct.unpack_from("<IBBHQ", symbuf, i * 16)
        if n_value == 0 or strx == 0:
            continue
        nm = name_at(strx)
        if any(k in nm.lower() for k in GATE_KW):
            rows.append((n_value, nm))
    rows.sort()
    with open(out_path, "w", encoding="utf-8") as o:
        for addr, nm in rows:
            o.write(f"{addr:x} t {nm}\n")
    print(f"  [+] wrote {len(rows)} gate-name symbol(s) -> {out_path}")
    return len(rows) > 0


def fetch_dsyms(data, out_dir, version):
    if not version:
        print("Error: macOS dSYM fetch needs --chrome-version (e.g. 151.0.7922.138).")
        return False
    ok = False
    for container, arch, base, uuid in _macho_slices(data):
        out_path = Path(out_dir) / f"mac-{arch}-syms.txt"
        print(f"\n== {container} ({arch}), slice uuid {uuid} ==")
        # A given version's dSYM lives under exactly one channel's path; try the
        # usual channels in turn (stable is by far the common case, but a beta-only
        # build -- e.g. a milestone still rolling to stable -- is under /beta/).
        for channel in ("stable", "beta", "dev", "canary"):
            if _dsym_symbols(version, arch, uuid, str(out_path), channel=channel):
                ok = True
                break
    return ok



# ---------------------------------------------------------------------------
# Shared: a one-line progress printer for streamed downloads.
# ---------------------------------------------------------------------------
def _progress(n, total, label="  "):
    if total > 0:
        sys.stdout.write(f"\r{label}{n * 100 // total:3d}%  {n >> 20}/{total >> 20} MiB")
    else:
        sys.stdout.write(f"\r{label}{n >> 20} MiB")
    sys.stdout.flush()


# ===========================================================================
# PE -> PDB
# ===========================================================================
def codeview_info(data):
    """(pdb_name, guid+age key) from the PE debug directory's RSDS record,
    falling back to a raw RSDS scan. Handles PE32 and PE32+."""
    info = _codeview_from_debug_dir(data)
    if info:
        return info
    pos = 0
    while True:
        i = data.find(b"RSDS", pos)
        if i < 0:
            break
        parsed = _parse_rsds(data, i)
        if parsed and parsed[0].lower().endswith(".pdb"):
            return parsed
        pos = i + 4
    raise ValueError("CodeView RSDS debug record not found in the PE")


def _codeview_from_debug_dir(data):
    if len(data) < 0x40:
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew < 0 or e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    size_opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:      # PE32+  -> data dirs start after 112-byte fixed opt hdr
        debug_dir_off = opt + 112 + 6 * 8
    elif magic == 0x10B:    # PE32   -> after 96-byte fixed opt hdr
        debug_dir_off = opt + 96 + 6 * 8
    else:
        return None
    if debug_dir_off + 8 > len(data):
        return None
    debug_rva, debug_size = struct.unpack_from("<II", data, debug_dir_off)

    sec_off = opt + size_opt
    secs = []
    for i in range(num_sections):
        s = sec_off + i * 40
        if s + 40 > len(data):
            return None
        v_size, v_addr, _raw_size, raw_ptr = struct.unpack_from("<IIII", data, s + 8)
        secs.append((v_addr, v_size, raw_ptr))

    def rva_to_off(rva):
        for v_addr, v_size, raw_ptr in secs:
            if v_addr <= rva < v_addr + v_size:
                return raw_ptr + (rva - v_addr)
        return None

    debug_file_off = rva_to_off(debug_rva)
    if debug_file_off is None:
        return None
    for i in range(debug_size // 28):
        e = debug_file_off + i * 28
        if e + 28 > len(data):
            break
        d_type = struct.unpack_from("<I", data, e + 12)[0]
        addr_rva, ptr = struct.unpack_from("<II", data, e + 20)
        if d_type != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        cv_off = ptr if ptr != 0 else rva_to_off(addr_rva)
        if cv_off is not None and data[cv_off:cv_off + 4] == b"RSDS":
            parsed = _parse_rsds(data, cv_off)
            if parsed:
                return parsed
    return None


def _parse_rsds(data, off):
    if off + 24 > len(data):
        return None
    d1, d2, d3 = struct.unpack_from("<IHH", data, off + 4)
    d4 = data[off + 12:off + 20]
    age = struct.unpack_from("<I", data, off + 20)[0]
    end = data.find(b"\x00", off + 24)
    if end < 0:
        end = len(data)
    # The RSDS record stores a Windows path (e.g. C:\...\chrome.dll.pdb). Strip it
    # with PureWindowsPath so both `\` and `/` separators are handled even when
    # this runs on a POSIX host - PurePosixPath.name would keep the whole string.
    name = PureWindowsPath(data[off + 24:end].decode("utf-8", errors="ignore")).name
    if not name or name == ".":
        return None
    guid = f"{d1:08X}{d2:04X}{d3:04X}{d4.hex().upper()}"
    return name, f"{guid}{age:X}"


def fetch_pdb(data, path, out_dir):
    print(f"Extracting debug info from {Path(path).name}...")
    pdb_name, key = codeview_info(data)
    url = f"{PDB_SYMBOL_BASE}/{pdb_name}/{key}/{pdb_name}"
    out_path = Path(out_dir) / pdb_name
    print(f"PDB Name:   {pdb_name}")
    print(f"Symbol Key: {key}")
    print(f"Downloading from: {url}")

    tmp = out_path.with_name(out_path.name + ".part")
    try:
        total = 0
        # Resume across dropped connections. These payloads run to several GB (a
        # win-arm64 chrome.dll.pdb is over 5) and a single mid-transfer reset used
        # to discard everything already written; the retry then re-downloaded the
        # whole file and often died again at a different offset.
        for attempt in range(1, MAX_RESUME_ATTEMPTS + 1):
            have = tmp.stat().st_size if tmp.exists() else 0
            headers = {"Range": f"bytes={have}-"} if have else {}
            request = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(request) as resp:
                    if not total:
                        total = (int(resp.headers.get("Content-Length") or 0)
                                 + (have if resp.status == 206 else 0))
                    if have and resp.status != 206:
                        have = 0                       # server ignored Range: restart
                    n = have
                    with open(tmp, "wb" if not have else "ab") as f:
                        while True:
                            chunk = resp.read(1 << 20)
                            if not chunk:
                                break
                            f.write(chunk)
                            n += len(chunk)
                            _progress(n, total)
            except (OSError, urllib.error.URLError) as e:
                if attempt == MAX_RESUME_ATTEMPTS:
                    raise
                got = tmp.stat().st_size if tmp.exists() else 0
                print(f"\n  connection dropped at {got}/{total or '?'} bytes "
                      f"({type(e).__name__}); resuming (attempt {attempt + 1})")
                continue
            if not total or tmp.stat().st_size >= total:
                break
            print(f"\n  stream ended early at {tmp.stat().st_size}/{total}; resuming")
        print()
    except urllib.error.HTTPError as e:
        tmp.unlink(missing_ok=True)
        print(f"\nFailed to download symbol file (HTTP {e.code}). Symbol might not be indexed.")
        return False
    except OSError as e:
        tmp.unlink(missing_ok=True)
        print(f"\nDownload failed: {e}")
        return False
    tmp.replace(out_path)
    print(f"\nSaved PDB to: {out_path.resolve()}")
    return True


# ===========================================================================
# ELF -> chrome.debug
# ===========================================================================
def elf_section_data(data, name):
    """Named ELF64 section's file bytes, or None (absent / SHT_NOBITS)."""
    if len(data) < 64 or data[4] != 2 or data[5] != 1:
        return None
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    if shoff == 0 or shnum == 0 or shoff + shentsize * shnum > len(data):
        return None
    str_hdr = shoff + shstrndx * shentsize
    str_off = struct.unpack_from("<Q", data, str_hdr + 0x18)[0]
    str_size = struct.unpack_from("<Q", data, str_hdr + 0x20)[0]
    if str_off + str_size > len(data):
        return None
    strtab = data[str_off:str_off + str_size]
    for i in range(shnum):
        sh = shoff + i * shentsize
        name_off = struct.unpack_from("<I", data, sh)[0]
        end = strtab.find(b"\x00", name_off)
        if strtab[name_off:end].decode("latin1") != name:
            continue
        sh_type = struct.unpack_from("<I", data, sh + 4)[0]
        if sh_type == 8:  # SHT_NOBITS
            return None
        off = struct.unpack_from("<Q", data, sh + 0x18)[0]
        size = struct.unpack_from("<Q", data, sh + 0x20)[0]
        if off + size > len(data):
            return None
        return data[off:off + size]
    return None


def elf_build_id(data):
    sec = elf_section_data(data, ".note.gnu.build-id")
    if not sec or len(sec) < 12:
        return None
    name_sz, desc_sz, n_type = struct.unpack_from("<III", sec, 0)
    if n_type != 3:  # NT_GNU_BUILD_ID
        return None
    desc_off = 12 + ((name_sz + 3) & ~3)
    if desc_off + desc_sz > len(sec):
        return None
    return sec[desc_off:desc_off + desc_sz].hex()


def elf_debug_link(data):
    """(name, crc, present)."""
    sec = elf_section_data(data, ".gnu_debuglink")
    if not sec:
        return "", 0, False
    end = sec.find(b"\x00")
    if end < 0:
        return "", 0, False
    name = sec[:end].decode("latin1")
    crc_off = (end + 4) & ~3
    if crc_off + 4 > len(sec):
        return name, 0, False
    return name, struct.unpack_from("<I", sec, crc_off)[0], True


def version_from_rodata(data):
    sec = elf_section_data(data, ".rodata")
    if not sec:
        return ""
    counts = {}
    for m in re.findall(rb"1\d{2}\.0\.\d{4}\.\d{1,4}", sec):
        counts[m] = counts.get(m, 0) + 1
    return max(counts, key=counts.get).decode("latin1") if counts else ""


def _http_range(url, start, end):
    req = urllib.request.Request(url)
    if start is not None:
        req.add_header("Range", f"bytes={start}-{end if end is not None else ''}")
    return urllib.request.urlopen(req)


def _http_range_bytes(url, start, end):
    with _http_range(url, start, end) as r:
        return r.read()


def remote_size(url):
    req = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(req) as r:
        n = int(r.headers.get("Content-Length") or 0)
    if n <= 0:
        raise ValueError("server did not report Content-Length")
    return n


def find_zip_member(url, total, member):
    """(local_off, comp, uncomp, method) for one member, via the EOCD + central
    directory read over HTTP range — no archive body transferred."""
    tail_len = min(70000, total)
    tail = _http_range_bytes(url, total - tail_len, total - 1)
    e = tail.rfind(b"PK\x05\x06")
    if e < 0:
        raise ValueError("zip End-Of-Central-Directory not found")
    cd_size = struct.unpack_from("<I", tail, e + 12)[0]
    cd_off = struct.unpack_from("<I", tail, e + 16)[0]
    if cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        raise ValueError("ZIP64 archive not supported by this fetcher")

    cd = _http_range_bytes(url, cd_off, cd_off + cd_size - 1)
    p = 0
    member_b = member.encode("utf-8")
    while p + 46 <= len(cd) and cd[p:p + 4] == b"PK\x01\x02":
        method = struct.unpack_from("<H", cd, p + 10)[0]
        csz = struct.unpack_from("<I", cd, p + 20)[0]
        usz = struct.unpack_from("<I", cd, p + 24)[0]
        name_len = struct.unpack_from("<H", cd, p + 28)[0]
        extra_len = struct.unpack_from("<H", cd, p + 30)[0]
        cmt_len = struct.unpack_from("<H", cd, p + 32)[0]
        lo = struct.unpack_from("<I", cd, p + 42)[0]
        name = cd[p + 46:p + 46 + name_len]
        if name == member_b:
            return lo, csz, usz, method
        p += 46 + name_len + extra_len + cmt_len
    raise ValueError(f"{member} not present in the archive")


def stream_zip_member(url, local_off, comp, uncomp, method, out_path):
    """Stream one member to disk, inflating on the fly; return its CRC-32."""
    lh = _http_range_bytes(url, local_off, local_off + 29)
    if lh[:4] != b"PK\x03\x04":
        raise ValueError("bad local file header signature")
    name_len = struct.unpack_from("<H", lh, 26)[0]
    extra_len = struct.unpack_from("<H", lh, 28)[0]
    data_off = local_off + 30 + name_len + extra_len

    if method == 0:
        decomp = None
    elif method == 8:
        decomp = zlib.decompressobj(-zlib.MAX_WBITS)  # raw deflate
    else:
        raise ValueError(f"unsupported zip compression method {method}")

    crc = 0
    n = 0
    consumed = 0
    # Resume on a dropped connection instead of restarting. `chrome.debug` inflates
    # to ~1.4 GiB and a mid-transfer reset used to fail the whole fetch; retrying
    # from scratch tended to die again at a different offset. The decompressor is
    # stateful but transport-agnostic, so reconnecting the *compressed* stream at
    # the exact byte already consumed and feeding the same object resumes cleanly.
    with open(out_path, "wb") as f:
        for attempt in range(1, MAX_RESUME_ATTEMPTS + 1):
            try:
                with _http_range(url, data_off + consumed, data_off + comp - 1) as body:
                    while True:
                        chunk = body.read(1 << 20)
                        if not chunk:
                            break
                        consumed += len(chunk)
                        out = decomp.decompress(chunk) if decomp else chunk
                        if out:
                            f.write(out)
                            crc = binascii.crc32(out, crc)
                            n += len(out)
                            _progress(n, uncomp)
            except (OSError, urllib.error.URLError) as e:
                if attempt == MAX_RESUME_ATTEMPTS or consumed >= comp:
                    raise
                print(f"\n  connection dropped after {consumed}/{comp} compressed bytes "
                      f"({type(e).__name__}); resuming (attempt {attempt + 1})")
                continue
            if consumed >= comp:
                break
            print(f"\n  stream ended early at {consumed}/{comp} compressed bytes; resuming")
        if decomp:
            tail = decomp.flush()
            if tail:
                f.write(tail)
                crc = binascii.crc32(tail, crc)
                n += len(tail)
    print()
    if uncomp > 0 and n != uncomp:
        raise ValueError(f"short read: got {n} bytes, expected {uncomp}")
    return crc & 0xFFFFFFFF


def fetch_debug(data, out_dir, forced_version):
    print("Reading debug identity from the binary...")
    build_id = elf_build_id(data)
    if not build_id:
        print("Error: no .note.gnu.build-id in the binary; cannot verify symbols.")
        return False
    debug_name, want_crc, have_crc = elf_debug_link(data)
    if not debug_name:
        debug_name = "chrome.debug"

    version = forced_version or version_from_rodata(data)
    if not version:
        print("Error: could not determine the Chrome version.")
        print("  Pass it explicitly: --chrome-version 151.0.7922.108")
        return False

    url = f"{DEBUG_SYMBOL_BASE}/google-chrome-debug-info-linux64-{version}.zip"
    out_path = Path(out_dir) / debug_name
    print(f"Version:    {version}")
    print(f"Build ID:   {build_id}")
    print(f"Debug link: {debug_name}" + (f" (CRC 0x{want_crc:08x})" if have_crc else ""))
    print(f"Archive:    {url}")

    try:
        total = remote_size(url)
        off, comp, uncomp, method = find_zip_member(url, total, DEBUG_MEMBER)
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError) as e:
        print(f"Failed to read the symbol archive: {e}")
        print("  Only versions recently served to Stable/Beta/Dev are published.")
        return False
    print(f"Member:     {DEBUG_MEMBER}  {comp >> 20} MiB compressed -> {uncomp >> 20} MiB")
    print(f"Writing:    {out_path}")

    part = out_path.with_name(out_path.name + ".part")
    try:
        got_crc = stream_zip_member(url, off, comp, uncomp, method, part)
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError, OSError) as e:
        part.unlink(missing_ok=True)
        print(f"Download failed: {e}")
        return False

    ok = True
    if have_crc:
        if got_crc == want_crc:
            print(f"[+] .gnu_debuglink CRC matches (0x{got_crc:08x}).")
        else:
            print(f"[-] debuglink CRC 0x{want_crc:08x} but downloaded file is 0x{got_crc:08x}.")
            ok = False
    dbg = part.read_bytes()
    dbg_id = elf_build_id(dbg)
    if dbg_id:
        if dbg_id == build_id:
            print("[+] build-id matches the installed binary.")
        else:
            print(f"[-] build-id {dbg_id} does not match {build_id}.")
            ok = False
    else:
        print("[-] downloaded file is not a readable ELF (no build-id).")
        ok = False

    if not ok:
        part.unlink(missing_ok=True)
        print("\nThese symbols do NOT belong to the installed binary - discarded the partial download.")
        return False
    part.replace(out_path)
    print(f"\nSaved symbols to: {out_path.resolve()}")
    return True


# ===========================================================================
def main():
    ap = argparse.ArgumentParser(description="Fetch Chrome debug symbols (PDB / chrome.debug) for MV2 derivation.")
    ap.add_argument("binary", help="chrome.dll (PE) or chrome (ELF) to fetch symbols for")
    ap.add_argument("--out", metavar="DIR", default=str(DEFAULT_OUT),
                    help="output directory (default: _scratch/)")
    ap.add_argument("--chrome-version", metavar="V", default="",
                    help="ELF only: override the version to fetch (e.g. 151.0.7922.108)")
    args = ap.parse_args()

    try:
        data = Path(args.binary).read_bytes()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    if data[:2] == b"MZ":
        return 0 if fetch_pdb(data, args.binary, out_dir) else 1
    if data[:4] == b"\x7fELF":
        return 0 if fetch_debug(data, out_dir, args.chrome_version) else 1
    be = struct.unpack_from(">I", data, 0)[0] if len(data) >= 4 else 0
    if be in (FAT_MAGIC, FAT_MAGIC_64) or data[:4] == b"\xcf\xfa\xed\xfe":
        return 0 if fetch_dsyms(data, out_dir, args.chrome_version) else 1
    print(f"error: {args.binary} is neither a PE ('MZ'), ELF, nor Mach-O binary.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
