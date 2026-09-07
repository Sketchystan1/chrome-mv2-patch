"""Shared helpers for the flat Python test suite (scripts/test_*.py).

The runtime patchers are shell/PowerShell; these tests drive them as black boxes
(subprocess) after building synthetic PE/ELF/Mach-O fixtures in pure Python.
"""
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Resolve bash explicitly: on Windows a bare "bash" in subprocess often hits the
# System32 WSL launcher (which needs /mnt/c paths), while shutil.which finds
# git-bash (which uses /c). Using the resolved path keeps posix() correct.
BASH = shutil.which("bash") or "bash"

_DRIVE = re.compile(r"^([A-Za-z]):[\\/](.*)$")


def posix(p):
    """A path string the local bash accepts. Converts a Windows drive path
    (C:\\x\\y) to the MSYS/git-bash form (/c/x/y); native POSIX paths (Linux/
    macOS CI) have no drive prefix and pass through unchanged."""
    p = str(p)
    m = _DRIVE.match(p)
    if m:
        return "/" + m.group(1).lower() + "/" + m.group(2).replace("\\", "/")
    return p.replace("\\", "/")


class Asserter:
    def __init__(self):
        self.passed = 0

    def ok(self):
        self.passed += 1

    def fail(self, msg):
        print(f"ASSERTION FAILED: {msg}", file=sys.stderr)
        sys.exit(1)

    def eq(self, got, want, msg):
        if got != want:
            self.fail(f"{msg} (got {got!r}, expected {want!r})")
        self.ok()

    def true(self, cond, msg):
        if not cond:
            self.fail(msg)
        self.ok()

    def is_file(self, path, msg):
        self.true(Path(path).is_file(), msg)


def run(cmd, env=None, cwd=None):
    """Run a command; return CompletedProcess with captured text output."""
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run(cmd, env=e, cwd=cwd, capture_output=True, text=True)


def run_ok(cmd, env=None, cwd=None):
    return run(cmd, env, cwd).returncode == 0


def bash(script, sub, target, sigs, *extra, env=None):
    """Invoke a shell patcher: bash <script> <sub> <target> --signatures <sigs>
    --quiet [extra...]. Paths are converted for the local bash."""
    cmd = [BASH, posix(script), sub, posix(target), "--signatures", posix(sigs), "--quiet", *extra]
    return run(cmd, env)


def copy(src, dst):
    """Portable file copy (avoids depending on a `cp` on PATH)."""
    shutil.copyfile(src, dst)


def byte_at(path, off):
    with open(path, "rb") as f:
        f.seek(off)
        return f.read(1)[0]


def read_word(path, off):
    """Little-endian 32-bit word at `off` (arm64 CBZ/B sites)."""
    with open(path, "rb") as f:
        f.seek(off)
        return struct.unpack("<I", f.read(4))[0]


def read_dword(path, off):
    """Little-endian 32-bit value at `off` (e.g. a near-jump disp32)."""
    with open(path, "rb") as f:
        f.seek(off)
        return struct.unpack("<i", f.read(4))[0]


def write_word(path, off, value):
    with open(path, "r+b") as f:
        f.seek(off)
        f.write(struct.pack("<I", value))


def poke(path, off, value):
    with open(path, "r+b") as f:
        f.seek(off)
        f.write(bytes([value]))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------------------------------------------------------------------------
# Synthetic fixtures (byte-identical to the old shell harnesses' builders).
# ---------------------------------------------------------------------------
def make_elf(path, sig_hex, build_byte=0x11, machine=62):
    """Minimal ELF64 with a .text carrying `sig_hex` at file offset 0x140 and a
    GNU build-id note. Mirrors the former test-bash.sh make_elf. `machine` is the
    ELF e_machine (62 x86_64 default, 183/0xB7 for aarch64 -> container elf-arm64)."""
    buf = bytearray(0x700)
    ident = bytes(b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8))
    buf[:64] = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, machine, 1, 0, 0, 0x500, 0, 64, 0, 0, 64, 4, 3)
    sig = bytes.fromhex(sig_hex)
    buf[0x140:0x140 + len(sig)] = sig
    note = struct.pack("<III", 4, 20, 3) + b"GNU\0" + bytes([build_byte]) * 20
    buf[0x300:0x300 + len(note)] = note
    names = b"\0.text\0.note.gnu.build-id\0.shstrtab\0"
    buf[0x400:0x400 + len(names)] = names
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 6, 0x400000, 0x100, 0x100, 0, 0, 16, 0),
        (7, 7, 2, 0, 0x300, len(note), 0, 0, 4, 0),
        (26, 3, 0, 0, 0x400, len(names), 0, 0, 1, 0),
    ]
    for i, sh in enumerate(sections):
        buf[0x500 + i * 64:0x500 + (i + 1) * 64] = struct.pack("<IIQQQQIIQQ", *sh)
    Path(path).write_bytes(buf)


def make_pe(path, sig_hex, sig_off=0x40, timestamp=0x12345678, signed=True, machine=0x8664):
    """Minimal PE32+ (or PE32 arm64 via `machine`) with a .text at file offset
    0x400 (RVA 0x1000, size 0x200) carrying `sig_hex` at 0x400+sig_off, and an
    optional non-zero Security directory. Mirrors New-TestPe from test_windows.py.
    machine: 0x8664 x64 (container pe), 0xAA64 arm64 (pe-arm64)."""
    buf = bytearray(0x800)
    buf[0], buf[1] = 0x4D, 0x5A
    struct.pack_into("<I", buf, 0x3C, 0x80)               # e_lfanew
    nt = 0x80
    buf[nt], buf[nt + 1] = 0x50, 0x45                     # "PE"
    struct.pack_into("<H", buf, nt + 4, machine)
    struct.pack_into("<H", buf, nt + 6, 1)                # NumberOfSections
    struct.pack_into("<I", buf, nt + 8, timestamp)
    struct.pack_into("<H", buf, nt + 20, 0xF0)            # SizeOfOptionalHeader
    opt = nt + 24
    struct.pack_into("<H", buf, opt, 0x20B)               # PE32+ magic
    struct.pack_into("<I", buf, opt + 108, 16)            # NumberOfRvaAndSizes
    if signed:
        struct.pack_into("<I", buf, opt + 144, 0x700)     # Security dir VA
        struct.pack_into("<I", buf, opt + 148, 0x20)      # Security dir size
    section = opt + 0xF0
    buf[section:section + 5] = b".text"
    struct.pack_into("<I", buf, section + 8, 0x200)       # VirtualSize
    struct.pack_into("<I", buf, section + 12, 0x1000)     # VirtualAddress (RVA)
    struct.pack_into("<I", buf, section + 16, 0x200)      # SizeOfRawData
    struct.pack_into("<I", buf, section + 20, 0x400)      # PointerToRawData
    sig = bytes.fromhex(sig_hex)
    buf[0x400 + sig_off:0x400 + sig_off + len(sig)] = sig
    Path(path).write_bytes(buf)


def make_pe_feature(path, gate_sig_hex, feature="webRequestBlocking",
                    gate_off=0x40, max_val=2, timestamp=0x12345678, gate2_hex=None, gate2_off=0x80):
    """PE32+ x64 with TWO sections: a .text carrying `gate_sig_hex` (a short-jg MV2
    gate, for a required site) and a .rdata carrying a synthetic SimpleFeatureData
    for `feature` - a name literal, an 8-byte .name pointer to it, and the rule-1
    config fields the featurebyte locator checks. The max_manifest_version value
    byte sits at struct+0xC0 (file offset 0x700). ImageBase 0x180000000. If
    `gate2_hex` is given it is written at .text+gate2_off (a second branch gate,
    e.g. for an optional short site test).

    Layout: headers 0..0x400; .text RVA 0x1000 raw 0x400 size 0x200; .rdata RVA
    0x2000 raw 0x600 size 0x200. Feature name literal @ RVA 0x2010 (raw 0x610);
    struct base @ RVA 0x2040 (raw 0x640)."""
    IMAGE_BASE = 0x180000000
    buf = bytearray(0x800)
    buf[0], buf[1] = 0x4D, 0x5A
    struct.pack_into("<I", buf, 0x3C, 0x80)               # e_lfanew
    nt = 0x80
    buf[nt], buf[nt + 1] = 0x50, 0x45                     # "PE"
    struct.pack_into("<H", buf, nt + 4, 0x8664)           # machine x64
    struct.pack_into("<H", buf, nt + 6, 2)                # NumberOfSections
    struct.pack_into("<I", buf, nt + 8, timestamp)
    struct.pack_into("<H", buf, nt + 20, 0xF0)            # SizeOfOptionalHeader
    opt = nt + 24
    struct.pack_into("<H", buf, opt, 0x20B)               # PE32+ magic
    struct.pack_into("<Q", buf, opt + 24, IMAGE_BASE)     # ImageBase
    struct.pack_into("<I", buf, opt + 108, 16)            # NumberOfRvaAndSizes
    struct.pack_into("<I", buf, opt + 144, 0x780)         # Security dir VA (stock discriminator)
    struct.pack_into("<I", buf, opt + 148, 0x20)          # Security dir size
    sec = opt + 0xF0
    buf[sec:sec + 5] = b".text"
    struct.pack_into("<IIII", buf, sec + 8, 0x200, 0x1000, 0x200, 0x400)   # VSize, VA, RawSize, RawPtr
    sec2 = sec + 40
    buf[sec2:sec2 + 6] = b".rdata"
    struct.pack_into("<IIII", buf, sec2 + 8, 0x200, 0x2000, 0x200, 0x600)
    # .text gate
    gate = bytes.fromhex(gate_sig_hex)
    buf[0x400 + gate_off:0x400 + gate_off + len(gate)] = gate
    if gate2_hex:
        g2 = bytes.fromhex(gate2_hex)
        buf[0x400 + gate2_off:0x400 + gate2_off + len(g2)] = g2
    # .rdata feature struct
    name = feature.encode("latin1") + b"\x00"
    buf[0x610:0x610 + len(name)] = name                   # name literal @ RVA 0x2010
    base = 0x640                                          # struct base @ RVA 0x2040
    struct.pack_into("<Q", buf, base + 0x00, IMAGE_BASE + 0x2010)  # .name ptr
    struct.pack_into("<Q", buf, base + 0x08, len(feature))         # .name len
    struct.pack_into("<Q", buf, base + 0x60, 2)           # extension_types.size = 2
    buf[base + 0xB4] = 0                                  # location.has_value = 0
    buf[base + 0xBC] = 0                                  # min_manifest_version.has_value = 0
    struct.pack_into("<i", buf, base + 0xC0, max_val)     # max_manifest_version value  (file 0x700)
    buf[base + 0xC4] = 1                                  # max_manifest_version.has_value = 1
    Path(path).write_bytes(buf)


def _macho_thin(cpu, text, uuid_byte):
    MH64, SEG, UUID, TEXT_OFF, VM = 0xFEEDFACF, 0x19, 0x1B, 0x200, 0x100000000
    seg_sz = 72 + 80
    hdr = struct.pack("<IiiIIIII", MH64, cpu, 0, 6, 2, seg_sz + 24, 0, 0)
    sect = struct.pack("<16s16sQQIIIIIII4x", b"__text", b"__TEXT", VM, len(text), TEXT_OFF, 4, 0, 0, 0, 0, 0)
    seg = struct.pack("<II16sQQQQiiII", SEG, seg_sz, b"__TEXT", VM, 0x1000, 0, TEXT_OFF + len(text), 7, 5, 1, 0)
    uuid = struct.pack("<II", UUID, 24) + bytes([uuid_byte]) * 16
    body = hdr + seg + sect + uuid
    body += b"\x00" * (TEXT_OFF - len(body)) + text
    return body


def make_fat_macho(path):
    """Universal fixture: x86_64 short-jg gate + arm64 b.cond gate, each at
    __text offset 0x40. Returns (x64_jg_offset, arm64_jg_offset) file offsets."""
    X64, ARM = 0x01000007, 0x0100000C
    x64_text = b"\x00" * 0x40 + bytes.fromhex("837E50027F2F554889E5488B8E280200008B413080BE080200") + b"\x00" * 0x40
    arm_text = b"\x00" * 0x40 + struct.pack("<IIII", 0x7100091F, 0x5400008C, 0xD503201F, 0x7100051F) + b"\x00" * 0x40
    sx, sa = _macho_thin(X64, x64_text, 0xA1), _macho_thin(ARM, arm_text, 0xB2)
    hdr = struct.pack(">II", 0xCAFEBABE, 2)
    off = len(hdr) + 40
    aligned = (off + 0xFFF) & ~0xFFF
    entries, blobs, cur, offs = b"", b"", aligned, []
    for cpu, d in ((X64, sx), (ARM, sa)):
        entries += struct.pack(">IIIII", cpu, 0, cur, len(d), 12)
        blobs += b"\x00" * (cur - (aligned + len(blobs))) + d
        offs.append(cur)
        cur = (cur + len(d) + 0xFFF) & ~0xFFF
    Path(path).write_bytes(hdr + entries + b"\x00" * (aligned - off) + blobs)
    return offs[0] + 0x200 + 0x40 + 4, offs[1] + 0x200 + 0x40 + 4

