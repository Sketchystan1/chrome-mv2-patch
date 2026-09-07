"""Cross-platform MV2 gate derivation and verification for the patch scripts.

One tool, all containers and both x86 `jg` encodings:
  - PE `chrome.dll` on Windows: 64-bit PE32+ x64 (`pe`), 32-bit PE32 x86 (`pe32`),
    and 64-bit PE32+ arm64 (`pe-arm64`, the Windows-on-ARM native dll - same
    `bcond` flip as macOS arm64 below)
  - ELF `chrome` on Linux: x86_64 (`elf`) and the arm64 build (`elf-arm64`, the
    same `bcond` flip as macOS/Windows arm64 below)
  - the universal "Google Chrome Framework" Mach-O on macOS: the arm64 slice
    (`macho-arm64`, a `bcond` kind: `cmp w,#2 ; b.gt` with the condition
    rewritten GT->AL). Intel x86_64 is no longer supported; its slice is skipped.

It is a single symbol-free finder that works for any future Chrome version,
replacing an earlier version- and Windows-specific derivation.

  derive   (default)  scan a stock binary for IsExtensionAffected gate sites and
                      print a signatures.json entry (container + sites[]).
  --verify JSON       re-check an existing signatures.json against a binary: every
                      site's masked match count must equal expectedMatches.
                      Prints `ALL SITES VERIFIED: True` on success (the static
                      check that a table still fits a build).

No third-party dependencies (capstone/pyelftools/pefile not required), so it runs
on the bare reference boxes. Symbols are optional and only used for *naming*
candidates — see symbols_from_pdb.py (Windows PDB) or `nm chrome.debug` (Linux).

The finder mirrors the report-only scanners and masked matchers in
chrome-mv2.ps1 and chrome-mv2.sh, extended to the near-jg encoding. Only the jg
opcode and its displacement are wild.

Usage:
    python scripts/derive_milestone.py <stock-binary> [--name NAME] [--json]
    python scripts/derive_milestone.py <stock-binary> --verify signatures.json
"""

import argparse
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_JSON = REPO / "signatures.json"


# ---------------------------------------------------------------------------
# Image parsing: PE and ELF, hand-rolled (no pefile / pyelftools).
# Returns the .text virtual start, file offset, size, and container tag. The
# "virtual start" is the PE section VirtualAddress (an RVA) or the ELF section
# sh_addr. The finder works on the .text slice, so positions are relative to
# .text's start; rva() maps such a slice-relative index to jgRVA = pos +
# text_virt (the address a disassembler shows and the patch scripts store).
# ---------------------------------------------------------------------------
class Image:
    def __init__(self, container, text_virt, text_raw, text_size, data):
        self.container = container      # "pe" | "pe32" | "pe-arm64" | "elf" | "elf-arm64" | "macho-arm64"
        self.text_virt = text_virt
        self.text_raw = text_raw
        self.text_size = text_size
        self.data = data
        self._text = None
        self.uuid = None                # Mach-O LC_UUID (hex), else None
        # PE-only, for the featurebyte (.rdata) locator (None elsewhere):
        self.imagebase = None
        self.rdata_virt = None
        self.rdata_raw = None
        self.rdata_size = None

    @property
    def text(self):
        if self._text is None:  # slice the ~250 MB .text once, then reuse
            self._text = self.data[self.text_raw:self.text_raw + self.text_size]
        return self._text

    def rva(self, textpos):
        """Index within the .text slice -> the address the scripts store (jgRVA)."""
        return textpos + self.text_virt

    def off(self, rva):
        """Inverse of rva(): jgRVA -> index within the .text slice."""
        return rva - self.text_virt


def parse_pe(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (bad NT signature)")
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    size_opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("unsupported PE optional header magic 0x%X" % magic)
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    # PE32 (x86), PE32+ x64, and PE32+ arm64 share the same section-table format;
    # only the gate machine code differs, so tag the container distinctly to keep
    # the milestone tables from cross-probing. x64 (machine 0x8664) and arm64
    # (0xAA64) are both PE32+ (magic 0x20B) - the machine field disambiguates them.
    if magic == 0x10B:
        container = "pe32"          # PE32, x86 cmp/jg
    elif machine == 0xAA64:
        container = "pe-arm64"      # PE32+, arm64 cmp/b.gt (same bcond flip as macOS arm64)
    else:
        container = "pe"            # PE32+, x64 cmp/jg
    sec_off = opt + size_opt
    imagebase = (struct.unpack_from("<I", data, opt + 28)[0] if magic == 0x10B
                 else struct.unpack_from("<Q", data, opt + 24)[0])
    text = None
    rdata = None
    for i in range(num_sections):
        b = sec_off + i * 40
        name = data[b:b + 8].split(b"\x00")[0].decode("latin1")
        v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, b + 8)
        if name == ".text":
            text = (v_addr, raw_ptr, raw_size)
        elif name == ".rdata":
            rdata = (v_addr, raw_ptr, raw_size)
    if text is None:
        raise ValueError("no .text section")
    img = Image(container, text[0], text[1], text[2], data)
    img.imagebase = imagebase
    if rdata is not None:
        img.rdata_virt, img.rdata_raw, img.rdata_size = rdata
        if img.rdata_raw + img.rdata_size > len(data):
            img.rdata_size = max(0, len(data) - img.rdata_raw)
    return img


def parse_elf(data):
    if data[4] != 2 or data[5] != 1:
        raise ValueError("not little-endian ELF64")
    # e_machine (0x12, u16): 0x3E x86_64 -> "elf", 0xB7 aarch64 -> "elf-arm64".
    # arm64 has no cmp/jg; its gate is cmp w,#2 ; b.gt (the bcond flip), so it must
    # be tagged distinctly to route through find_gates_arm64 and avoid cross-probing
    # the x86_64 table.
    e_machine = struct.unpack_from("<H", data, 0x12)[0]
    container = "elf-arm64" if e_machine == 0xB7 else "elf"
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    str_hdr = shoff + shstrndx * shentsize
    str_off = struct.unpack_from("<Q", data, str_hdr + 0x18)[0]
    str_size = struct.unpack_from("<Q", data, str_hdr + 0x20)[0]
    strtab = data[str_off:str_off + str_size]
    for i in range(shnum):
        sh = shoff + i * shentsize
        name_off = struct.unpack_from("<I", data, sh)[0]
        name = strtab[name_off:strtab.find(b"\x00", name_off)].decode("latin1")
        if name == ".text":
            addr = struct.unpack_from("<Q", data, sh + 0x10)[0]
            off = struct.unpack_from("<Q", data, sh + 0x18)[0]
            size = struct.unpack_from("<Q", data, sh + 0x20)[0]
            return Image(container, addr, off, size, data)
    raise ValueError("no .text section")


# ---------------------------------------------------------------------------
# Mach-O (macOS). The gate-bearing binary is the universal "Google Chrome
# Framework", a fat archive carrying an x86_64 slice and an arm64 slice, each a
# thin Mach-O. Unlike ELF there is NO vmaddr->fileoffset delta to apply for byte
# location: section_64.offset is already the slice-relative file offset, so the
# absolute file offset is slice_base + section.offset. text_virt keeps the
# vmaddr only for jgRVA bookkeeping. The x86_64 slice reuses the x86 cmp/jg
# finder; the arm64 slice uses find_gates_arm64 (cmp #2 ; b.gt -> AL flip).
# ---------------------------------------------------------------------------
MH_MAGIC_64 = 0xFEEDFACF          # thin 64-bit Mach-O, little-endian on disk (CF FA ED FE)
FAT_MAGIC = 0xCAFEBABE            # fat header, big-endian, 32-bit fat_arch entries
FAT_MAGIC_64 = 0xCAFEBABF         # fat header, big-endian, 64-bit fat_arch entries
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B


def _parse_macho_thin(data, base, cputype_hint=None):
    """Parse one thin Mach-O slice starting at file offset `base`. Returns an
    Image (container macho-arm64) with the UUID stashed on it, or raises
    ValueError. Only the 64-bit little-endian arm64 slice is supported; the
    x86_64 slice and anything else declines (Intel macOS is unsupported)."""
    if base + 32 > len(data):
        raise ValueError("Mach-O slice header out of bounds")
    magic = struct.unpack_from("<I", data, base)[0]
    if magic != MH_MAGIC_64:
        raise ValueError("not a 64-bit little-endian Mach-O (magic 0x%08X)" % magic)
    cputype = struct.unpack_from("<I", data, base + 4)[0]
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    if cputype == CPU_TYPE_ARM64:
        container = "macho-arm64"
    else:
        # x86_64 and any other CPU: skip (Intel macOS is no longer supported).
        raise ValueError("unsupported Mach-O cputype 0x%08X" % cputype)

    text_addr = text_off = text_size = None
    uuid = None
    p = base + 32
    for _ in range(ncmds):
        if p + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, p)
        if cmdsize < 8 or p + cmdsize > len(data):
            raise ValueError("Mach-O load command out of bounds")
        if cmd == LC_SEGMENT_64:
            segname = data[p + 8:p + 24].split(b"\x00")[0]
            nsects = struct.unpack_from("<I", data, p + 64)[0]
            if segname == b"__TEXT":
                sec = p + 72
                for _s in range(nsects):
                    sectname = data[sec:sec + 16].split(b"\x00")[0]
                    if sectname == b"__text":
                        text_addr = struct.unpack_from("<Q", data, sec + 32)[0]
                        text_size = struct.unpack_from("<Q", data, sec + 40)[0]
                        text_off = struct.unpack_from("<I", data, sec + 48)[0]
                    sec += 80
        elif cmd == LC_UUID:
            uuid = data[p + 8:p + 24].hex()
        p += cmdsize

    if text_addr is None:
        raise ValueError("no __TEXT,__text section")
    raw = base + text_off
    if raw + text_size > len(data):
        raise ValueError("Mach-O __text out of file bounds")
    img = Image(container, text_addr, raw, text_size, data)
    img.uuid = uuid
    return img


def parse_macho(data):
    """Return a list of Images, one per slice. A fat binary yields both slices;
    a thin binary yields one."""
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        is64 = magic_be == FAT_MAGIC_64
        nfat = struct.unpack_from(">I", data, 4)[0]
        entry = 32 if is64 else 20
        images = []
        off = 8
        for _ in range(nfat):
            if off + entry > len(data):
                break
            if is64:
                cputype, _sub, soff, _size = struct.unpack_from(">IIQQ", data, off)
            else:
                cputype, _sub, soff, _size = struct.unpack_from(">IIII", data, off)
            off += entry
            try:
                images.append(_parse_macho_thin(data, soff, cputype))
            except ValueError:
                continue  # skip a slice we don't handle rather than fail the whole fat file
        if not images:
            raise ValueError("no supported Mach-O slices in the fat binary")
        return images
    return [_parse_macho_thin(data, 0)]


def open_images(path):
    """Return a list of Images. PE/ELF yield one; a universal Mach-O yields one
    per CPU slice (x86_64, arm64)."""
    data = Path(path).read_bytes()
    if data[:2] == b"MZ":
        return [parse_pe(data)]
    if data[:4] == b"\x7fELF":
        return [parse_elf(data)]
    magic_be = struct.unpack_from(">I", data, 0)[0] if len(data) >= 4 else 0
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64) or data[:4] == b"\xcf\xfa\xed\xfe":
        return parse_macho(data)
    raise ValueError("unrecognized binary (not PE 'MZ', ELF '\\x7fELF', or Mach-O)")


def open_image(path):
    """Back-compat single-image accessor (first slice for a fat Mach-O)."""
    return open_images(path)[0]


# ---------------------------------------------------------------------------
# Masked matcher - mirrors the matchers in both runtime patch scripts.
# Exact on every signature byte except the jg opcode and its displacement.
#
# A naive per-offset scan of the ~250 MB .text is far too slow in pure Python,
# so we anchor on the longest fixed (unmasked) run in the signature via
# bytes.find and only full-check at those few candidate offsets. The result is
# identical to the naive scan; it just skips the offsets that cannot match.
# ---------------------------------------------------------------------------
def _masked_indices(jg_off, kind):
    if kind == "short":
        return {jg_off, jg_off + 1}
    if kind in ("bcond", "cbz"):
        # the whole 4-byte little-endian branch word is special (bit-masked in full_ok)
        return {jg_off, jg_off + 1, jg_off + 2, jg_off + 3}
    return {jg_off, jg_off + 1, jg_off + 2, jg_off + 3, jg_off + 4, jg_off + 5}


def _sign_extend(v, bits):
    if v & (1 << (bits - 1)):
        v -= 1 << bits
    return v


def _cbz_word_ok(cand_word, sig_word):
    """True when cand_word is the stock CBZ (0x34, Rt pinned to the sig's) or the
    patched unconditional B (0x14) whose resolved target equals the sig CBZ's."""
    if (cand_word & 0xFF000000) == 0x34000000:
        return (cand_word & 0x1F) == (sig_word & 0x1F)
    if (cand_word & 0xFC000000) == 0x14000000:
        disp_cand = _sign_extend(cand_word & 0x03FFFFFF, 26)
        disp_ref = _sign_extend((sig_word >> 5) & 0x7FFFF, 19)
        return disp_cand == disp_ref
    return False


def _longest_fixed_run(n, masked):
    """Return (start, length) of the longest contiguous unmasked span in [0,n)."""
    best_start, best_len = 0, 0
    i = 0
    while i < n:
        if i in masked:
            i += 1
            continue
        j = i
        while j < n and j not in masked:
            j += 1
        if j - i > best_len:
            best_start, best_len = i, j - i
        i = j
    return best_start, best_len


def masked_match_count(text, sig, jg_off, kind, cap=None):
    """Offsets in .text where sig matches under per-encoding masking."""
    n = len(sig)
    masked = _masked_indices(jg_off, kind)
    anchor_off, anchor_len = _longest_fixed_run(n, masked)
    anchor = bytes(sig[anchor_off:anchor_off + anchor_len])

    def full_ok(r):
        # arm64 B.cond: validate the 4-byte little-endian branch word once. Accept
        # only the stock GT (0xC) or the flipped AL (0xE) condition; the opcode
        # (0x54) and bit[4]=0 are fixed (bit[4]=1 would be BC.cond), and imm19 is
        # wildcarded so a displacement shift across a point release still matches.
        if kind == "bcond":
            w = int.from_bytes(bytes(text[r + jg_off:r + jg_off + 4]), "little")
            if (w & 0xFF000010) != 0x54000000:
                return False
            if (w & 0xF) not in (0x0C, 0x0E):
                return False
        # arm64 CBZ->B: the word is either the stock 32-bit CBZ (Rt pinned,
        # imm19 wild) or the patched unconditional B with the same target.
        if kind == "cbz":
            w = int.from_bytes(bytes(text[r + jg_off:r + jg_off + 4]), "little")
            sig_w = int.from_bytes(bytes(sig[jg_off:jg_off + 4]), "little")
            if not _cbz_word_ok(w, sig_w):
                return False
        for k in range(n):
            if k in masked:
                b = text[r + k]
                if kind == "short" and k == jg_off:
                    # the sig's own stock byte (default 7F jg) or the EB patch
                    if b != sig[k] and b != 0xEB:
                        return False
                elif kind == "near" and k == jg_off:
                    # the sig's own stock pair (default 0F 8F jg) or 90 (nop)
                    if b != sig[k] and b != 0x90:
                        return False
                elif kind == "near" and k == jg_off + 1:
                    if b != sig[k] and b != 0xE9:
                        return False
                # displacement bytes (and bcond/cbz words, already validated): wildcard
                continue
            if text[r + k] != sig[k]:
                return False
        return True

    hits = []
    pos = 0
    tlen = len(text)
    while True:
        h = text.find(anchor, pos)
        if h < 0:
            break
        start = h - anchor_off
        if start >= 0 and start + n <= tlen and full_ok(start):
            hits.append(start)
            if cap is not None and len(hits) > cap:
                break
        pos = h + 1
    return hits


# ---------------------------------------------------------------------------
# The finder: cmp <mv>,2 ; jg (short|near) ; ... type/location follow-up.
# Byte skeleton (both cmp encodings, matching the runtime scripts' scanners):
#   reg   : 83 F8..FF 02              cmp <reg32>, 2         (mod=11, reg=/7)
#   disp8 : 83 78..7F <disp8> 02      cmp [reg+disp8], 2     (mod=01, reg=/7)
# then the jg: short 7F | near 0F 8F. A real gate also carries, within ~40
# bytes, a Manifest::Type compare (83 F8..FF {01|05}) or the location byte test
# (80 B8..BF <disp32> 00) - the same follow-up the runtime scripts require.
# ---------------------------------------------------------------------------
def find_gates(img):
    text = img.text
    n = len(text)
    gates = []  # (cmp_pos, jg_pos, kind)
    seen = set()

    def has_followup(after):
        end = min(after + 40, n - 2)
        j = after
        while j + 2 < end:
            if text[j] == 0x83 and (text[j + 1] & 0xF8) == 0xF8 and text[j + 2] in (0x01, 0x05):
                return True  # cmp reg, 1/5  (Manifest::Type enum)
            if text[j] == 0x80 and (text[j + 1] & 0xF8) == 0xB8 and j + 6 < end and text[j + 6] == 0x00:
                return True  # cmp byte [reg+disp32], 0  (location gate)
            j += 1
        return False

    def cmp_start(imm_pos):
        """If imm_pos is the imm8 `02` of a `cmp r/m32,2` (opcode 83 /7), return
        the cmp start, else None. Handles the reg (mod=11) and disp8 (mod=01)
        encodings, matching the runtime scripts' scanners."""
        if imm_pos >= 2 and text[imm_pos - 2] == 0x83 and (text[imm_pos - 1] & 0xF8) == 0xF8:
            return imm_pos - 2
        if imm_pos >= 3 and text[imm_pos - 3] == 0x83 and (text[imm_pos - 2] & 0xF8) == 0x78:
            return imm_pos - 3
        return None

    # Short jg: the imm8 `02` is immediately followed by `7F`. Anchor on `02 7F`.
    pos = 0
    while True:
        h = text.find(b"\x02\x7f", pos)
        if h < 0:
            break
        pos = h + 1
        cp = cmp_start(h)
        if cp is None:
            continue
        jg_pos = h + 1
        if has_followup(jg_pos + 2) and jg_pos not in seen:
            seen.add(jg_pos)
            gates.append((cp, jg_pos, "short"))

    # Near jg: the imm8 `02` is followed by `0F 8F`. Anchor on `02 0F 8F`.
    pos = 0
    while True:
        h = text.find(b"\x02\x0f\x8f", pos)
        if h < 0:
            break
        pos = h + 1
        cp = cmp_start(h)
        if cp is None:
            continue
        jg_pos = h + 1
        if has_followup(jg_pos + 6) and jg_pos not in seen:
            seen.add(jg_pos)
            gates.append((cp, jg_pos, "near"))

    gates.sort(key=lambda g: g[0])
    return gates


# ---------------------------------------------------------------------------
# The arm64 finder: cmp w,#2 ; b.gt (GT) ; ... type follow-up in the fall-through.
# arm64 has no cmp/jg; the mv>=3 early-out compiles to a signed-greater-than
# conditional branch, and the sanctioned flip rewrites its condition GT->AL
# (0xC->0xE), keeping imm19 so it targets the same not-affected label. Encodings:
#   cmp w?, #2  = SUBS WZR, Wn, #2 : (word & 0xFFFFFC1F) == 0x7100081F   (Rn wild)
#   b.gt disp   : B.cond cond=GT   : (word & 0xFF00001F) == 0x5400000C   (imm19 wild)
# A real gate carries, within the fall-through (mv<=2) path, the Manifest::Type
# compare (cmp/ccmp w?, #1 or #5). Requiring that follow-up also fixes branch
# POLARITY: if the fall-through were instead `movz w0,#0 ; ret` the branch target
# would be the not-affected return (inverted), and flipping to AL would force the
# WRONG outcome -- such a candidate lacks the follow-up and is declined, never
# guessed. cmp #3/b.ge, cbz/cbnz/tbz and branchless ccmp/csel shapes simply miss
# this anchor and decline. See mv2-reversing.md.
ARM64_BGT_MASK = 0xFF00001F
ARM64_BGT_VAL = 0x5400000C          # B.cond, cond=GT(0xC), bit[4]=0


def _u32le(text, pos):
    return int.from_bytes(bytes(text[pos:pos + 4]), "little")


def _is_arm64_cmp_imm(word, imm):
    """SUBS WZR, Wn, #imm (32-bit `cmp w?, #imm`), Rn wildcarded."""
    return (word & 0xFFFFFC1F) == (0x7100001F | (imm << 10))


# The arm64 mirror of the x86 finder's `cmp byte [reg+disp32], 0` follow-up: the
# location/flag gate compiles to `ldrb w?, [x?, #imm12]` on a far-out Extension
# field, then a bit test. Only large displacements qualify, the same way the x86
# side only accepts the disp32 encoding - a near-zero offset ldrb is ordinary
# byte loading, not a gate marker. Without this shape the type!=PLATFORM_APP
# variant (whose fall-through compares the Manifest::Type against 6, never 1/5)
# is silently dropped on arm64 while the x86 finder keeps it.
def _is_arm64_flag_load(word, min_disp=0x100):
    """LDRB Wt, [Xn, #imm12] (unsigned offset) with imm12 >= min_disp."""
    if (word & 0xFFC00000) != 0x39400000:
        return False
    return ((word >> 10) & 0xFFF) >= min_disp


def _has_arm64_bit_test(text, start, end):
    """A TBZ/TBNZ within [start, end) - the `!= 0` half of the flag check."""
    j = start
    while j <= end:
        if (_u32le(text, j) & 0x7E000000) == 0x36000000:   # TBZ/TBNZ
            return True
        j += 4
    return False


def find_gates_arm64(img):
    text = img.text
    n = len(text)
    gates = []

    def has_followup(after):
        end = min(after + 64, n - 4)  # ~16 words of the fall-through path
        j = after
        while j <= end:
            w = _u32le(text, j)
            if _is_arm64_cmp_imm(w, 1) or _is_arm64_cmp_imm(w, 5):
                return True  # cmp w?, #1 / #5  (Manifest::Type enum)
            if _is_arm64_flag_load(w) and _has_arm64_bit_test(text, j + 4, min(j + 20, n - 4)):
                return True  # ldrb w?,[x?,#big] ; tbnz/tbz  (the location gate)
            j += 4
        return False

    # Anchor on the cmp word's fixed tail: a 32-bit `cmp w?, #2` (SUBS WZR,Wn,#2,
    # sh=0) is 0x7100081F | (Rn<<5), so bytes[2:4] are always 00 71. bytes.find
    # over ~200 MB is C-fast; the mask/b.gt/follow-up checks run at the few hits.
    pos = 0
    while True:
        h = text.find(b"\x00\x71", pos)
        if h < 0:
            break
        pos = h + 1
        cp = h - 2                       # candidate cmp-word start
        if cp < 0 or cp % 4 != 0 or cp + 8 > n:
            continue
        if not _is_arm64_cmp_imm(_u32le(text, cp), 2):
            continue
        if (_u32le(text, cp + 4) & ARM64_BGT_MASK) == ARM64_BGT_VAL and has_followup(cp + 8):
            gates.append((cp, cp + 4, "bcond"))

    gates.sort(key=lambda g: g[0])
    return gates


def find_gates_for(img):
    """Dispatch to the arm64 or x86 finder by container."""
    return find_gates_arm64(img) if img.container in ("macho-arm64", "pe-arm64", "elf-arm64") else find_gates(img)


# Default signature window past the cmp, matching the shipping entries (24-32B).
# Long enough to span the follow-up type/location check, so the anchor is a
# distinctive fixed run and the masked count is meaningful.
SIGLEN = {"short": 25, "near": 28, "bcond": 32, "cbz": 32}
# Minimum bytes that must follow jg_off inside the signature (the jump itself).
NEED = {"short": 2, "near": 6, "bcond": 4, "cbz": 4}


def build_site(img, cmp_pos, jg_pos, kind, name):
    """Package one candidate as a signatures.json site dict, measuring how many
    times its fixed-window signature matches .text under the scripts' masking."""
    text = img.text
    jg_off = jg_pos - cmp_pos
    siglen = min(max(SIGLEN[kind], jg_off + NEED[kind] + 4),
                 len(text) - cmp_pos)
    sig = text[cmp_pos:cmp_pos + siglen]
    count = len(masked_match_count(text, sig, jg_off, kind, cap=16))
    return {
        "name": name,
        "kind": kind,
        "jgRVA": "0x%08X" % img.rva(jg_pos),
        "jgOff": jg_off,
        "expectedMatches": count,
        "sig": sig.hex().upper(),
    }, count


# ---------------------------------------------------------------------------
# Optional symbol filter: without symbols the finder surfaces every gate-shaped
# idiom in .text (the real gates plus many unrelated enum dispatches). Given a
# symbol table it keeps only candidates that fall inside one of the MV2 gate
# functions, and names them after it. Accepts either JSON (flat
# [{name,rva,size}] or symbols_from_pdb.py's {label: [[name,rva,size],...]}) or
# raw `nm -S` output, so the same flag works from a Windows PDB or a Linux
# chrome.debug.
# ---------------------------------------------------------------------------
GATE_KEYWORDS = (
    "isextensionaffected", "shouldblockextension", "onextensionsystemready",
    "maybereenableextension", "usermayinstall", "mustremaindisabled",
)


def _is_gate_name(name):
    low = name.lower()
    return any(k in low for k in GATE_KEYWORDS)


def load_symbols(path):
    """Return [(name, start_rva, end_rva)] for gate functions. Missing sizes get
    a conservative default span so inlined checks near the entry still fall in."""
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    entries = []  # (name, rva, size)
    text = raw.strip()
    if text[:1] in "[{":
        doc = json.loads(text)
        rows = []
        if isinstance(doc, dict):
            for v in doc.values():
                rows.extend(v)
        else:
            rows = doc
        for r in rows:
            if isinstance(r, dict):
                entries.append((r.get("name", "?"), int(r["rva"], 0) if isinstance(r["rva"], str) else int(r["rva"]), int(r.get("size", 0))))
            else:  # [name, rva, size]
                entries.append((r[0], int(r[1]), int(r[2]) if len(r) > 2 else 0))
    else:
        # nm output: "<hex addr> [<hex size>] <type> <name>"
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            if len(parts) >= 4:  # nm -S: addr size type name
                try:
                    size = int(parts[1], 16)
                except ValueError:
                    size = 0
                name = " ".join(parts[3:])
            else:                # nm: addr type name
                size, name = 0, " ".join(parts[2:])
            entries.append((name, addr, size))

    ranges = []
    for name, rva, size in entries:
        if not _is_gate_name(name):
            continue
        span = size if size > 0 else 0x600
        ranges.append((name, rva, rva + span))
    return ranges


def name_for(ranges, jg_rva):
    for name, lo, hi in ranges:
        if lo <= jg_rva < hi:
            return name
    return None


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
def milestone_name_for(base, img):
    """Give every non-x64-PE container an arch/OS-tagged milestone name so each
    lands in a distinct, non-cross-probing table and never collides with the bare
    x64-PE name: Mach-O slices 151 -> 151-macos-arm64, Windows arm64 151 ->
    151-win-arm64, arm64 ELF 151 -> 151-linux-arm64, x86_64 ELF 151 -> 151-linux,
    32-bit PE 151 -> 151-x86. Only the x64 PE (container 'pe') keeps the base name.
    This mirrors the naming convention already shipped in signatures.json."""
    if img.container.startswith("macho-"):
        return f"{base}-macos-{img.container.split('-', 1)[1]}"
    if img.container == "pe-arm64":
        return f"{base}-win-arm64"
    if img.container == "elf-arm64":
        return f"{base}-linux-arm64"
    if img.container == "elf":
        return f"{base}-linux"
    if img.container == "pe32":
        return f"{base}-x86"
    return base


def build_sites(img, ranges):
    """Locate gates and package each as a signatures.json site dict. Returns
    (sites, dropped) where dropped counts symbol-filtered non-gate candidates."""
    gates = find_gates_for(img)
    sites = []
    dropped = 0
    for idx, (cmp_pos, jg_pos, kind) in enumerate(gates, 1):
        jg_rva = img.rva(jg_pos)
        name = name_for(ranges, jg_rva) if ranges else f"site{idx}"
        if ranges and name is None:
            dropped += 1
            continue  # not inside a gate function - discard the false positive
        site, _count = build_site(img, cmp_pos, jg_pos, kind, name)
        sites.append(site)
    return sites, dropped


def cmd_derive(img, milestone_name, as_json, ranges):
    sites, dropped = build_sites(img, ranges)

    if as_json:
        entry = {"name": milestone_name, "container": img.container, "sites": sites}
        print(json.dumps({"milestones": [entry]}, indent=2))
        return 0

    print(f"# container={img.container}  .text virt=0x{img.text_virt:X} "
          f"raw=0x{img.text_raw:X} size=0x{img.text_size:X}")
    if ranges:
        print(f"# {len(sites)} gate site(s) inside {len(ranges)} named gate function(s); "
              f"{dropped} non-gate candidate(s) dropped:\n")
    else:
        print(f"# {len(sites)} IsExtensionAffected gate candidate(s) "
              f"(no --symbols: run symbols_from_pdb.py or nm to name/filter these):\n")
    for s in sites:
        flag = "" if s["expectedMatches"] <= 2 else "  <-- WIDEN (count>2, sig not unique)"
        print(f"  {s['kind']:5} jg@{s['jgRVA']}  jgOff={s['jgOff']:>2}  "
              f"matches={s['expectedMatches']}{flag}  {s['name']}")
        print(f"        sig={s['sig']}")
    if as_json:
        return 0
    print("\n# Re-run with --json to emit a signatures.json entry.")
    return 0


def locate_featurebyte(img, site):
    """Mirror the runtime featurebyte locator: name-anchored .rdata struct find.
    `site` is a signatures.json site dict. Returns patch-byte file offsets."""
    if not img.rdata_size or not img.imagebase:
        return []
    data = img.data
    lo, hi = img.rdata_raw, img.rdata_raw + img.rdata_size
    patch_off = int(site["patchOff"])
    stock, patched = int(site["stock"]), int(site["patched"])
    verify = {int(str(k), 0): int(v) for k, v in (site.get("verify") or {}).items()}
    expected = int(site["expectedMatches"])

    def decode(base):
        poff = base + patch_off
        if poff < lo or poff >= hi or data[poff] not in (stock, patched):
            return None
        for off, exp in verify.items():
            vo = base + off
            if vo < lo or vo >= hi or data[vo] != exp:
                return None
        return poff

    sr = site.get("structRVA")
    if sr:
        srva = int(str(sr), 16)
        if img.rdata_virt <= srva < img.rdata_virt + img.rdata_size:
            p = decode(img.rdata_raw + (srva - img.rdata_virt))
            if p is not None:
                return [p]
    needle = site["feature"].encode("latin1") + b"\x00"
    found, li = [], lo
    while True:
        i = data.find(needle, li, hi)
        if i < 0:
            break
        li = i + 1
        lit_rva = img.rdata_virt + (i - img.rdata_raw)
        ptr = (img.imagebase + lit_rva).to_bytes(8, "little")
        p = lo
        while True:
            j = data.find(ptr, p, hi)
            if j < 0:
                break
            p = j + 1
            po = decode(j)
            if po is not None and po not in found:
                found.append(po)
                if len(found) > expected:
                    return found
    return found


# 64-bit SimpleFeatureData field offsets (FeatureData 0x28 + SimpleFeatureConfig).
# See mv2-reversing.md; used only by the --feature emitter.
_FB = {"ext_types_size": 0x60, "location_has": 0xB4, "min_has": 0xBC,
       "max_val": 0xC0, "max_has": 0xC4, "channel_val": 0xD8, "channel_has": 0xDC}


def emit_featurebyte(img, feature):
    """Find `feature`'s rule-1 SimpleFeatureData (extension_types size 2, a set
    max_manifest_version, no location/min) and emit its featurebyte site dict
    (max_manifest_version value -> value+1). PE x64 ('pe') only."""
    if img.container != "pe":
        raise ValueError("--feature derivation is supported only for the 'pe' (x64) container")
    if not img.rdata_size or not img.imagebase:
        raise ValueError("no .rdata section found")
    data = img.data
    lo, hi = img.rdata_raw, img.rdata_raw + img.rdata_size
    needle = feature.encode("latin1") + b"\x00"
    hits, li = [], lo
    while True:
        i = data.find(needle, li, hi)
        if i < 0:
            break
        li = i + 1
        lit_rva = img.rdata_virt + (i - img.rdata_raw)
        ptr = (img.imagebase + lit_rva).to_bytes(8, "little")
        p = lo
        while True:
            j = data.find(ptr, p, hi)
            if j < 0:
                break
            p = j + 1
            et_size = struct.unpack_from("<Q", data, j + _FB["ext_types_size"])[0]
            loc_has = data[j + _FB["location_has"]]
            min_has = data[j + _FB["min_has"]]
            max_val = struct.unpack_from("<i", data, j + _FB["max_val"])[0]
            max_has = data[j + _FB["max_has"]]
            if et_size == 2 and max_has == 1 and loc_has == 0 and min_has == 0:
                struct_rva = img.rdata_virt + (j - img.rdata_raw)
                hits.append((struct_rva, max_val))
    if len(hits) != 1:
        raise ValueError(f"expected exactly 1 rule-1 struct for {feature!r}, found {len(hits)}")
    struct_rva, max_val = hits[0]
    return {
        "name": f"{feature} permission feature rule 1 (max_manifest_version {max_val}->{max_val + 1}; grants MV3)",
        "kind": "featurebyte", "optional": True, "feature": feature,
        "structRVA": "0x%08X" % struct_rva, "patchOff": _FB["max_val"],
        "stock": max_val, "patched": max_val + 1,
        "verify": {str(_FB["ext_types_size"]): 2, str(_FB["location_has"]): 0,
                   str(_FB["min_has"]): 0, str(_FB["max_has"]): 1},
        "expectedMatches": 1,
    }


def cmd_verify(img, json_path):
    """Report each milestone's fit against this one binary. A binary is a single
    Chrome version, so only its matching milestone verifies fully - success is
    "at least one milestone of this container fully covers the build", which is
    how the runtime scripts pick the best-matching milestone to apply."""
    doc = json.loads(Path(json_path).read_text(encoding="utf-8"))
    text = img.text
    candidates = [ms for ms in doc.get("milestones", []) if ms.get("container") == img.container]
    if not candidates:
        print(f"# no '{img.container}' milestones in {json_path} to verify against this binary")
        return 1

    any_full = False
    for ms in candidates:
        ok_count = 0
        req_total = 0
        rows = []
        for s in ms["sites"]:
            expected = s["expectedMatches"]
            optional = bool(s.get("optional"))
            if s.get("kind") == "featurebyte":
                hits = locate_featurebyte(img, s)
                label = "feat"
            else:
                hits = masked_match_count(text, bytes.fromhex(s["sig"]), s["jgOff"], s["kind"],
                                          cap=expected + 2)
                label = s["kind"]
            ok = len(hits) == expected
            mark = "OK " if ok else f"x got {len(hits)}"
            tag = f"{label:5}{' opt' if optional else ''}"
            rows.append(f"    [{mark}] {tag} exp={expected} {s['name'][:52]}")
            if optional:
                continue          # best-effort; never affects the milestone verdict
            req_total += 1
            ok_count += ok
        full = ok_count == req_total
        any_full |= full
        verdict = "VERIFIED" if full else "partial"
        print(f"milestone {ms['name']}: {verdict} ({ok_count}/{req_total})")
        print("\n".join(rows))
    print("\nALL SITES VERIFIED:", any_full,
          "(binary is fully covered by a milestone)" if any_full else "(no milestone fully matches)")
    return 0 if any_full else 1


def main():
    ap = argparse.ArgumentParser(description="Cross-platform MV2 gate derivation/verification.")
    ap.add_argument("binary", help="stock chrome.dll (PE), chrome (ELF), or Google Chrome Framework (Mach-O)")
    ap.add_argument("--name", default="NEW", help="milestone name for the emitted entry (e.g. 153)")
    ap.add_argument("--json", action="store_true", help="emit a signatures.json entry")
    ap.add_argument("--symbols", metavar="FILE",
                    help="symbol table (symbols_from_pdb.py JSON, or `nm -S` output) to "
                         "name and filter candidates to real gate functions")
    ap.add_argument("--verify", metavar="signatures.json", nargs="?", const=str(DEFAULT_JSON),
                    help="verify an existing table against the binary (default: signatures.json)")
    ap.add_argument("--feature", metavar="NAME",
                    help="emit a featurebyte site for permission feature NAME (e.g. webRequestBlocking): "
                         "flips its rule-1 max_manifest_version to grant the permission to MV3 (pe x64 only)")
    args = ap.parse_args()

    try:
        imgs = open_images(args.binary)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    multi = len(imgs) > 1  # a universal Mach-O has one Image per CPU slice

    if args.feature:
        for img in imgs:
            if multi:
                print(f"\n=== slice: {img.container} ===")
            try:
                site = emit_featurebyte(img, args.feature)
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            print(json.dumps(site, indent=2))
        return 0

    if args.verify is not None:
        rc = 0
        for img in imgs:
            if multi:
                print(f"\n=== slice: {img.container} ===")
            if cmd_verify(img, args.verify) != 0:
                rc = 1
        return rc

    ranges = []
    if args.symbols:
        try:
            ranges = load_symbols(args.symbols)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"error reading --symbols: {e}", file=sys.stderr)
            return 2
        if not ranges:
            print("warning: no MV2 gate functions found in the symbol file; "
                  "showing all candidates unfiltered", file=sys.stderr)

    if args.json:
        # Emit one document; a universal binary yields one milestone per slice.
        milestones = []
        for img in imgs:
            sites, _dropped = build_sites(img, ranges)
            milestones.append({"name": milestone_name_for(args.name, img),
                               "container": img.container, "sites": sites})
        print(json.dumps({"milestones": milestones}, indent=2))
        return 0

    for img in imgs:
        if multi:
            print(f"\n=== slice: {img.container} ===")
        cmd_derive(img, milestone_name_for(args.name, img), False, ranges)
    return 0


if __name__ == "__main__":
    sys.exit(main())
