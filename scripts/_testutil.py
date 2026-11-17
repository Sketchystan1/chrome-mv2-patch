"""Synthetic PE/ELF/Mach-O fixtures for analysis and installer tests."""
import struct
from pathlib import Path


def make_elf(path, sig_hex, build_byte=0x11, machine=62):
    """ELF64 with payload at file offset 0x140 and a GNU build-id note."""
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
    """PE x64/x86/ARM64 with payload at 0x400+sig_off, RVA 0x1000+sig_off."""
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
    struct.pack_into("<H", buf, opt, 0x10B if machine == 0x14C else 0x20B)
    struct.pack_into("<I", buf, opt + (92 if machine == 0x14C else 108), 16)            # NumberOfRvaAndSizes
    if signed:
        struct.pack_into("<I", buf, opt + (128 if machine == 0x14C else 144), 0x700)     # Security dir VA
        struct.pack_into("<I", buf, opt + (132 if machine == 0x14C else 148), 0x20)      # Security dir size
    section = opt + 0xF0
    buf[section:section + 5] = b".text"
    struct.pack_into("<I", buf, section + 8, 0x200)       # VirtualSize
    struct.pack_into("<I", buf, section + 12, 0x1000)     # VirtualAddress (RVA)
    struct.pack_into("<I", buf, section + 16, 0x200)      # SizeOfRawData
    struct.pack_into("<I", buf, section + 20, 0x400)      # PointerToRawData
    sig = bytes.fromhex(sig_hex)
    buf[0x400 + sig_off:0x400 + sig_off + len(sig)] = sig
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

