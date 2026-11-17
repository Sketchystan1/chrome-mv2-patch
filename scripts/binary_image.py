"""Read-only PE, ELF and Mach-O code-section metadata for patcher research.

The readers are shared by analysis tools and retained for future native Linux
and macOS ports. Addresses are PE RVAs or ELF/Mach-O virtual addresses; file
offsets remain separate. This module does not discover or apply patches.

    python scripts/binary_image.py <stock-binary>
"""
import argparse
import json
from pathlib import Path
import struct
import sys


def _span(data, offset, size, label):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"{label} exceeds the file")


class Image:
    def __init__(self, container, text_virt, text_raw, text_size, data):
        _span(data, text_raw, text_size, "code section")
        self.container = container
        self.text_virt, self.text_raw, self.text_size = text_virt, text_raw, text_size
        self.data, self._text = data, None
        self.uuid, self.macho_base, self.imagebase = None, 0, None

    @property
    def text(self):
        if self._text is None:
            self._text = self.data[self.text_raw:self.text_raw + self.text_size]
        return self._text

    def rva(self, textpos):
        """Code-section index to PE RVA or ELF/Mach-O virtual address."""
        return self.text_virt + textpos

    def off(self, address):
        """PE RVA or ELF/Mach-O virtual address to code-section index."""
        return address - self.text_virt


def parse_pe(data):
    _span(data, 0, 64, "DOS header")
    if data[:2] != b"MZ":
        raise ValueError("not a PE (bad DOS signature)")
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    _span(data, nt, 24, "PE header")
    if data[nt:nt + 4] != b"PE\0\0":
        raise ValueError("not a PE (bad NT signature)")
    machine, sections = struct.unpack_from("<HH", data, nt + 4)
    optional_size = struct.unpack_from("<H", data, nt + 20)[0]
    opt = nt + 24
    _span(data, opt, optional_size, "PE optional header")
    if optional_size < 32:
        raise ValueError("truncated PE optional header")
    magic = struct.unpack_from("<H", data, opt)[0]
    container = {(0x14C, 0x10B): "pe32", (0x8664, 0x20B): "pe",
                 (0xAA64, 0x20B): "pe-arm64"}.get((machine, magic))
    if container is None:
        raise ValueError("unsupported PE machine/optional-header combination")
    section_table = opt + optional_size
    _span(data, section_table, sections * 40, "PE section table")
    text = None
    for index in range(sections):
        pos = section_table + index * 40
        if data[pos:pos + 8].split(b"\0")[0] == b".text":
            if text is not None:
                raise ValueError("duplicate .text section")
            _, address, size, raw = struct.unpack_from("<IIII", data, pos + 8)
            text = address, raw, size
    if text is None:
        raise ValueError("no .text section")
    image = Image(container, *text, data)
    image.imagebase = (struct.unpack_from("<I", data, opt + 28)[0] if magic == 0x10B
                       else struct.unpack_from("<Q", data, opt + 24)[0])
    return image


def parse_elf(data):
    _span(data, 0, 64, "ELF header")
    if data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
        raise ValueError("not little-endian ELF64")
    machine = struct.unpack_from("<H", data, 0x12)[0]
    container = {0x3E: "elf", 0xB7: "elf-arm64"}.get(machine)
    if container is None:
        raise ValueError("unsupported ELF machine")
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    entry_size, count, names_index = struct.unpack_from("<HHH", data, 0x3A)
    if entry_size < 64 or not count or names_index >= count:
        raise ValueError("invalid ELF section table")
    _span(data, shoff, entry_size * count, "ELF section table")
    names_header = shoff + names_index * entry_size
    names_off, names_size = struct.unpack_from("<QQ", data, names_header + 0x18)
    _span(data, names_off, names_size, "ELF section names")
    names = data[names_off:names_off + names_size]
    text = None
    for index in range(count):
        pos = shoff + index * entry_size
        name_off = struct.unpack_from("<I", data, pos)[0]
        name_end = names.find(b"\0", name_off)
        if name_off >= len(names) or name_end < 0:
            raise ValueError("invalid ELF section name")
        if names[name_off:name_end] == b".text":
            if text is not None:
                raise ValueError("duplicate .text section")
            address, raw, size = struct.unpack_from("<QQQ", data, pos + 0x10)
            text = address, raw, size
    if text is None:
        raise ValueError("no .text section")
    return Image(container, *text, data)


MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B


def _parse_macho_thin(data, base, size, cpu_hint=None):
    _span(data, base, size, "Mach-O slice")
    if size < 32:
        raise ValueError("truncated Mach-O header")
    magic, cpu = struct.unpack_from("<II", data, base)
    if magic != MH_MAGIC_64 or cpu != CPU_TYPE_ARM64:
        raise ValueError("unsupported Mach-O magic/CPU (ARM64 required)")
    if cpu_hint is not None and cpu != cpu_hint:
        raise ValueError("Mach-O slice CPU differs from fat header")
    count, commands_size = struct.unpack_from("<II", data, base + 16)
    if commands_size > size - 32 or count > commands_size // 8:
        raise ValueError("Mach-O load commands exceed the slice")
    pos, commands_end = base + 32, base + 32 + commands_size
    text, uuid = None, None
    for _ in range(count):
        if pos + 8 > commands_end:
            raise ValueError("truncated Mach-O load command")
        command, command_size = struct.unpack_from("<II", data, pos)
        if command_size < 8 or pos + command_size > commands_end:
            raise ValueError("Mach-O load command exceeds its region")
        if command == LC_SEGMENT_64:
            if command_size < 72:
                raise ValueError("truncated Mach-O segment")
            sections = struct.unpack_from("<I", data, pos + 64)[0]
            if sections > (command_size - 72) // 80:
                raise ValueError("Mach-O sections exceed the load command")
            if data[pos + 8:pos + 24].split(b"\0")[0] == b"__TEXT":
                for index in range(sections):
                    section = pos + 72 + index * 80
                    if data[section:section + 16].split(b"\0")[0] == b"__text":
                        if text is not None:
                            raise ValueError("duplicate __text section")
                        address, text_size, raw = struct.unpack_from("<QQI", data, section + 32)
                        if raw + text_size > size:
                            raise ValueError("Mach-O __text exceeds the slice")
                        text = address, base + raw, text_size
        elif command == LC_UUID:
            if command_size < 24:
                raise ValueError("truncated Mach-O UUID")
            uuid = data[pos + 8:pos + 24].hex()
        pos += command_size
    if pos != commands_end:
        raise ValueError("Mach-O load-command count/size mismatch")
    if text is None:
        raise ValueError("no __TEXT,__text section")
    image = Image("macho-arm64", *text, data)
    image.uuid, image.macho_base = uuid, base
    return image


def parse_macho(data):
    _span(data, 0, 8, "Mach-O header")
    magic = struct.unpack_from(">I", data)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return [_parse_macho_thin(data, 0, len(data))]
    count = struct.unpack_from(">I", data, 4)[0]
    entry_size = 32 if magic == FAT_MAGIC_64 else 20
    table_end = 8 + count * entry_size
    _span(data, 8, count * entry_size, "Mach-O fat table")
    images = []
    for index in range(count):
        pos = 8 + index * entry_size
        if magic == FAT_MAGIC_64:
            cpu, _, base, size = struct.unpack_from(">IIQQ", data, pos)
        else:
            cpu, _, base, size = struct.unpack_from(">IIII", data, pos)
        _span(data, base, size, "Mach-O fat slice")
        if base < table_end:
            raise ValueError("Mach-O slice overlaps the fat table")
        if cpu == CPU_TYPE_ARM64:
            images.append(_parse_macho_thin(data, base, size, cpu))
    if not images:
        raise ValueError("no supported ARM64 slices in the fat Mach-O")
    return images


def open_images(path):
    """PE/ELF yield one image; Mach-O yields its supported ARM64 slices."""
    data = Path(path).read_bytes()
    if data[:2] == b"MZ":
        return [parse_pe(data)]
    if data[:4] == b"\x7fELF":
        return [parse_elf(data)]
    magic = struct.unpack_from(">I", data)[0] if len(data) >= 4 else 0
    if magic in (FAT_MAGIC, FAT_MAGIC_64) or data[:4] == b"\xcf\xfa\xed\xfe":
        return parse_macho(data)
    raise ValueError("unrecognized binary (expected PE, ELF or Mach-O)")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    try:
        images = open_images(args.binary)
    except (OSError, ValueError, struct.error) as error:
        parser.exit(2, f"inspection failed: {error}\n")
    print(json.dumps([dict(container=image.container, text_address=hex(image.text_virt),
                           text_file_offset=hex(image.text_raw), text_size=image.text_size,
                           uuid=image.uuid) for image in images], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
