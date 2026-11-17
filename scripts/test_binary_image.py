"""Portable image-reader checks for current analysis and future native ports."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import _testutil as T
from binary_image import open_images, parse_elf, parse_macho, parse_pe


class ImageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="mv2-image-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "fixture"

    def test_pe_architectures_and_address_mapping(self):
        for machine, container in ((0x8664, "pe"), (0x14C, "pe32"), (0xAA64, "pe-arm64")):
            with self.subTest(container=container):
                T.make_pe(self.path, "90", machine=machine)
                stock = self.path.read_bytes()
                image, = open_images(self.path)
                self.assertEqual(image.container, container)
                self.assertEqual(image.text_raw, 0x400)
                self.assertEqual(image.rva(0x40), 0x1040)
                self.assertEqual(image.off(0x1040), 0x40)
                self.assertEqual(image.text[0x40], 0x90)
                self.assertEqual(self.path.read_bytes(), stock)

    def test_elf_virtual_addresses_are_not_file_offsets(self):
        for machine, container in ((0x3E, "elf"), (0xB7, "elf-arm64")):
            with self.subTest(container=container):
                T.make_elf(self.path, "41424344", machine=machine)
                image, = open_images(self.path)
                self.assertEqual(image.container, container)
                self.assertEqual(image.rva(0x40), 0x400040)
                self.assertEqual(image.text_raw + image.off(0x400040), 0x140)
                self.assertEqual(image.text[0x40:0x44], b"ABCD")

    def test_fat_macho_uses_arm64_slice_offset_and_uuid(self):
        T.make_fat_macho(self.path)
        image, = open_images(self.path)
        self.assertEqual(image.container, "macho-arm64")
        self.assertEqual(image.macho_base, 0x2000)
        self.assertEqual(image.text_raw, image.macho_base + 0x200)
        self.assertEqual(image.rva(0x40), 0x100000040)
        self.assertEqual(image.uuid, "b2" * 16)

    def test_fat64_macho_is_read(self):
        T.make_fat_macho(self.path)
        data = bytearray(self.path.read_bytes())
        entries = [struct.unpack_from(">IIIII", data, 8 + index * 20) for index in range(2)]
        header = struct.pack(">II", 0xCAFEBABF, 2)
        for cpu, subtype, offset, size, alignment in entries:
            header += struct.pack(">IIQQII", cpu, subtype, offset, size, alignment, 0)
        data[:len(header)] = header
        image, = parse_macho(data)
        self.assertEqual(image.macho_base, 0x2000)
        self.assertEqual(image.uuid, "b2" * 16)

    def test_thin_macho_and_unsupported_cpu(self):
        arm = T._macho_thin(0x0100000C, b"\x1f\x20\x03\xd5", 0xA1)
        image, = parse_macho(arm)
        self.assertEqual(image.text_raw, 0x200)
        self.assertEqual(image.text, b"\x1f\x20\x03\xd5")
        with self.assertRaises(ValueError):
            parse_macho(T._macho_thin(0x01000007, b"\x90", 0xA1))

    def test_pe_truncation_and_unknown_machine_are_rejected(self):
        T.make_pe(self.path, "90")
        stock = bytearray(self.path.read_bytes())
        with self.assertRaises(ValueError):
            parse_pe(stock[:64])
        struct.pack_into("<H", stock, 0x84, 0xFFFF)
        with self.assertRaises(ValueError):
            parse_pe(stock)

    def test_pe_text_outside_file_is_rejected(self):
        T.make_pe(self.path, "90")
        data = bytearray(self.path.read_bytes())
        struct.pack_into("<I", data, 0x188 + 16, len(data))
        with self.assertRaises(ValueError):
            parse_pe(data)

    def test_elf_bad_section_names_and_machine_are_rejected(self):
        T.make_elf(self.path, "90")
        stock = bytearray(self.path.read_bytes())
        data = stock.copy()
        struct.pack_into("<I", data, 0x540, 0xFFFFFFFF)
        with self.assertRaises(ValueError):
            parse_elf(data)
        struct.pack_into("<H", stock, 0x12, 3)
        with self.assertRaises(ValueError):
            parse_elf(stock)

    def test_supported_macho_slice_cannot_read_past_declared_bounds(self):
        T.make_fat_macho(self.path)
        data = bytearray(self.path.read_bytes())
        struct.pack_into(">I", data, 8 + 20 + 12, 32)
        with self.assertRaises(ValueError):
            parse_macho(data)

    def test_macho_load_commands_are_bounded(self):
        data = bytearray(T._macho_thin(0x0100000C, b"\x1f\x20\x03\xd5", 0xA1))
        struct.pack_into("<I", data, 32 + 4, len(data))
        with self.assertRaises(ValueError):
            parse_macho(data)

    def test_empty_file_is_rejected(self):
        self.path.write_bytes(b"")
        with self.assertRaises(ValueError):
            open_images(self.path)

    def test_cli_reports_metadata_without_changing_image(self):
        T.make_elf(self.path, "90")
        stock = self.path.read_bytes()
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("binary_image.py")),
                                 str(self.path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata, = json.loads(result.stdout)
        self.assertEqual(metadata["container"], "elf")
        self.assertEqual(metadata["text_file_offset"], "0x100")
        self.assertEqual(self.path.read_bytes(), stock)


if __name__ == "__main__":
    unittest.main()
