"""Checks for signature-free x64 discovery and its decoded predicate model."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

if not all(importlib.util.find_spec(name) for name in ('capstone', 'z3')):
    print('SKIP: scan_windows tests need capstone and z3-solver')
    raise SystemExit(0)

import _testutil as T
from derive_milestone import open_images
from scan_windows import Scanner, resolve_binary, runtime_plan


# Complete functions: branch targets include the type checks after the first RET.
FREE = bytes.fromhex('31c083f9027f1f83fa08771ab90a0100000fa3d173104183f8050f95c14183f80a0f95c020c8c3')
MEMBER = bytes.fromhex('837a50027f37488b8a280200008b415080ba0802000000750b8b898800000083f901750f83f8050f95c183f80a0f95c020c8c383f90874ec83f90374e731c0ebf1')
INVERTED = bytes.fromhex('837a50027e0331c0c3488b82280200008b485080ba080200000075198b908800000031c083fa0877df41b80a010000410fa3d073d383f9050f95c283f90a0f95c020d0ebc3')


class ScanTests(unittest.TestCase):
    def image(self, code):
        with tempfile.TemporaryDirectory(prefix='mv2-autoscan-') as directory:
            root = Path(directory).resolve()
            self.assertEqual(root.parent, Path(tempfile.gettempdir()).resolve())
            path = root / 'chrome.dll'
            T.make_pe(path, code.hex(), sig_off=0x40)
            data = bytearray(path.read_bytes())
            data[0x400:0x600] = b'\xCC' * 0x200
            data[0x440:0x440 + len(code)] = code
            path.write_bytes(data)
            return open_images(str(path))[0]

    def scan(self, code):
        return Scanner(self.image(code)).scan()

    def test_free_predicate_and_type_range(self):
        result = self.scan(FREE)
        self.assertEqual(len(result['gates']), 1)
        self.assertFalse(result['unresolved'])
        # Keep CMP type,8 but remove its JA: BT wraps the index for type 33.
        missing_range = FREE.replace(bytes.fromhex('771a'), b'\x90\x90')
        rejected = self.scan(missing_range)
        self.assertFalse(rejected['gates'])
        self.assertTrue(rejected['unresolved'])

    def test_wrong_location_polarity_is_rejected(self):
        rejected = self.scan(FREE.replace(bytes.fromhex('0f95c1'), bytes.fromhex('0f94c1')))
        self.assertFalse(rejected['gates'])
        self.assertTrue(rejected['unresolved'])

    def test_member_follows_branches_after_return(self):
        result = self.scan(MEMBER)
        self.assertEqual(len(result['gates']), 1)
        self.assertEqual(result['gates'][0]['fields']['type'], 0x88)

    def test_inverted_bool_return_ignores_dead_upper_bits(self):
        result = self.scan(INVERTED)
        self.assertEqual(len(result['gates']), 1)
        self.assertEqual(result['gates'][0]['kind'], 'short-nop')
        self.assertFalse(result['unresolved'])
        wrong_result = INVERTED.replace(bytes.fromhex('0f95c0'), bytes.fromhex('0f94c0'))
        self.assertFalse(self.scan(wrong_result)['gates'])

    def test_field_offsets_are_recovered(self):
        changed = (MEMBER.replace(bytes.fromhex('837a50'), bytes.fromhex('837a70'))
                   .replace(bytes.fromhex('28020000'), bytes.fromhex('48030000'))
                   .replace(bytes.fromhex('8b4150'), bytes.fromhex('8b4138'))
                   .replace(bytes.fromhex('08020000'), bytes.fromhex('00030000'))
                   .replace(bytes.fromhex('88000000'), bytes.fromhex('a4000000')))
        result = self.scan(changed)
        self.assertEqual(len(result['gates']), 1)
        self.assertEqual(result['gates'][0]['fields'], {
            'manifest_version': 0x70, 'manifest': 0x348, 'type': 0xA4,
            'location': 0x38, 'converted_user_script': 0x300})

    def test_equivalent_threshold_and_operand_width(self):
        ge = FREE.replace(bytes.fromhex('83f9027f'), bytes.fromhex('83f9037d'))
        self.assertEqual(len(self.scan(ge)['gates']), 1)
        narrow = FREE[:2] + b'\x66' + FREE[2:]
        self.assertFalse(self.scan(narrow)['gates'])

    def test_previous_displacement_is_not_an_instruction_prefix(self):
        # The JNE displacement 2E can decode as a spurious CS prefix on CMP.
        prefix = bytes.fromhex('31c085c0752e')
        result = self.scan(prefix + FREE[2:])
        self.assertEqual(len(result['gates']), 1)
        self.assertEqual(result['gates'][0]['compare_rva'], '0x1046')

    def test_same_constants_from_different_fields_do_not_match(self):
        # The location==10 check now reads EDX instead of EAX.
        wrong_value = MEMBER.replace(bytes.fromhex('83f80a'), bytes.fromhex('83fa0a'))
        self.assertFalse(self.scan(wrong_value)['gates'])

    def test_csp_selector_is_not_a_predicate(self):
        selector = bytes.fromhex('837a50027f0a488b8a2802000083798806c3')
        self.assertFalse(self.scan(selector)['gates'])

    def test_plan_is_generated_from_the_current_image(self):
        image = self.image(FREE)
        report = Scanner(image).scan()
        report['sha256'] = hashlib.sha256(image.data).hexdigest()
        plan = runtime_plan(image, report)
        self.assertEqual(plan['binary_sha256'], report['sha256'])
        self.assertEqual(plan['milestones'], [])
        sites = plan['milestones_v2'][0]['sites']
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]['kind'], 'short')
        self.assertEqual(sites[0]['expectedMatches'], 1)
        report['unresolved'].append({'reason': 'unknown code'})
        with self.assertRaises(ValueError):
            runtime_plan(image, report)

    def test_truncated_text_is_rejected(self):
        image = self.image(FREE)
        image.text_size = len(image.data)
        with self.assertRaises(ValueError):
            Scanner(image)

    def test_launcher_resolution_declines_multiple_dlls(self):
        with tempfile.TemporaryDirectory(prefix='mv2-autoscan-') as directory:
            root = Path(directory).resolve()
            self.assertEqual(root.parent, Path(tempfile.gettempdir()).resolve())
            exe = root / 'chrome.exe'
            exe.touch()
            for version in ('1', '2'):
                (root / version).mkdir()
                (root / version / 'chrome.dll').touch()
            with self.assertRaises(ValueError):
                resolve_binary(exe)


if __name__ == '__main__':
    unittest.main()
