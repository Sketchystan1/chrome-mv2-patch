"""Check browser-memory readiness with simulated Windows reads and elapsed time."""
import ctypes as C
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

if os.name == 'nt':
    import test_autoscan_runtime as runtime
else:
    runtime = None


@unittest.skipIf(runtime is None, 'Windows-only browser memory helper')
class MemoryCheckTests(unittest.TestCase):
    def check(self, observed, *, patched=True, optional=False, allow_offstore=True):
        self.elapsed = 0
        self.sleeps = []
        self.snapshots = []
        self.module_iter = iter(())
        report = dict(gates=[dict(rva=0x20, optional=optional, stock='7F34', patch='EB34')])

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.elapsed += seconds

        def snapshot(*args):
            handle = 100 + len(self.snapshots)
            self.snapshots.append(handle)
            return handle

        def next_module(handle, pointer):
            item = next(self.module_iter, None)
            if item is None:
                return False
            module = C.cast(pointer, C.POINTER(runtime.Module)).contents
            module.szModule, module.szExePath, module.modBaseAddr = item
            return True

        def first_module(handle, pointer):
            modules = [('chrome.dll', 'C:/owned/app/chrome.dll', 0x100000),
                       ('SspiCli.dll', 'C:/Windows/System32/SspiCli.dll', 0x200000),
                       ('Secur32.dll', 'C:/Windows/System32/Secur32.dll', 0x280000)]
            if self.elapsed >= .5:
                modules.append(('Secur32.dll', 'C:/owned/app/Secur32.dll', 0x300000))
            self.module_iter = iter(modules)
            return next_module(handle, pointer)

        def read(process, address, buffer, size, got):
            self.assertEqual((process, address, size), (202, 0x100020, 2))
            body = observed(self.elapsed) if callable(observed) else observed
            if body is None:
                return False
            count = min(len(body), size)
            C.memmove(buffer, body, count)
            C.cast(got, C.POINTER(C.c_size_t)).contents.value = count
            return True

        self.api = SimpleNamespace(
            CreateToolhelp32Snapshot=Mock(side_effect=snapshot),
            OpenProcess=Mock(return_value=202),
            Module32FirstW=Mock(side_effect=first_module),
            Module32NextW=Mock(side_effect=next_module),
            ReadProcessMemory=Mock(side_effect=read),
            CloseHandle=Mock())
        clock = SimpleNamespace(monotonic=lambda: self.elapsed, sleep=sleep)
        with patch.object(runtime, 'K', self.api), patch.object(runtime, 'time', clock):
            try:
                runtime.memory_check(42, report, patched, allow_offstore)
            finally:
                self.assertCountEqual([args[0] for args, kwargs in self.api.CloseHandle.call_args_list],
                                      self.snapshots + [202])

    def test_already_patched_returns_without_waiting(self):
        self.check(bytes.fromhex('EB34'))
        self.assertEqual(self.sleeps, [])
        self.assertEqual(self.api.ReadProcessMemory.call_count, 1)

    def test_stock_waits_for_patch_without_hex_case_dependency(self):
        self.check(lambda elapsed: bytes.fromhex('7f34' if elapsed < .5 else 'eb34'))
        self.assertGreaterEqual(self.elapsed, .5)
        self.assertLess(self.elapsed, 75)
        self.assertGreater(self.api.ReadProcessMemory.call_count, 1)

    def test_persistent_stock_times_out_with_latest_security_paths(self):
        with self.assertRaisesRegex(AssertionError, 'memory decision differs') as caught:
            self.check(bytes.fromhex('7f34'))
        self.assertGreaterEqual(self.elapsed, 75)
        self.assertLess(self.elapsed, 75.2)
        self.assertIn('C:/Windows/System32/SspiCli.dll', str(caught.exception))
        self.assertIn('C:/Windows/System32/Secur32.dll', str(caught.exception))
        self.assertIn('C:/owned/app/Secur32.dll', str(caught.exception))

    def test_unexpected_bytes_fail_without_waiting(self):
        with self.assertRaisesRegex(AssertionError, 'memory decision differs') as caught:
            self.check(bytes.fromhex('7F35'))
        self.assertEqual(self.sleeps, [])
        self.assertEqual(self.api.ReadProcessMemory.call_count, 1)
        self.assertIn('C:/Windows/System32/SspiCli.dll', str(caught.exception))

    def test_partial_and_failed_reads_fail_without_waiting(self):
        for observed in (b'\x7f', None):
            with self.subTest(observed=observed):
                with self.assertRaises(AssertionError):
                    self.check(observed)
                self.assertEqual(self.sleeps, [])
                self.assertEqual(self.api.ReadProcessMemory.call_count, 1)

    def test_unpatched_stock_returns_without_waiting(self):
        self.check(bytes.fromhex('7f34'), patched=False)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(self.api.ReadProcessMemory.call_count, 1)

    def test_disabled_optional_gate_rejects_patch_without_waiting(self):
        with self.assertRaisesRegex(AssertionError, 'memory decision differs'):
            self.check(bytes.fromhex('eb34'), optional=True, allow_offstore=False)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(self.api.ReadProcessMemory.call_count, 1)


if __name__ == '__main__':
    unittest.main()
