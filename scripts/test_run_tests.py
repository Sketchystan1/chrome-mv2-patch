"""Check that focused test runs omit unrelated and unavailable suites."""
import contextlib
import io
from pathlib import Path
import unittest
from unittest.mock import patch

import run_tests


class SelectionTests(unittest.TestCase):
    def run_selected(self, arguments, *, node="node", platform="nt", failed=()):
        with patch.object(run_tests.os, "name", platform), \
                patch.dict(run_tests.os.environ, {"MV2_TEST_FAST": "0"}), \
                patch.object(run_tests.shutil, "which", return_value=node), \
                patch.object(run_tests, "run_wave", return_value=list(failed)) as wave, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = run_tests.main(arguments)
        return code, wave

    def test_only_runs_requested_suites_once(self):
        code, wave = self.run_selected(["--only", "fetch", "crx-cdp", "fetch"])
        self.assertEqual(code, 0)
        steps = wave.call_args.args[0]
        self.assertEqual([Path(command[-1]).name for _, command in steps],
                         ["test_fetch_arm64_browser.py", "autoscan_crx_cdp.mjs"])

    def test_unrelated_missing_dependencies_do_not_block_selection(self):
        code, wave = self.run_selected(["--only", "image"], node=None, platform="posix")
        self.assertEqual(code, 0)
        self.assertEqual(len(wave.call_args.args[0]), 1)

    def test_explicit_unavailable_suites_fail_before_running(self):
        for arguments, options in ((["--only", "cdp"], dict(node=None)),
                                   (["--only", "installer"], dict(platform="posix"))):
            with self.subTest(arguments=arguments):
                code, wave = self.run_selected(arguments, **options)
                self.assertEqual(code, 1)
                wave.assert_not_called()

    def test_fast_default_omits_installer(self):
        code, wave = self.run_selected(["--fast"])
        self.assertEqual(code, 0)
        self.assertEqual(len(wave.call_args.args[0]), len(run_tests.SUITES) - 1)
        self.assertFalse(any("test_install.py" in command[-1] for _, command in wave.call_args.args[0]))

    def test_failure_is_propagated(self):
        code, _ = self.run_selected(["--only", "fetch"], failed=["fetch"])
        self.assertEqual(code, 1)

    def test_fast_conflicts_with_explicit_installer(self):
        with self.assertRaises(SystemExit) as failure:
            self.run_selected(["--fast", "--only", "installer"])
        self.assertEqual(failure.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
