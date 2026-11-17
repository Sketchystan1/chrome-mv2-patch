"""Ensure discovery evaluation uses independent evidence and catches coverage loss."""
import copy
import unittest

from check_autoscan_matrix import evaluate_report

DIGEST = "a" * 64


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.entry = dict(version="fixture", binary="fixture.dll", reviewed_baseline=dict(
            sha256=DIGEST, provenance="independent source review",
            core=["0x1010", "0x1020"], optional=["0x1030"]))
        self.report = dict(ready=True, sha256=DIGEST, unresolved=[], error="",
                           gates=[dict(rva=0x1010), dict(rva=0x1020)])

    def evaluate(self):
        return evaluate_report(self.entry, self.report, DIGEST, 0.125)

    def test_core_passes_without_optional_check(self):
        result = self.evaluate()
        self.assertTrue(result["passed"])
        self.assertEqual(result["optional_found"], 0)

    def test_reviewed_optional_check_is_accepted(self):
        self.report["gates"].append(dict(rva=0x1030))
        self.assertTrue(self.evaluate()["passed"])

    def test_missing_required_check_fails(self):
        self.report["gates"].pop()
        result = self.evaluate()
        self.assertFalse(result["passed"])
        self.assertEqual(result["missing"], ["0x1020"])

    def test_unreviewed_check_fails(self):
        self.report["gates"].append(dict(rva=0x1040))
        result = self.evaluate()
        self.assertFalse(result["passed"])
        self.assertEqual(result["extra"], ["0x1040"])

    def test_declined_or_unresolved_scan_fails(self):
        original = copy.deepcopy(self.report)
        for change in (dict(ready=False), dict(unresolved=[dict(reason="unknown")]),
                       dict(error="invalid image")):
            self.report = dict(original, **change)
            self.assertFalse(self.evaluate()["passed"])

    def test_report_and_matrix_identities_are_checked(self):
        self.report["sha256"] = "b" * 64
        self.assertFalse(self.evaluate()["passed"])
        self.report["sha256"] = DIGEST
        self.entry["sha256"] = "b" * 64
        self.assertFalse(self.evaluate()["passed"])

    def test_baseline_identity_and_provenance_are_required(self):
        baseline = copy.deepcopy(self.entry["reviewed_baseline"])
        for change in (dict(sha256="b" * 64), dict(provenance=" "),
                       dict(provenance=None)):
            self.entry["reviewed_baseline"] = dict(baseline, **change)
            with self.assertRaises(ValueError):
                self.evaluate()

    def test_baseline_is_required_without_a_signature_table(self):
        del self.entry["reviewed_baseline"]
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_empty_overlapping_and_duplicate_core_are_rejected(self):
        for core in ([], ["0x1030"], ["0x1010", "0x1010"]):
            self.entry["reviewed_baseline"]["core"] = core
            with self.assertRaises(ValueError):
                self.evaluate()

    def test_invalid_and_duplicate_report_addresses_are_rejected(self):
        for gates in ([dict(rva=0)], [dict(rva=True)], [dict(rva=1.5)],
                      [dict(rva=0x1010), dict(rva=0x1010)]):
            self.report["gates"] = gates
            with self.assertRaises(ValueError):
                self.evaluate()


if __name__ == "__main__":
    unittest.main()
