"""Evaluate native discovery against independent, hash-bound address baselines.

Each matrix entry needs binary, version and reviewed_baseline (sha256, provenance,
core and optional RVA lists). Baselines are used after discovery and are never
passed to the scanner. No maintained signature table is read.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

REPO = Path(__file__).resolve().parent.parent


def _addresses(values, label):
    if not isinstance(values, list):
        raise ValueError(f"{label} must be an RVA list")
    addresses = []
    for value in values:
        if type(value) not in (str, int):
            raise ValueError(f"{label} contains a non-integer RVA")
        address = int(value, 0) if isinstance(value, str) else value
        if not 0 < address <= 0xFFFFFFFF:
            raise ValueError(f"{label} contains an invalid RVA")
        addresses.append(address)
    if len(set(addresses)) != len(addresses):
        raise ValueError(f"{label} contains duplicate RVAs")
    return set(addresses)


def evaluate_report(entry, report, digest, elapsed):
    baseline = entry.get("reviewed_baseline")
    if not isinstance(baseline, dict):
        raise ValueError("every build needs an independently reviewed baseline")
    provenance = baseline.get("provenance")
    if (baseline.get("sha256") != digest or not isinstance(provenance, str)
            or not provenance.strip()):
        raise ValueError("reviewed baseline lacks matching identity/provenance")
    expected = _addresses(baseline.get("core"), "baseline core")
    optional = _addresses(baseline.get("optional", []), "baseline optional")
    if not expected or expected & optional:
        raise ValueError("reviewed baseline must have distinct, nonempty core addresses")
    actual = _addresses([gate["rva"] for gate in report["gates"]], "scanner decisions")
    missing, extra = expected - actual, actual - expected - optional
    passed = bool(report["ready"] and not report["unresolved"] and not report["error"]
                  and not missing and not extra and report["sha256"] == digest
                  and entry.get("sha256", digest) == digest)
    return dict(version=entry["version"], binary=str(Path(entry["binary"]).resolve()),
                sha256=digest, seconds=round(elapsed, 3), ready=report["ready"],
                evaluation_basis="reviewed baseline: " + provenance.strip(),
                gates=len(actual), known_core=len(expected),
                missing=[hex(value) for value in sorted(missing)],
                extra=[hex(value) for value in sorted(extra)],
                optional_found=len(actual & optional), optional_known=len(optional),
                install_verifier=report.get("install_verifier"),
                crx_download=report.get("crx_download"),
                unresolved=report["unresolved"], error=report["error"], passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix", type=Path)
    parser.add_argument("--scanner", type=Path,
                        default=REPO / "mv2-mem-patch-win/out/x64/mv2-scan.exe")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    results = []
    try:
        entries = json.loads(args.matrix.read_text(encoding="utf-8"))
        if not isinstance(entries, list) or not entries:
            raise ValueError("matrix must be a nonempty JSON list")
        args.output.mkdir(parents=True, exist_ok=True)
        for index, entry in enumerate(entries):
            path = Path(entry["binary"]).resolve()
            started = time.monotonic()
            run = subprocess.run([str(args.scanner), str(path)], capture_output=True,
                                 text=True, encoding="utf-8", errors="replace", timeout=60)
            elapsed = time.monotonic() - started
            if run.returncode not in (0, 1):
                raise ValueError(f"{entry['version']}: scanner failed ({run.returncode}): {run.stderr}")
            report = json.loads(run.stdout)
            (args.output / f"{index:02d}-scan.json").write_text(
                json.dumps(report, indent=2), encoding="utf-8")
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            result = evaluate_report(entry, report, digest, elapsed)
            results.append(result)
            (args.output / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
            print(json.dumps(result), flush=True)
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        parser.exit(2, f"evaluation failed: {error}\n")
    return 0 if all(result["passed"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
