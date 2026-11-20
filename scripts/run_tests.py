"""Run the current analysis fixtures and Windows installer integration checks.

    python scripts/run_tests.py
    python scripts/run_tests.py --fast   # skip Windows installer integration
    python scripts/run_tests.py --only fetch crx-cdp

Native C++ tests and real-browser experiments have separate build/artifact
requirements and are documented in scripts/README.md.
"""
import argparse
import concurrent.futures
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SUITES = ("image", "matrix", "fetch", "macho", "scanner", "installer", "cdp", "crx-cdp", "runner")


def run_step(title, command):
    """Capture one independent check so concurrent output stays readable."""
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                encoding="utf-8", errors="replace")
    except OSError as error:
        return title, 127, f"could not launch: {error}"
    return title, result.returncode, result.stdout + result.stderr


def run_wave(steps):
    failed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(steps)) as executor:
        futures = [executor.submit(run_step, title, command) for title, command in steps]
        for future in concurrent.futures.as_completed(futures):
            title, code, output = future.result()
            print(f"\n=== {title} ===", flush=True)
            if output.strip():
                print(output.rstrip(), flush=True)
            print("PASS" if code == 0 else f"FAILED (exit {code})", flush=True)
            if code:
                failed.append(title)
    return failed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fast", action="store_true",
                        default=os.environ.get("MV2_TEST_FAST") == "1",
                        help="skip Windows installer integration checks")
    parser.add_argument("--only", nargs="+", choices=SUITES,
                        help="run only the named suites needed for this change")
    args = parser.parse_args(argv)
    if args.only and args.fast and "installer" in args.only:
        parser.error("--only installer conflicts with --fast")
    py = [sys.executable]
    checks = {
        "image": ("PE/ELF/Mach-O image readers", py + [str(HERE / "test_binary_image.py")]),
        "matrix": ("Native scanner evaluation", py + [str(HERE / "test_check_autoscan_matrix.py")]),
        "fetch": ("Windows browser fetch", py + [str(HERE / "test_fetch_arm64_browser.py")]),
        "macho": ("Mach-O load-command research", py + [str(HERE / "macho_insert_dylib.py"), "--self-test"]),
        "scanner": ("Windows x64 Python discovery (optional dependencies)",
         py + [str(HERE / "test_scan_windows.py")]),
        "runner": ("Test suite selection", py + [str(HERE / "test_run_tests.py")]),
    }
    selected = set(args.only or SUITES)
    unavailable = []
    if os.name == "nt" and not args.fast:
        checks["installer"] = ("Native Windows batch installer", py + [str(HERE / "test_install.py")])
    elif "installer" in selected:
        unavailable.append("Windows installer integration " + ("(--fast)" if args.fast else "(Windows required)"))
    node = shutil.which("node")
    if node:
        for suite, helper in (("cdp", "autoscan_cdp.mjs"), ("crx-cdp", "autoscan_crx_cdp.mjs")):
            checks[suite] = (f"CDP helper syntax ({helper})", [node, "--check", str(HERE / helper)])
    elif selected.intersection({"cdp", "crx-cdp"}):
        unavailable.append("CDP helper syntax (Node required)")
    for reason in unavailable:
        print(("ERROR: " if args.only else "SKIP: ") + reason)
    if args.only and unavailable:
        return 1
    steps = [checks[suite] for suite in SUITES if suite in selected and suite in checks]
    failed = run_wave(steps)
    if failed:
        print(f"\nFAILED: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("\nAll requested checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
