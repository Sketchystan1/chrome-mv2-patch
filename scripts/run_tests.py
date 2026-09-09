"""Run the full local test suite (flat, Python).

Replaces scripts/tests/run-tests.ps1. Runs the per-target test files, syntax-
checks the shell patchers, and parse-checks the PowerShell patcher when pwsh is
available. Each step's non-zero exit fails the run.

    python scripts/run_tests.py            # everything
    python scripts/run_tests.py --fast     # skip the slow bash black-box tests

Execution: the steps are independent (each uses its own tmp dir and only reads
the shared tables), so they run CONCURRENTLY in two waves. Wave 1 is the fast,
deterministic set (table audits, the PowerShell PE suite, and the pure-Python
universal port that already exercises PE + ELF + Mach-O); if anything there
fails, the run stops before the slow wave starts, so a real regression still
fails in seconds. Wave 2 is the bash black-box tests (test_linux.py /
test_macos.py), which shell out to chrome-mv2.sh: on a Windows host each of the
~35 patch/restore/check spawns goes through the git-bash/WSL launcher and is
slow (test_linux.py can exceed several minutes) and the environment is fragile.
--fast (or MV2_TEST_FAST=1) skips wave 2; CI still runs it on native
Linux/macOS runners, and test_pyport.py covers the same ELF/Mach-O patch logic
cross-platform via the MV2_TEST_* env toggles.

The steps are spawn/IO-bound, not CPU-bound (the harness itself does almost no
computation - it waits on child processes), so running them on threads and
letting the OS overlap the child processes is what buys the wall-clock, not the
language the harness is written in.
"""
import concurrent.futures
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
import _testutil as T

_print_lock = threading.Lock()


def run_step(title, cmd):
    """Run one step to completion, capturing its output. Returns
    (title, returncode, combined_output). Output is captured (not streamed) so
    concurrent steps don't interleave; each block is printed atomically on
    completion."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    except OSError as e:
        return (title, 127, f"could not launch: {e}")
    return (title, r.returncode, (r.stdout or "") + (r.stderr or ""))


def run_wave(steps):
    """Run steps concurrently; print each result as it finishes. Returns the
    list of failed step titles (empty if all passed)."""
    failed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(steps)) as ex:
        futs = [ex.submit(run_step, title, cmd) for title, cmd in steps]
        for fut in concurrent.futures.as_completed(futs):
            title, rc, out = fut.result()
            with _print_lock:
                print(f"\n=== {title} ===")
                if out.strip():
                    print(out.rstrip())
                print("PASS" if rc == 0 else f"FAILED (exit {rc})")
            if rc != 0:
                failed.append(title)
    return failed


def main():
    fast = "--fast" in sys.argv[1:] or os.environ.get("MV2_TEST_FAST") == "1"
    py = [sys.executable]

    # ---- Wave 1: fast, deterministic checks (run in parallel, fail-fast) ----
    #
    # Table audits are seconds and catch defects no per-binary test can see - two
    # milestones with identical signature sets make the patcher decline every
    # build they match, and an embedded table that drifted from signatures.json
    # ships a patcher that needs an external file to work. The Windows PE suite
    # shells to pwsh; the universal Python patcher's black-box suite covers
    # PE + ELF + Mach-O on any OS via the test env toggles (the fast path that
    # exercises ELF/Mach-O without shelling to bash).
    steps = [
        ("derivation unit checks (arm64 bcond safety)",
         py + [str(HERE / "test_derive.py")]),
        ("audit signatures.json",
         py + [str(HERE / "audit_signatures.py"), str(REPO / "signatures.json")]),
        ("embedded tables match signatures.json",
         py + [str(HERE / "sync_embedded.py"), "--check"]),
        ("Windows PE (chrome-mv2.ps1)", py + [str(HERE / "test_windows.py")]),
        ("compile chrome-mv2.py", py + ["-m", "py_compile", str(REPO / "chrome-mv2.py")]),
        ("Universal Python (chrome-mv2.py)", py + [str(HERE / "test_pyport.py")]),
    ]

    # Syntax check for the shell patcher. Use the resolved bash (T.BASH): a bare
    # "bash" in subprocess can hit the WSL launcher on Windows, which cannot read
    # the git-bash /c/... path form T.posix emits.
    if T.BASH:
        steps.append(("bash -n chrome-mv2.sh",
                     [T.BASH, "-n", T.posix(REPO / "chrome-mv2.sh")]))
    else:
        print("(bash not found; skipping shell syntax checks)")

    # Parse-check the PowerShell patcher.
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if pwsh:
        ps = (r"$t=$null;$e=$null;"
              r"[Management.Automation.Language.Parser]::ParseFile("
              rf"'{REPO / 'chrome-mv2.ps1'}',[ref]$t,[ref]$e)|Out-Null;"
              r"if($e.Count){$e|%{Write-Error $_.Message};exit 1}")
        steps.append(("parse chrome-mv2.ps1", [pwsh, "-NoProfile", "-Command", ps]))
    else:
        print("(pwsh not found; skipping PowerShell parse check)")

    print(f"\n--- Fast checks ({len(steps)} in parallel) ---")
    failed = run_wave(steps)
    if failed:
        print(f"\nFAILED: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)

    # ---- Wave 2: slow bash black-box tests (parallel, skippable with --fast) ----
    if fast:
        print("\n(--fast: skipping the bash black-box tests "
              "test_linux.py / test_macos.py; CI runs them on native Linux/macOS)")
    else:
        slow = [
            ("Linux ELF (chrome-mv2.sh)", py + [str(HERE / "test_linux.py")]),
            ("macOS Mach-O (chrome-mv2.sh)", py + [str(HERE / "test_macos.py")]),
        ]
        print(f"\n--- Bash black-box tests ({len(slow)} in parallel) ---")
        failed = run_wave(slow)
        if failed:
            print(f"\nFAILED: {', '.join(failed)}", file=sys.stderr)
            sys.exit(1)

    print("\nAll tests passed." + (" (--fast: bash black-box skipped)" if fast else ""))


if __name__ == "__main__":
    main()
