"""Run the full local test suite (flat, Python).

Replaces scripts/tests/run-tests.ps1. Runs the per-target test files, syntax-
checks the shell patchers, and parse-checks the PowerShell patcher when pwsh is
available. Each step's non-zero exit fails the run.

    python scripts/run_tests.py
"""
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
import _testutil as T


def step(title, cmd):
    print(f"\n=== {title} ===")
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print(f"FAILED: {title}", file=sys.stderr)
        sys.exit(r.returncode)


def main():
    py = [sys.executable]
    # Engine + gate-finder unit checks (fast, pure Python).
    step("derivation unit checks (arm64 bcond safety)", py + [str(HERE / "test_derive.py")])

    # Table audits: seconds, no binary needed, and they catch defects no per-binary
    # test can see - two milestones with identical signature sets make the patcher
    # decline every build they match, and an embedded table that drifted from
    # signatures.json ships a patcher that needs an external file to work.
    step("audit signatures.json", py + [str(HERE / "audit_signatures.py"),
                                        str(REPO / "signatures.json")])
    step("embedded tables match signatures.json",
         py + [str(HERE / "sync_embedded.py"), "--check"])

    # Black-box patcher tests (shell out to the runtime scripts).
    step("Linux ELF (chrome-mv2.sh)", py + [str(HERE / "test_linux.py")])
    step("macOS Mach-O (chrome-mv2.sh)", py + [str(HERE / "test_macos.py")])
    step("Windows PE (chrome-mv2.ps1)", py + [str(HERE / "test_windows.py")])

    # Universal Python patcher: byte-compile, then the cross-platform black-box
    # suite (PE + ELF + Mach-O all run on any OS via the test env toggles).
    step("compile chrome-mv2.py", py + ["-m", "py_compile", str(REPO / "chrome-mv2.py")])
    step("Universal Python (chrome-mv2.py)", py + [str(HERE / "test_pyport.py")])

    # Syntax check for the shell patcher (one cross-platform script). Use the
    # resolved bash (T.BASH): a bare "bash" in subprocess can hit the WSL launcher
    # on Windows, which cannot read the git-bash /c/... path form T.posix emits.
    if T.BASH:
        step("bash -n chrome-mv2.sh", [T.BASH, "-n", T.posix(REPO / "chrome-mv2.sh")])
    else:
        print("\n(bash not found; skipping shell syntax checks)")

    # Parse-check the PowerShell patcher.
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if pwsh:
        ps = (r"$t=$null;$e=$null;"
              r"[Management.Automation.Language.Parser]::ParseFile("
              rf"'{REPO / 'chrome-mv2.ps1'}',[ref]$t,[ref]$e)|Out-Null;"
              r"if($e.Count){$e|%{Write-Error $_.Message};exit 1}")
        step("parse chrome-mv2.ps1", [pwsh, "-NoProfile", "-Command", ps])
    else:
        print("\n(pwsh not found; skipping PowerShell parse check)")

    print("\nAll tests passed.")


if __name__ == "__main__":
    main()
