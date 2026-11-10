"""Build and run the legacy table-based Windows memory engine's C++ assertions.

Requires MSVC and the Detours headers fetched by build.bat.
--arm64 uses the ARM64 cross tools and WSLC with linaro/wine-arm64:10.2.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm64", action="store_true", help="run ARM64 tests through WSLC/Wine")
    args = parser.parse_args()
    if sys.platform != "win32":
        print("Memory patcher tests skipped: Windows required")
        return 1 if args.arm64 else 0
    if args.arm64 and not shutil.which("wslc"):
        print("ARM64 tests require wslc on PATH", file=sys.stderr)
        return 1
    arch = "arm64" if args.arm64 else "x64"
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    detours = REPO / f"mv2-mem-patch-win/out/{arch}/_deps/detours_src-src/src"
    if not vswhere.is_file() or not (detours / "detours.h").is_file():
        print("Memory patcher tests skipped: run build.bat with MSVC installed first")
        return 1 if args.arm64 else 0
    vs = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires",
                                  "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                                  "-property", "installationPath"], text=True).strip()
    if not vs:
        print("Memory patcher tests skipped: MSVC x64 tools unavailable")
        return 1 if args.arm64 else 0
    with tempfile.TemporaryDirectory(prefix="mv2-memory-tests-") as directory:
        work = Path(directory)
        assert work.resolve().parent == Path(tempfile.gettempdir()).resolve()
        command = 'cl /nologo /O2 /W3 /EHsc /std:c++20 /FIintrin.h /DUNICODE /D_UNICODE '
        command += f'/I"{detours}" /Fe:tests.exe "{REPO / "scripts/test_memory.cpp"}"'
        command += " /link kernel32.lib winhttp.lib /MANIFEST:NO\n"
        batch = work / "build.cmd"
        vcarg = "x64_arm64" if args.arm64 else "x64"
        batch.write_text(f'@echo off\ncall "{vs}/VC/Auxiliary/Build/vcvarsall.bat" {vcarg} >nul\n'
                         'if errorlevel 1 exit /b 1\n'
                         f'if not exist "%VCToolsInstallDir%bin\\Hostx64\\{arch}\\cl.exe" exit /b 1\n'
                         + command, encoding="utf-8")
        result = subprocess.run(["cmd", "/d", "/c", str(batch)], cwd=work, capture_output=True, text=True)
        if result.returncode:
            print(result.stdout + result.stderr)
            return result.returncode
        if args.arm64:
            return subprocess.call([
                "wslc", "run", "--rm", "--mount", f"type=bind,source={work},target=/tests,readonly",
                "linaro/wine-arm64:10.2", "timeout", "120", "wine-arm64", "/tests/tests.exe",
            ])
        return subprocess.call([str(work / "tests.exe")], cwd=work)


if __name__ == "__main__":
    sys.exit(main())
