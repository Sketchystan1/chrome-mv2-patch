"""Build and run the actual Windows memory engine's C++ assertions.

Requires the MSVC x64 tools and the Detours sources fetched by build.bat.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parent.parent


def main():
    if sys.platform != "win32":
        print("Memory patcher tests skipped: Windows required")
        return 0
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    detours = REPO / "mv2-mem-patch-win/detours/src"
    if not vswhere.is_file() or not (detours / "detours.cpp").is_file():
        print("Memory patcher tests skipped: run build.bat with MSVC installed first")
        return 0
    vs = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires",
                                  "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                                  "-property", "installationPath"], text=True).strip()
    if not vs:
        print("Memory patcher tests skipped: MSVC x64 tools unavailable")
        return 0
    with tempfile.TemporaryDirectory(prefix="mv2-memory-tests-") as directory:
        work = Path(directory)
        assert work.resolve().parent == Path(tempfile.gettempdir()).resolve()
        sources = [REPO / "scripts/test_memory.cpp"] + [detours / (name + ".cpp") for name in
                   ("detours", "disasm", "image", "modules", "disolx64")]
        command = 'cl /nologo /O2 /W3 /EHsc /std:c++20 /FIintrin.h /DUNICODE /D_UNICODE /D_AMD64_ '
        command += f'/I"{detours}" /Fe:tests.exe ' + " ".join(f'"{p}"' for p in sources)
        command += " /link kernel32.lib winhttp.lib /MANIFEST:NO\n"
        batch = work / "build.cmd"
        batch.write_text(f'@echo off\ncall "{vs}/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\n'
                         'if errorlevel 1 exit /b 1\n' + command, encoding="utf-8")
        result = subprocess.run(["cmd", "/d", "/c", str(batch)], cwd=work, capture_output=True, text=True)
        if result.returncode:
            print(result.stdout + result.stderr)
            return result.returncode
        return subprocess.call([str(work / "tests.exe")], cwd=work)


if __name__ == "__main__":
    sys.exit(main())
