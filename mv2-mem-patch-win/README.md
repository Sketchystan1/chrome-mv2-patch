# Windows MV2 DLL

A C++20 `version.dll` proxy that discovers Chrome's MV2 checks at startup and
patches them in memory. It supports x64, x86 and ARM64, with a 150,000-byte build
limit. No signature table, Capstone or Z3 is used by this DLL.

## Build

Install Visual Studio 2022 or newer with **Desktop development with C++**,
**C++ CMake tools for Windows** (including Ninja), and the ARM64 compiler tools
if building ARM64. From the repository root:

```powershell
.\mv2-mem-patch-win\build.bat
# Optional: build.bat x64, x86, arm64, or all (default).
```

The only files in `build/` are:

```text
build/x64/version.dll
build/x86/version.dll
build/arm64/version.dll
```

CMake intermediates, fetched Detours sources, test programs and diagnostic tools
go into ignored `out/<arch>/` directories. The default build produces only the DLLs.

In Visual Studio, choose **File > Open > Folder**, open `mv2-mem-patch-win`,
select **x64 Release**, **x86 Release** or **ARM64 Release**, and build the
`version` target. Visual Studio and `build.bat` share the same CMake presets.

## Install a local build

1. Close the browser copy being tested.
2. Copy the matching `build/<arch>/version.dll` beside its `chrome.exe`.
3. Launch it with a separate `--user-data-dir` for the trial.

The browser's `chrome.dll` on disk is unchanged. Close the browser and remove the
proxy DLL to restore stock behavior. `/MD` requires the matching Microsoft Visual
C++ runtime and Windows UCRT. Redistribute `out/<arch>/Detours-LICENSE.md` with the
DLL; release packaging includes it outside the build directory.

The [repository installers](../README.md) download the published release.

## Off-store extensions

The local **x64** build automatically enables off-store support wherever the
scanner recognizes InstallVerifier's gate. This covers extensions disabled with
“This extension is not listed in the Chrome Web Store and may have been added
without your knowledge.” No extra launch flag is needed; the old
`--mv2-allow-offstore` argument can be removed.

Close all processes for that Chrome installation, including background apps,
replace its proxy with the new DLL, and launch Chrome normally. Enable the
extension at `chrome://extensions` if it is still disabled.

This applies to all off-store extensions in that browser process. Management
policy and corruption checks still apply. Close Chrome and remove the proxy DLL
to restore stock behavior. An unavailable off-store gate is reported in the
runtime debug log; unknown layouts are skipped. x86 and ARM64 currently support
core MV2 discovery only. Recognition has been checked on x64 Chrome/Chromium
152–159; other versions are not guaranteed.

## Installing downloaded CRX files

The local **x64** build also recognizes Chrome's off-store download gate. On a
recognized layout, a developer-signed CRX3 can install without Chrome Web Store
publisher proof, avoiding `CRX_REQUIRED_PROOF_MISSING` for that missing proof.

After replacing the DLL and restarting Chrome:

1. Download the CRX from a source you trust and keep the file if Chrome prompts.
2. If Chrome has not already opened the install dialog, open the CRX from
   Downloads (`chrome://downloads`).
3. Confirm **Add extension**.

You can also enable **Developer mode** at `chrome://extensions` and drag the CRX
onto that page. No extra launch flag is needed. Opening a CRX from Windows
Explorer depends on the system's file association.

Developer signatures, package integrity checks and the install confirmation
remain enforced. A package missing its developer proof can still report the same
error; damaged or incorrectly signed files remain invalid. This allows manual
off-store downloads in that browser process, so use CRXs you trust. Unknown
download-gate layouts are skipped and reported in the debug log. This capability
is in the local build; the repository installer downloads the published release.

## Tests and diagnostics

After building, use a matching Visual Studio Developer Command Prompt in this
folder. For x64:

```bat
cmake --build out/x64
ctest --preset x64
out\x64\mv2-scan.exe "C:\path\to\chrome.dll"
```

Use `x86` or `arm64` for the other targets. ARM64 tests require ARM64 Windows.
Tests and the read-only scanner remain in `out/`; they are not deployment files.
The older table-based engine is retained for `scripts/test_memory.py` regressions.

After building ARM64, its legacy engine checks can also run on x64 Windows with
MSVC ARM64 tools and WSLC:

```bat
python ..\scripts\test_memory.py --arm64
```

This uses `linaro/wine-arm64:10.2` to execute the legacy engine and patched ARM64
instructions under Wine/QEMU. The compact DLL is tested by the CMake targets above.

[Implementation and limits](AUTOSCAN.md) · [Measured results](AUTOSCAN-RESULTS.json)
