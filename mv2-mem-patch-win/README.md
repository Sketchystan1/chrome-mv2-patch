# Windows MV2 DLL

C++20 `version.dll` and `secur32.dll` proxies discover Chrome's MV2 checks at
startup and patch them in memory. They support x64, x86 and ARM64, with a 300,000-byte build
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
build/x64/secur32.dll
build/x86/version.dll
build/x86/secur32.dll
build/arm64/version.dll
build/arm64/secur32.dll
```

CMake intermediates, fetched Detours sources, test programs and diagnostic tools
go into ignored `out/<arch>/` directories. The default build produces only the DLLs.

In Visual Studio, choose **File > Open > Folder**, open `mv2-mem-patch-win`,
select **x64 Release**, **x86 Release** or **ARM64 Release**, and build the
`version` or `secur32` target. Visual Studio and `build.bat`
share the same CMake presets.

## Install a local build

1. Close the browser copy being tested.
2. Copy the matching `build/<arch>/version.dll` beside its `chrome.exe`.
3. Launch it with a separate `--user-data-dir` for the trial.

The browser's `chrome.dll` on disk is unchanged. Close the browser and remove the
proxy DLL to restore stock behavior. `/MD` requires the matching Microsoft Visual
C++ runtime and Windows UCRT. Redistribute `out/<arch>/Detours-LICENSE.md` with the
DLL; release packaging includes it outside the build directory.

The [repository installers](../README.md) download the published release.

### secur32.dll automatic patcher beside the executable

Copy `build/<arch>/secur32.dll` beside **`chrome.exe` or `msedge.exe`**. Use one
automatic proxy per browser copy, and test with a separate `--user-data-dir`.
The placement is the same for both browsers:

```text
Chrome: Application/chrome.exe
        Application/secur32.dll
Edge:   Application/msedge.exe
        Application/secur32.dll
```

It forwards all 98 system exports, including 91 Windows forwarders, to the
absolute System32 path. The parent installs a temporary `QueryPerformanceCounter`
import hook on the main browser DLL. The browser's main thread runs the existing
scanner synchronously at its next safe clock call, before extension
initialization in the measured runs. The clock import is then restored. An
executable `ChromeMain` lookup hook also covers earlier loading. Children only
forward; this carrier does not change their DLL-signing mitigation policy.

The loader-lock address is checked against ownership during `DllMain`; failed
calibration or an unreadable lock prevents scanning. A held loader lock also
defers the scan. The main-thread selection and clock-call ordering require
rechecking if a browser changes its startup model. No polling thread is used.
Close the browser copy and remove `secur32.dll` to restore stock behavior.

Verified on Windows 11 build 26300 with the **same x64 DLL** beside both
executables:

| Browser | Verified behavior |
| --- | --- |
| Chrome 157.0.8103.79 | Packed external MV2 enables and blocks requests; all nine memory gates match; warm and empty-cache restarts pass; removal restores MV2 deprecation. |
| Edge 157.0.4341.46 | Developer-signed CRX3 installation from Downloads, enablement and MV2 background execution pass. Both installer gates apply; shared store detection stays unchanged. Tampered packages and missing developer proofs are rejected. |

Native secur32 forwarding and loader-lock checks passed on x64 and x86.
Ordinary browser-window startup also passed for both browsers on a private
Windows desktop, without the headless flag; Chrome's nine memory gates matched.
x64, x86 and ARM64 DLLs build below 300,000 bytes. Native x86/ARM64 browser
launches, interactive browsing and updates were not validated. See the
[carrier results](SECUR32-AUTOPATCH-RESULTS.json) and [Edge CRX results](EDGE-CRX-RESULTS.json).

The Chrome runtime harness accepts
`--dll mv2-mem-patch-win/build/x64/secur32.dll`, places it beside the executable,
and also verifies a restart after removing the cached scan plan.

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
runtime debug log; unknown layouts are skipped. x86 and ARM64 also run bounded
optional recognition. Browser lifecycle validation covers x64 Chrome/Chromium
152–159; other versions and native ARM64 browser behavior are not guaranteed.

## Installing downloaded CRX files

The local **x64** build also recognizes Chrome's off-store download gate. On a
recognized layout, a developer-signed CRX3 can install without Chrome Web Store
publisher proof, avoiding `CRX_REQUIRED_PROOF_MISSING` for that missing proof.

For **Edge x64**, close all Edge processes, copy `build/x64/secur32.dll` beside
`msedge.exe`, and restart. Keep the downloaded file, open it from `edge://downloads`,
and confirm **Add extension**. You can also enable **Developer mode** at
`edge://extensions` and drag the CRX onto that page. Enable an existing extension
there if the old source block left it disabled. Edge still labels off-store
extensions as coming from an unknown source; they can remain enabled.

Edge recognition requires both installer checks and is verified on
157.0.4341.46 x64. Its MV2 support already works stock. Signature, package
integrity and management-policy checks remain enforced; unknown Edge layouts
are declined. See [validation](EDGE-CRX-RESULTS.json).

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
