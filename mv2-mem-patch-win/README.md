# Windows MV2 memory patcher

Version **2.0.0**. A native `secur32.dll` for Windows x64, x86 and ARM64. It
patches recognized Chrome/Chromium MV2 decisions and optional off-store extension
and CRX installation checks in memory. Edge uses separate installer checks.

The user reports that installed Edge SxS Canary 160.0.4415.0 x64 works with
uBlock Origin 1.76.4. Edge Stable ARM64 passed the seven-phase lifecycle. The
latest extracted-copy Edge Beta/Canary ARM64 tests read stock gate bytes; their
verified payloads lack the installed top-level `Application/msedge.exe`, so the
separate direct DLL-only check reports `not_tested`. Installed Beta/Canary
support remains unresolved. See
[PERFORMANCE.md](PERFORMANCE.md#edge-beta-and-canary-arm64-follow-up).

Browser files on disk stay unchanged. Close the browser and remove the added DLL
to restore its original checks on the next launch. Support depends on recognizing
the browser's code; future versions can change those checks or remove MV2 entirely.

## Startup and cache

1. Loads the real Windows `secur32.dll` from the system directory and forwards
   its 98 listed functions.
2. Waits for a validated startup call on the main Chrome or Edge thread, outside
   Windows' DLL-loading lock. Child processes only forward the Windows functions.
3. Opens the browser DLL read-only and calculates its complete file fingerprint.
   A cache miss starts Windows' `rundll32.exe` to analyze the file using a helper
   in this DLL. The browser waits up to 30 seconds. Analysis runs on a joined
   worker with a 1 MiB stack reserve, including in the small-stack x86 host.
4. Validates the plan and compares the loaded `.text` section with the stock file,
   accounting for loader relocations. Only recognized decision instructions may
   differ. Unsupported or ambiguous core checks decline the plan; unrecognized
   optional Chrome checks are skipped. Edge requires both installer checks.
5. Makes the affected pages writable, edits and verifies them, flushes the
   instruction cache and restores protection. Failure rolls back every edit.
   Failed rollback or protection restoration stops the browser.

| Area | Access or change |
| --- | --- |
| Browser files | Reads the browser DLL and this project's DLL; does not overwrite browser executables. |
| Browser memory | Changes verified MV2/source decisions and startup function pointers in the main process. |
| Cache | Reads and writes DPAPI-protected `%LOCALAPPDATA%\chrome-mv2-patch\autoscan\*.bin` plans, bound to browser BLAKE3, scanner SHA-256 and protocol version. Temporary files replace entries only after a complete write. |
| Profiles and registry | The deployed DLL does not edit extension preferences or registry settings. The installer and test helpers have separate behavior described below. |
| Network | The deployed project code has no download, telemetry or outbound-request routine. Building downloads two pinned libraries; Windows file access can reach a redirected network share. |

## Install or remove

### Batch installer

Keep `install.bat` and the matching `secur32.dll` together, either in an extracted
release or a local `build/<arch>/` folder. Right-click the batch file and select
**Run as administrator**; it does not elevate itself.

Choose a browser by number or paste its folder, executable or DLL path. Paths
with spaces accept optional surrounding quotes; **0** opens the custom-path
prompt. The numbered **Scan for Custom Browser Paths** option finds custom or
portable installations and adds their paths to the browser list. The action menu
offers **1 Install**, **2 Uninstall** and **0 Quit**.
Detection covers Chrome and Edge Stable, Beta, Dev and Canary, plus standard
machine/per-user `Chromium\Application` folders. The DLL must match the browser's
processor type. Installation does not guarantee that its code is recognized.
Install uBlock Origin separately; the batch does not install extensions.

```bat
install.bat install "C:\Program Files (x86)\Microsoft\Edge\Application"
install.bat check "C:\Program Files (x86)\Microsoft\Edge\Application" -Quiet
install.bat check -Search
install.bat uninstall "C:\Program Files (x86)\Microsoft\Edge\Application"
install.bat cleanup -Quiet
```

`-Quiet` skips normal prompts; errors still wait for a key. `check` is read-only.
Specify a path when multiple installations are found. `cleanup` handles all
detected installations; a supplied path also includes a portable installation.
`-Search` runs the drive search before selecting a browser. Drives are searched
in parallel; NTFS uses its file metadata instead of walking every directory.
Other filesystems, or unavailable NTFS metadata, fall back to one directory
traversal per drive. Network drives and directory junctions are excluded;
inaccessible folders and additional hard-link aliases can be missed.
The batch uses built-in Windows commands and embedded PowerShell, and disables
console QuickEdit so text selection cannot suspend it.

Install skips DLL replacement when the installed and local files match, while
still performing legacy cleanup. Current `secur32.dll` patches in other
installations are preserved. Uninstall limits removal to the selected browser;
repeating it after cleanup leaves the browser running.

### Browser shutdown and restart

When changes are needed, the batch closes only your processes whose executable
path matches the affected installation. It asks windows to close, waits up to
15 seconds, briefly allows session writes, then stops remaining background
processes, including Edge startup boost workers. Restarting processes are retried
for up to five seconds. A forced close can lose unsaved page data.

A temporary Task Scheduler task reopens each closed browser with normal user
privileges and `--restore-last-session`, including after an operation fails.
Task Scheduler must be running. Already closed browsers stay closed. Session
restoration depends on the saved session; custom startup flags and profile paths
are not retained.

### Legacy cleanup

Install automatically cleans old patcher files and registry entries across
detected Chrome, Chromium and Edge installations. Other running installations
are deferred; explicit `cleanup` closes each installation that needs changes.
Cleanup preserves current `secur32.dll` patches, backups and unrelated DLLs.
Legacy byte patches require restoring stock Chrome first.

Cleanup removes branded old `version.dll` proxies, leftover `signatures.json`
beside browser executables and in `%LOCALAPPDATA%\chrome-mv2-patch`, and the old
uBlock Origin registration under the browser's `Extensions` registry key. Other
files in the data folder are preserved; leftover signatures and registry entries
are removed even when the old proxy is already gone.

**Chrome cleanup clears the entire `HKLM\Software\Policies\Google\Chrome` key
in both registry views, including unrelated policies.** Uninstall removes the
selected browser's proxy, legacy files and old extension registration without
clearing Chrome policies.

### Manual installation

Paths under `build/` and `out/` are relative to this folder.

1. Close all processes for the browser installation, including background apps.
2. Copy `build/<arch>/secur32.dll` beside `chrome.exe` or `msedge.exe`, matching
   the browser's processor type. Use one patcher DLL per browser copy.
3. Test with a separate profile, for example
   `chrome.exe --user-data-dir="C:\mv2-test-profile"`.

```text
Chrome: Application/chrome.exe
        Application/secur32.dll
Edge:   Application/msedge.exe
        Application/secur32.dll
```

To remove it, close that browser copy and delete the added `secur32.dll`. The
scan cache can also be deleted while the browser is closed; it is recreated when
needed. Removal does not undo extensions or profile changes made through the
browser while the patch was installed.

## Off-store extensions and CRX installation

The source changes relax restrictions for **all extensions in that browser
process**. Recognized paths retain developer-signature, package-integrity,
management-policy and installation-confirmation checks. Use sources you trust;
these changes do not make an extension trustworthy or remove warning labels.

A recognized InstallVerifier layout permits enabling extensions disabled with
“This extension is not listed in the Chrome Web Store and may have been added
without your knowledge.” After installation and restart, enable the extension
at `chrome://extensions` or `edge://extensions` if needed. The old
`--mv2-allow-offstore` argument can be removed. Unrecognized optional Chrome
checks are skipped and reported in the debug log.

On a recognized x86 or x64 download layout, a developer-signed CRX3 can install
without Chrome Web Store publisher proof. This addresses
`CRX_REQUIRED_PROOF_MISSING` when the missing proof is the store's publisher
proof. Missing developer proofs, damaged packages and invalid signatures remain
rejected.

1. Download a CRX from a source you trust and keep it if prompted.
2. Open it from `chrome://downloads` or `edge://downloads`.
3. Confirm **Add extension**.

Alternatively, enable **Developer mode** on the extensions page and drag the CRX
there. Opening it from Explorer depends on file associations. Edge retains its
unknown-source label and requires both recognized installer checks; MV2 already
works in the recorded stock Edge build.

## Build

Install Visual Studio 2022 or newer with **Desktop development with C++** and
**C++ CMake tools for Windows** (including Ninja). ARM64 also needs its compiler
tools. From the repository root:

```bat
mv2-mem-patch-win\build.bat
rem Optional argument: x64, x86, arm64, or all. The default builds all three.
```

Each `mv2-mem-patch-win/build/<arch>/` contains `secur32.dll` and `install.bat`.
Dependencies, intermediates, tests and diagnostic tools go in ignored
`mv2-mem-patch-win/out/<arch>/`. Deployment DLLs and the diagnostic scanner must
be below 300,000 bytes. Release ZIPs contain only the DLL and batch installer.

The build verifies fixed SHA-256 archive checksums for Detours 4.0.1
(`e4bfd6b03e50de46b47abfbd1e46b384f0c5f833`) and BLAKE3 1.8.7
(`f3149ec5bb5449af877ba20377a11008ff499fa2`). It writes their licenses to
`out/<arch>/Detours-LICENSE.md` and `out/<arch>/BLAKE3-LICENSE.md`. The DLL needs
the matching Microsoft Visual C++ runtime and Windows Universal C Runtime.

In Visual Studio, open this folder, select **x64 Release**, **x86 Release** or
**ARM64 Release**, and build `secur32`. Visual Studio and `build.bat` share
`CMakePresets.json`. `CMakeLists.txt` supplies the DLL/release version;
`version.rc` contains its Windows Properties labels.

## Tests and diagnostics

After `build.bat x64`, use a matching Visual Studio Developer Command Prompt in
this folder to build the test targets:

```bat
cmake --build out/x64
ctest --preset x64
out\x64\mv2-scan.exe "C:\path\to\chrome.dll"
```

Use `x86` or `arm64` for the other targets. Native ARM64 execution requires ARM64
Windows; the x64 suite also tests ARM64 instruction layouts. The
[scripts README](../scripts/README.md) documents portable fixtures and isolated
browser lifecycle/CRX tests.

ARM64 browser-test helpers use a newer checksum-pinned Detours source because
4.0.1's full ARM64 hooker is incomplete. The deployed DLL retains its existing
Detours import enumerator. The test source license is copied to
`out/arm64/Detours-test-LICENSE.md`.

`mv2-scan.exe` reads the file and prints JSON with SHA-256/BLAKE3 fingerprints,
proposed bytes, skipped optional checks and unresolved candidates. It does not
launch or patch a browser. Exit codes are **0** for a ready plan, **1** for a
declined plan and **2** for an invocation/file/output error. DebugView messages
start with `[mv2patch autoscan]` and include scan/cache timings.

Test programs and fixture DLLs are separate from deployment files. They use
fabricated images, temporary caches and failed Windows calls to check rejection,
rollback, protection and cleanup. The browser launcher uses a test-only DLL to
redirect matching extension registry operations into a private subtree; closing
the launcher terminates its test-browser process tree.

## Implementation and limits

| File(s) | Responsibility |
| --- | --- |
| `autopatch_proxy.cpp`, `secur32-exports.txt`, `hook.hpp`, `loader_lock.h` | Forward system functions and validate the startup hook. |
| `autoscan_runtime.cpp`, `autoscan_runtime.h`, `autoscan_cache.cpp` | Read the stock image, run the helper and authenticate cached plans. |
| `autoscan.cpp`, `autoscan.h`, `boundaries.hpp`, `lifter.hpp`, `solver.hpp` | Parse function bounds, decode instructions and prove recognized decisions. |
| `autoscan_apply.cpp`, `text_compare.hpp` | Independently validate loaded code, apply edits and roll back failures. |
| `blake3_threads.cpp` | Parallel file hashing with joined workers. |
| `autoscan_cli.cpp` | Read-only diagnostic reports. |
| `*_test.cpp`, `test_launch.cpp`, `test_registry.cpp` | Native fixtures and isolated browser-test helpers. |
| `CMakeLists.txt`, `CMakePresets.json`, `build.bat`, `check-size.cmake`, `version.rc` | Build configuration, output checks and DLL labels. |

The scanner infers member relationships from each browser file and verifies the
[reviewed Chromium predicate](../mv2-reversing.md#1-the-source-predicate). It uses
no signature table, debug symbols, Capstone or Z3. Unsupported instructions,
conflicting evidence and exhausted bounds decline recognition. Project scanner
buffers have fixed capacity; Windows APIs and the C runtime can still allocate.

Cache protection is for the current Windows user, not a boundary against other
code running as that user. Cache hits still require full-file identity and
loaded-code comparison, so they add startup work.

Patch pages change execute/read → read/write → verified edit and instruction-cache
flush → execute/read. No deployed path requests writable/executable memory.
Patching depends on startup occurring before the affected routines run; changed
startup ordering needs validation. Memory protection does not guarantee antivirus
acceptance.

`complete_enforcement_coverage_proven` remains **false**. Bounded recognition does
not prove that every MV2 enforcement check was found. x86 function bounds include
heuristics, and compiler changes can escape recognition.

## Validation record

[PERFORMANCE.md](PERFORMANCE.md) owns the dates, exact browser/DLL fingerprints,
check counts, reproduction commands and failure records. Results apply to those
artifacts; a new DLL or browser build needs fresh validation.

| Recorded browser | Verified behavior |
| --- | --- |
| Chrome 157.0.8103.79 x64 | Packed external MV2 enablement, request blocking, cached/empty-cache restarts and removal. |
| Chrome Stable 158.0.8127.37 x64/x86/ARM64 | Signed CRX3 installation and MV2 lifecycle; x86 requires the November 18 discovery fix. |
| Chrome Beta 159.0.8154.6 x86 | Signed CRX3 installation and MV2 lifecycle. |
| Chrome Beta 159.0.8154.13 ARM64 | Signed CRX3 installation and MV2 lifecycle on native Windows ARM64 CI. |
| Chrome Dev 160.0.8157.0 x86 | Signed CRX3 installation and MV2 lifecycle. |
| Chrome Canary 160.0.8168.0 x64/x86 | Signed CRX3 installation and MV2 lifecycle. |
| Chrome Canary 160.0.8171.0 ARM64 | Signed CRX3 installation and MV2 lifecycle on native Windows ARM64 CI. |
| Chrome Canary 160.0.8166.2 x86 | Signed CRX3 installation and MV2 lifecycle. |
| Chrome Canary 160.0.8167.0 x86 | External MV2 lifecycle; the tested DLL did not recognize the CRX download check. |
| Edge 157.0.4341.46 x64 | Signed CRX3 installation, MV2 execution, restart and removal; tampered packages and missing developer proofs rejected. |
| Edge Stable/Beta/Canary ARM64, initial November 19 CI | Scanner declined before the architecture fixes. |

The November 20 frozen matrix passed all nine Chrome cells and Edge Stable across
all three architectures using `secur32.dll` alone. Native tests passed 20/20 x64,
18/18 x86 and 17/17 ARM64. Edge Stable ARM64's follow-up seven-phase lifecycle
passed. Newer Canary 160.0.8172.1 ARM64 was separately rejected because its
candidate layouts were unsupported; 160.0.8173.0 remains unvalidated. Exact
identities and limits are in [PERFORMANCE.md](PERFORMANCE.md#final-recorded-dll-only-matrix-november-20-2026).

Edge Beta/Canary ARM64 remains unresolved: current verified package extractions
lack the installed Application entrypoint, and the isolated CRX harness uses a
test-only registry shim. It preserves hard memory and signature checks but does
not establish DLL-only loading in the installed launch context. See
[PERFORMANCE.md](PERFORMANCE.md#edge-beta-and-canary-arm64-follow-up).

Chrome CRX lifecycle runs include native confirmation, tampered-signature and
missing-developer-proof rejection, MV3 controls, both restart types and removal.
The November 18 x86 Stable/Beta/Dev/Canary validation passed **28/28 browser
phases and 18/18 native tests** with the identical corrected DLL.
The November 19 ARM64 Stable/Beta/Canary validation passed **21/21 Chrome browser
phases and 17/17 native tests** with an identical ARM64 DLL.
Earlier intermittent startup failures remain unexplained in the validation
record. Browser updates, broader interactive browsing and DRM remain unvalidated.
