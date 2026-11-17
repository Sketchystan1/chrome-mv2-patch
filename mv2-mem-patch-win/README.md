# Windows MV2 memory patcher

Version **2.0.0**. This project builds a `secur32.dll` that lets Manifest V2 (MV2)
extensions run in recognized Chrome builds by changing a few instructions in
the running browser's memory. It also recognizes off-store extension and CRX
installation checks in Chrome, and separate installer checks in Edge.

The browser files on disk stay unchanged. Closing the browser and removing the
added DLL restores its original behavior on the next launch. Support depends on
recognizing the browser's code; future versions can change those checks or remove
MV2 entirely.

## What the code does

1. Loads the real Windows `secur32.dll` from the system directory and forwards
   its 98 listed functions. This project's DLL supplies the startup patching;
   Windows continues to handle the forwarded security functions.
2. In the main Chrome or Edge process, waits for a startup call on the browser's
   main thread, outside Windows' DLL-loading lock. Browser child processes only
   forward the Windows functions.
3. Opens the browser DLL read-only and calculates a file fingerprint. It reuses a
   checked scan plan from the user's cache, or starts Windows' `rundll32.exe` to
   analyze the same read-only file with a helper in this DLL. The browser waits
   for the helper, with a 30-second deadline. Analysis runs on a joined worker
   with a 1 MiB stack reserve, including in the small-stack x86 `rundll32` host.
4. Checks the returned plan and compares the browser DLL's main code section
   (`.text`) in memory with the original file,
   accounting for addresses adjusted by Windows. Only recognized decision
   instructions may differ. Unsupported or ambiguous core checks decline the
   plan; unrecognized optional Chrome checks are skipped. Edge requires both of
   its installer checks.
5. Temporarily makes the affected memory pages writable, applies the edits,
   checks them, and restores their original protection. A failure attempts to
   undo every edit. If undoing the edits or restoring protection fails, it stops
   the browser rather than allowing partially patched code to run.

| Area | Actual access or change |
| --- | --- |
| Browser files | Reads the browser DLL and this project's DLL; does not overwrite the browser executables. |
| Browser memory | Changes verified MV2/source decisions and startup function pointers in the main browser process. |
| Cache | Reads and writes `%LOCALAPPDATA%\chrome-mv2-patch\autoscan\*.bin`; Windows protects entries for the current user. Writes use temporary files, replacing the old entry only after a complete write. |
| Processes and threads | Starts the scan helper on a cache miss, terminates that helper if it times out, and uses joined workers for large reads/comparisons. Cleanup may finish in a Windows worker callback. |
| Profiles and registry | The deployed DLL does not edit extension preferences or registry settings. Test-only registry redirection is described below. |
| Network | The deployed project code has no download, telemetry or outbound-request routine. Building downloads two pinned libraries. Windows file access can reach a network share if the cache folder is redirected there. |

The off-store changes intentionally relax browser source restrictions for **all
extensions in that browser process**. Recognized paths retain developer-signature,
package-integrity, management-policy and installation-confirmation checks; a
Chrome Web Store publisher proof is no longer required for the recognized manual
CRX download path. Use extensions from sources you trust. These changes do not
make an extension trustworthy or remove its warning labels.

## Build

Install Visual Studio 2022 or newer with **Desktop development with C++** and
**C++ CMake tools for Windows** (including Ninja). ARM64 builds also need the
ARM64 compiler tools. From the repository root:

```bat
mv2-mem-patch-win\build.bat
rem Build one processor type: build.bat x64, x86, or arm64.
rem No argument, or "all", builds all three.
```

The deployment files are:

```text
build/x64/secur32.dll
build/x86/secur32.dll
build/arm64/secur32.dll
```

Each DLL folder also includes `install.bat`. Keep the batch file and the DLL
together. Downloaded library sources, build
intermediates, tests and the diagnostic scanner stay in ignored `out/<arch>/`
directories. Every deployment DLL and the diagnostic scanner must be below
300,000 bytes.

The build verifies fixed SHA-256 archive checksums for Microsoft Detours 4.0.1
(`e4bfd6b03e50de46b47abfbd1e46b384f0c5f833`) and BLAKE3 1.8.7
(`f3149ec5bb5449af877ba20377a11008ff499fa2`). Runtime dependency downloads are
not needed. The DLL requires the matching Microsoft Visual C++ runtime and
Windows Universal C Runtime. The build writes the library licenses to
`out/<arch>/Detours-LICENSE.md` and `out/<arch>/BLAKE3-LICENSE.md`.
Release ZIPs contain only `install.bat` and `secur32.dll`.

In Visual Studio, open this folder, select **x64 Release**, **x86 Release** or
**ARM64 Release**, and build `secur32`. Visual Studio and `build.bat` share
`CMakePresets.json`. `CMakeLists.txt` supplies the DLL and release version;
`version.rc` contains its Windows Properties labels.

## Install a local build

### secur32.dll automatic patcher beside the executable

Right-click `build/<arch>/install.bat` (or the batch file in an extracted release)
and select **Run as administrator**. Choose an installation by number or paste
its folder, executable or DLL path at the same prompt. Paths with spaces work
with or without surrounding quotes; **0** also opens the custom-path prompt.
The list groups Chrome, Chromium and Edge in that order, without full paths.
Recognized patches show **patch installed**; other entries show only the browser name.
The action menu offers **1 Install**, **2 Uninstall**
and **0 Quit**.
The batch uses built-in Windows commands and an embedded Windows PowerShell
section to select and close browser processes. No separate helper executable is
needed. Install
uBlock Origin manually; the batch does not prompt for or install extensions.
Stable, Beta, Dev and Canary are discovered for Chrome and Edge. Chromium is
discovered in standard `Chromium\Application` folders under machine and per-user
install roots. Detection does not depend on version numbers. The DLL must match
the browser's processor type. Recognition
limits still apply; installation does not guarantee every version can be patched.

```bat
install.bat cleanup -Quiet
install.bat install "C:\Program Files (x86)\Microsoft\Edge\Application"
install.bat check "C:\Program Files (x86)\Microsoft\Edge\Application" -Quiet
install.bat uninstall "C:\Program Files (x86)\Microsoft\Edge\Application"
```

The batch installer uses the local DLL without downloading a release. `-Quiet`
skips normal prompts; errors still wait for a key so their messages remain visible.
It disables QuickEdit text selection in its console window so clicking the window
does not suspend installation, and clears any selection started during startup.
Specify a path for installation or removal when multiple installations
are found. Cleanup processes all detected installations and needs no path. A supplied
path also includes a portable installation in cleanup. Administrator access is
required before browser menus or actions. Without it, the batch shows manual
restart instructions and exits; it does not elevate itself. The command-line
`check` action remains read-only.

Installation skips replacement when the installed DLL matches the local
DLL. It first cleans up old patcher files and registry entries across all detected
Chrome, Chromium and Edge installations, then updates only the selected installation if
needed. Existing
`secur32.dll` patches in other installations are preserved.

Installation and removal close only your processes whose executable path matches
the selected installation when files or old installer entries need changes.
Repeating Uninstall after cleanup leaves the browser running.
Other running Chrome, Chromium and Edge installations
stay open. Automatic legacy cleanup cleans closed installations and defers other
running installations; explicit `cleanup` closes each installation that needs
changes. Each browser that was closed reopens its own executable with
`--restore-last-session`, including after an operation fails. Custom startup flags,
including profile paths, are not retained.

The batch asks browser windows to close and waits up to 15 seconds for them.
After a brief wait for session writes, it stops remaining background processes,
including Edge startup boost workers,
without waiting for background mode to exit on its own. Processes that restart during
shutdown are retried for up to five seconds. A warning appears if browser windows
remain open after the normal close timeout.
Session restoration depends on the browser's saved session; a forced close can lose
unsaved page data. A temporary Task Scheduler task reopens the browser with normal
user privileges and is then removed. Task Scheduler must be running to auto-close
and reopen; a browser that was already closed stays closed.

Cleanup runs automatically before Install. The command-line
`install.bat cleanup` also removes old patcher files across all detected
installations without replacing any current `secur32.dll`.
Legacy Chrome byte patches require restoring stock Chrome first; backups and
unrelated DLLs are preserved. Cleanup removes branded old `version.dll` proxies
and also removes leftover signature files and registry entries when that DLL is
already gone. It removes `signatures.json` beside each browser executable and in
`%LOCALAPPDATA%\chrome-mv2-patch`; other files in that data folder are preserved.
Chrome cleanup clears the entire `HKLM\Software\Policies\Google\Chrome` key in
both registry views, including policies unrelated to this patch. Uninstall removes
legacy files and the old uBlock registration without clearing Chrome policies.
The old uBlock Origin registration is removed from `Microsoft\Edge\Extensions`
for Edge, `Google\Chrome\Extensions` for Chrome and `Chromium\Extensions` for
Chromium during global cleanup.
Uninstall limits proxy and registry removal to the selected browser.

For a manual installation:

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
needed. Removal restores the browser's checks, but does not undo extensions or
profile changes made through the browser while the patch was installed.

## Off-store extensions

On a recognized InstallVerifier layout, the patch permits enabling extensions
disabled with “This extension is not listed in the Chrome Web Store and may have
been added without your knowledge.” No extra launch flag is needed; the old
`--mv2-allow-offstore` argument can be removed.

After installing and restarting, enable the extension at `chrome://extensions`
or `edge://extensions` if it is still disabled. Management policy and corruption
checks still apply. An unrecognized optional Chrome gate is skipped and reported
in the debug log. x86 and ARM64 include optional recognition. Native browser
lifecycle checks include recorded x64 builds and Chrome Canary 160.0.8167.0 x86.

## Installing downloaded CRX files

On a recognized x64 download layout, a developer-signed CRX3 can install without
Chrome Web Store publisher proof. This addresses `CRX_REQUIRED_PROOF_MISSING`
when the missing proof is the store's publisher proof. A missing developer proof
or a damaged or incorrectly signed package remains invalid.

1. Download a CRX from a source you trust and keep it if the browser prompts.
2. Open it from `chrome://downloads` or `edge://downloads`.
3. Confirm **Add extension**.

Alternatively, enable **Developer mode** on the browser's extensions page and
drag the CRX there. Opening it from Windows Explorer depends on file associations.
Edge still labels off-store extensions as coming from an unknown source. Its
recognized installer path requires both optional checks; Edge MV2 already works
in the stock version recorded below.

## Tests and diagnostics

After `build.bat x64`, open a matching Visual Studio Developer Command Prompt in
this folder and build the test targets:

```bat
cmake --build out/x64
ctest --preset x64
out\x64\mv2-scan.exe "C:\path\to\chrome.dll"
```

Use `x86` or `arm64` for the other targets. Native ARM64 tests require ARM64
Windows; x64 also runs analysis tests for ARM64 instruction layouts.

`mv2-scan.exe` reads the supplied file and prints JSON with SHA-256 and BLAKE3
fingerprints, proposed bytes, skipped optional checks and unresolved candidates.
It neither launches nor patches a browser. Exit codes are **0** for a ready plan,
**1** for a declined plan and **2** for an invocation/file/output error. Runtime
messages in DebugView start with `[mv2patch autoscan]` and include scan/cache timings.

Test executables and fixture DLLs are not deployment files. They use fabricated
browser images, temporary cache files and deliberately failed Windows calls to
check rejection, rollback, memory protection and cleanup. The browser test
launcher loads a test-only registry DLL that redirects matching Chrome extension
key operations into a test subtree; it can create keys there. Closing the launcher
terminates its launched test-browser process tree.

## Implementation and limits

Comments beside the relevant code explain these actions in plain language.
The files are separated by responsibility so each step can be inspected:

| File(s) | Responsibility |
| --- | --- |
| `autopatch_proxy.cpp`, `secur32-exports.txt` | Forward Windows functions and trigger scanning during browser startup. The text file is the function list used to generate forwarding code. |
| `autoscan_runtime.cpp`, `autoscan_runtime.h` | Read the browser file, communicate with the helper, and define the checked patch message and cache functions. |
| `autoscan_cache.cpp` | Read/write the protected per-user cache, tied to browser BLAKE3, scanner SHA-256 and message format. A changed browser or scanner gets a fresh scan. |
| `autoscan.cpp`, `autoscan.h` | Recognize browser checks and report proposed edits without executing browser instructions. |
| `boundaries.hpp` | Check Windows executable file sections and locate bounded function ranges. |
| `lifter.hpp` | Translate supported machine instructions into descriptions the scanner can reason about. |
| `solver.hpp` | Follow bounded possible values and paths to check what a decision tests. |
| `autoscan_apply.cpp`, `text_compare.hpp` | Validate the plan and the browser DLL's main code section (`.text`), apply memory edits, and undo failed edits. The comparison helper only reads bytes. |
| `hook.hpp`, `loader_lock.h` | Change imported function pointers and check whether Windows is still loading DLLs. |
| `blake3_threads.cpp` | Divide large fingerprint calculations among available CPUs and wait for workers to finish. |
| `autoscan_cli.cpp` | Print the read-only diagnostic report. |
| `*_test.cpp`, `test_launch.cpp`, `test_registry.cpp` | Separate test programs and test-browser helpers. |
| `CMakeLists.txt`, `CMakePresets.json`, `build.bat`, `check-size.cmake`, `version.rc` | Build configuration, compiler setup, output-size checks and DLL labels. |

In 2.0.0, the three declarations formerly in `autoscan_cache.h` are combined into
`autoscan_runtime.h`; the redundant header is removed. The separate cache source
stays because the runtime and tests share it. The other helpers and test files
have distinct callers or build outputs; combining them would couple unrelated
checks. `build/` and `out/` are generated and can be removed when their local
outputs are no longer needed. `PERFORMANCE.md` retains measured results and
historical evidence.

The core decision follows this reviewed Chromium condition, with member offsets
inferred from each browser file:

```text
manifest_version < 3
&& (converted_user_script || type in {1, 3, 8})
&& location != 5 && location != 10
```

Recognition has fixed limits and refuses unsupported instructions or conflicting
evidence. It uses no signature table, Capstone or Z3. Project scanner buffers have
fixed capacity; Windows APIs and the C runtime can still allocate internally.
Cache protection is for the current Windows user and is not a boundary against
other code running as that same user. Cached plans undergo the same memory checks
before application.

Decision pages change from execute/read to read/write, are edited and checked,
then return to execute/read. No deployed path requests memory that is both
writable and executable. This depends on browser startup occurring before the
patched routines run; changed startup ordering needs validation. Memory
protection rules do not guarantee antivirus acceptance.

`complete_enforcement_coverage_proven` remains **false**: bounded recognition
does not prove that every MV2 enforcement check was found. x86 function bounds
include heuristics, compiler changes can escape recognition, and full-file reads
and code comparison still add startup time on cache hits.

## Validation record

The [performance and validation record](PERFORMANCE.md) describes earlier
measurements and artifact fingerprints. Its browser results apply to those
recorded builds, not automatically to a newly versioned DLL.

| Recorded browser | Verified behavior |
| --- | --- |
| Chrome 157.0.8103.79 x64 | Packed external MV2 enablement and request blocking; nine memory decisions; cached and empty-cache restarts; removal restores deprecation. |
| Chrome Canary 160.0.8167.0 x86 | Packed external MV2 enablement and request blocking; eight memory decisions including the off-store verifier; cached and empty-cache restarts; removal restores deprecation. The optional CRX download check was unrecognized. |
| Chrome Canary 160.0.8166.2 x86 | Signed off-store CRX3 installation through Downloads and native confirmation; MV2 enablement and request blocking; nine memory decisions; cached and empty-cache restarts; tampered packages and missing developer proofs rejected; removal restores both restrictions. |
| Edge 157.0.4341.46 x64 | Developer-signed CRX3 installation, enablement and MV2 background execution; both installer decisions; tampered packages and missing developer proofs rejected. |

Earlier scanner validation covered 21 x64 and two x86 stock images plus two
ARM64 analysis images. Native ARM64 browser launches, browser updates,
interactive browsing and DRM remain unvalidated. A future browser may refuse a
plan or have checks this scanner does not recognize.
