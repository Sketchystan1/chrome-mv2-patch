# Windows MV2 automatic patcher

The C++20 `secur32.dll` proxy discovers Chrome's MV2 checks at startup and
patches them in memory. It supports x64, x86 and ARM64, with a 300,000-byte build
limit. The same x64 DLL also recognizes Edge's CRX installer gates. No signature
table, Capstone or Z3 is used by this DLL.

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
build/x64/secur32.dll
build/x86/secur32.dll
build/arm64/secur32.dll
```

CMake intermediates, fetched Detours sources, test programs and diagnostic tools
go into ignored `out/<arch>/` directories. The default build produces only the DLLs.

The build fetches Detours 4.0.1 at `e4bfd6b03e50de46b47abfbd1e46b384f0c5f833`
and BLAKE3 1.8.7 at `f3149ec5bb5449af877ba20377a11008ff499fa2`, verifying both
archives with pinned SHA-256 values. The DLL fetches no dependencies at runtime.
Release uses `/O2 /GL /GS- /GR- /EHs-c- /Gw /Gy /MD` and
`/LTCG /OPT:REF /OPT:ICF /INCREMENTAL:NO`.

In Visual Studio, choose **File > Open > Folder**, open `mv2-mem-patch-win`,
select **x64 Release**, **x86 Release** or **ARM64 Release**, and build the
`secur32` target. Visual Studio and `build.bat`
share the same CMake presets.

## Install a local build

1. Close the browser copy being tested.
2. Copy `build/<arch>/secur32.dll` beside `chrome.exe` or `msedge.exe`.
3. Launch it with a separate `--user-data-dir` for the trial.

The browser's `chrome.dll` on disk is unchanged. Close the browser and remove the
proxy DLL to restore stock behavior. `/MD` requires the matching Microsoft Visual
C++ runtime and Windows UCRT. Redistribute `out/<arch>/Detours-LICENSE.md` and
`out/<arch>/BLAKE3-LICENSE.md` with the DLL; release packaging includes them
outside the build directory.

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
[consolidated performance and validation record](PERFORMANCE.md).

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
are declined. See [validation](PERFORMANCE.md#validation-and-historical-identities).

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

## Implementation and limits

### Modules

- `boundaries.hpp` validates file-layout PE sections and RVA translations. x64
  uses `.pdata` and chained `.xdata` unwind records. ARM64 uses packed function
  lengths or the unpacked `.xdata` header; reserved flags are rejected. Padding
  is removed at instruction boundaries, so an immediate containing `90` or `CC`
  is preserved. x86 combines CFG table RVAs, decoded relative calls and padded
  frame/hotpatch prologues, with a bounded 64 KiB search around a candidate.
- `lifter.hpp` defines a 16-byte `LiftedInsn`, a 256-entry x86 length table and
  ARM64 instruction masks. It handles signed comparisons and branches, field
  loads, register moves and immediate arithmetic. Small additional instruction
  forms used by the existing Boolean predicates are represented as `Other`.
  Unsupported instructions inside a predicate decline that candidate; unlisted
  VEX/EVEX encodings never receive a guessed length.
- `solver.hpp` tracks 32 registers as unknown values, constants, pointers with
  displacements or connected field values. Closed signed 32-bit intervals split
  at branches and prune empty paths. Arithmetic wraparound is handled explicitly.
  Limits include 32 fields, 64 pending states, 256 steps per path and 8,192 total
  steps. Exceeding a limit declines the plan.
- `hook.hpp` uses Detours' unchanged import enumeration routines to find pointer
  slots, then performs atomic swaps with `PAGE_READWRITE` followed by
  `PAGE_READONLY`. The pinned inline-hook engine is excluded: stock Detours
  allocates heap memory and uses RWX pages. Generated assembly tail jumps forward
  all 98 system secur32 exports; `VersionMV2ScanW` is the private scan helper
  at ordinal 1000.

Scanner, solver, IPC and hashing buffers use fixed caller-owned
storage, principally `std::array` on the stack. Shipped project code has no
`new`, `malloc`, heap-backed containers, RTTI or C++ exceptions. This is a
source-level allocation guarantee: the Windows loader, UCRT and called Windows
APIs may allocate internally. DPAPI allocates temporary protected/decrypted blobs,
which are freed with `LocalFree`; hash callbacks are joined before caller storage
expires. Deferred view cleanup uses one fixed slot and holds its DLL reference
until callback return. Detours' import parser still uses Windows SEH.

BLAKE3 dispatches to upstream SSE2/SSE4.1/AVX2/AVX-512 assembly on x64, isolated
intrinsic objects on x86, and NEON on ARM64. CPU and OS feature checks retain
architecture fallbacks. `blake3_threads.cpp` supplies the pinned library's parallel
join hook using balanced subtree budgets for large subtrees. The total thread
budget adapts to process affinity, eligible processor groups and the default
CPU-set count without a fixed application ceiling; the scheduler places threads.
The 16 MiB fork threshold bounds useful work. This is not per-CPU benchmark
autotuning. Work allocation or TLS initialization/installation failure falls back
to serial hashing. Scoped dynamic TLS stores pointers to joined caller-owned
budgets; failed restoration disables future lookups before storage expires.
No oneTBB runtime is required. SSE2 filters, bounded literal/call
searches and one exact cached trim range reduce discovery work without changing
the structural checks. Optional recognizers collect their anchor names once and
share the reference traversal, retaining independent hit limits and ambiguity
checks. Each boundary object reads one immutable image.
On x64, a complete preliminary check of authoritative runtime-table bounds can
reject a core candidate before trimming. Decode/capacity uncertainty still runs
the original trimmed checks; leaf, x86 and ARM64 recovery retain their usual path.

### Recognition and application

The core predicate is tied to the reviewed Chromium source:

```text
manifest_version < 3
&& (converted_user_script || type in {1, 3, 8})
&& location != 5 && location != 10
```

Extension/Manifest offsets are inferred independently in each binary. An accepted
plan needs one coherent member layout plus a free predicate, or two independent
functions with paired normal/inverted diagnostic bodies. Plausible unresolved
candidates decline the entire core plan. The optional InstallVerifier check uses
its provider name, virtual table, Extension argument, store bit and disable reason;
it is skipped if its structure cannot be recognized.

On x64, argument provenance also follows private stack spills through register
copies and ABI calls. All predecessor paths must agree. Exposed slots, overlapping
or unknown stores, call shadow space and unsupported stack changes decline the
candidate. SIMD stores conservatively cover 16 bytes, so a scalar store can cause
a safe decline. Spill tracking is bounded to 256 states and requires the slot to
lie below every address-taken local; it does not model arbitrary stack objects.

Every verified InstallVerifier gate is applied automatically, with no launch
flag or version-specific opt-in. This permits enabling off-store extensions,
including ones already disabled with `DISABLE_NOT_VERIFIED`; it does not hide
warning text or edit extension preferences. Browser lifecycle validation covers
x64; x86 and ARM64 also run the bounded optional recognizers.
See [launch instructions](README.md#off-store-extensions).

The optional x64 CRX download gate is anchored to `apps-gallery-url` in
`CrxInstaller::InstallCrx`. The scanner identifies its existing CRX3 format path,
infers the off-store allow-reason field, then finds a unique caller whose Boolean
decision guards only the `OffStoreInstallAllowedBecausePref` store to that field.
The store and installer call must load the same stack-backed installer, including
x64 copies kept in nonvolatile registers across calls, without a
recognized intervening frame change or overwrite of that slot. Unrecognized or
ambiguous layouts are skipped. The existing JE becomes NOPs, allowing the normal
download installer to request CRX3 verification and reach its confirmation dialog.
The CRX verifier itself is unchanged: developer proofs, signature validation,
package parsing and requested file hashes still apply. Drag-and-drop already uses
Chrome's external verifier format. See [CRX installation](README.md#installing-downloaded-crx-files).

An x64 PE exporting the name `msedge.dll` uses a separate Edge installer path:
both optional gates must be verified, and no Chrome MV2 predicate is required.
String anchors must begin at a string boundary, so `ms-apps-gallery-url` does not
make `apps-gallery-url` ambiguous. Edge's provider body can include forward cold
blocks whose x64 unwind chains identify the same owning method. The scanner
corroborates its third-argument `DISABLE_NOT_VERIFIED` store and extension argument
with the out-of-line store helper's flag test and existing true return. It patches
only the caller's source decision in `MustRemainDisabled`, preserving shared store
detection and content verification. The same decode buffer is reused for callees
to stay within `rundll32`'s 512 KiB stack. [Edge validation](PERFORMANCE.md#validation-and-historical-identities).

`secur32.dll` uses a temporary main-thread clock hook and a `ChromeMain` lookup
hook, and waits for the loader lock to be released before scanning. The runtime
locks and maps the browser disk image read-only and computes its full-file BLAKE3.
The parent reads a valid cached plan directly. A miss launches System32
`rundll32.exe` with a helper entry point in the same DLL. The helper has
30 seconds to return a fixed 1,532-byte response with at most 64 sites. Analysis
and cache writes run outside the loading browser; cache reads run in the parent
after the loader lock is released, never in `DllMain`.

A cache under `%LOCALAPPDATA%\chrome-mv2-patch\autoscan` is bound to both the
browser BLAKE3 and scanner SHA-256. User-scoped `CryptProtectData` with UI forbidden
keeps plans usable across Windows logons. Protected input is bounded to 4 KiB;
decrypted size, checksum, identities and protocol are checked on read. A browser
or scanner change, corrupt entry or cache IO failure causes a fresh scan.
Successful writes replace a temporary file atomically. Same-user code is not a
security boundary for this cache.

Protocol 5 uses explicit BLAKE3 identity and records separate RVAs for the optional InstallVerifier and CRX download
sites. The parent validates every site, requires the former to identify a JNE
(or Edge's verified-path JE) and the latter a JE, and applies all verified sites
together. A plan consisting only of these two sites requires an Edge PE identity.
The scanner hash
prevents an older DLL's cache from being reused after an update.

Before applying a plan, the parent validates its identity, stock instructions,
branch direction, targets, ordering and allocation bounds. All other loaded
`.text` bytes must match the disk image, allowing checked HIGHLOW/DIR64 relocations.
Decision-page protections are queried in one bounded `K32QueryWorkingSetEx` batch.
Only valid exact execute/read results pass; all other results use the original
`VirtualQuery` check. Residency and sharing never replace content validation.
Large code gaps use two joined comparisons after hashing, with serial fallback
on one available CPU or worker creation failure. Relocation block headers are
validated once; sorted tables reuse a bounded cursor between decisions, while
unsorted tables retain the original traversal and relocation checks.
The existing decision instructions are edited during startup with this order:

```text
PAGE_EXECUTE_READ -> PAGE_READWRITE -> write -> FlushInstructionCache -> PAGE_EXECUTE_READ
```

No shipped path requests `PAGE_EXECUTE_READWRITE`. Failure rolls back all edits;
a failed rollback stops the process. This code is restricted to startup before
Chrome enters the patched routines; it is not a live-patching API for running
threads. W^X and data pointer swaps do not guarantee antivirus allowlisting.

After successful verification/application, file-view unmapping can finish in a
thread-pool callback while startup proceeds. A busy slot, failed DLL reference or
failed submission falls back to synchronous unmapping. Runtime timings separate
application from queued/synchronous cleanup. The proxy disables unused thread
notifications without static hash TLS and frees its dynamic TLS index on DLL
detach after joined calls and retained cleanup callbacks finish.

The diagnostic scanner retains truthful SHA-256 output and adds a `blake3` field.
It computes both hashes, so its CLI wall time includes extra diagnostic hashing
that the runtime patcher does not perform. Runtime stage timings use QPC.

Children only forward system exports; the proxy does not change their DLL-signing
mitigation policy. Renderer Win32k lockdown is retained. Crypt32 is delay-loaded
for cache IO in the parent and helper.

## Validation and diagnostics

The [performance record](PERFORMANCE.md) summarizes current measurements,
validation, rejected experiments and artifact hashes. It also links the complete
experiment ledger in Git history and the local evidence archive. Measurements for
an earlier carrier/build are not guarantees for a new DLL. All deployment DLLs
must remain below 300,000 bytes.

The reviewed native matrix reproduced 166 core decisions across 21 x64 and two
x86 stock images, with 23 InstallVerifier and 20 x64 download gates. Two ARM64
analysis images also matched frozen reports. Chrome 159.0.8148.1 DCHECK safely
skips its different optional download layout. Current carrier browser validation
covers x64 Chrome 157.0.8103.79 and Edge 157.0.4341.46, including cache reuse and
removal controls. Native x86/ARM64 browser behavior and updates need validation.

The diagnostic JSON reports SHA-256 and BLAKE3, inferred fields, patch bytes,
skipped optional gates and unresolved candidates. Exit codes are 0 for a ready
plan, 1 for a declined plan and 2 for an invocation/file error. Runtime DebugView
messages start with `[mv2patch autoscan]` and include scan/cache timings.

`complete_enforcement_coverage_proven` remains **false**. Bounded local interval
reasoning cannot establish that every enforcement site was discovered. x86
bounds are heuristic, unsupported compiler forms can escape the prescreen, and
future Chrome versions can remove MV2 entirely. Full-file hashing and code
validation still add startup time on cache hits. Controlled cold-boot latency,
broader CPU/ISA/NUMA performance and DRM are not established by these tests.
