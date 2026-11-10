# Compact Windows automatic scanner

This C++20 build produces `version.dll` for x86, x64 and ARM64. It discovers MV2
decisions from the installed `chrome.dll`, without a maintained offset table,
symbols, Capstone or Z3. A read-only `mv2-scan.exe` is available for development.

The Release build fails if the DLL or diagnostic scanner reaches **150,000 bytes**.
It uses `/O1 /Os /GL /GS- /GR- /EHs-c- /Gw /Gy /MD` and
`/LTCG /OPT:REF /OPT:ICF`. `/MD` requires the matching Microsoft Visual C++
runtime and Windows UCRT on the target machine.

## Build

Use `build.bat` or open this folder in Visual Studio; see [README.md](README.md)
for the build, test and installation commands. Only `build/<arch>/version.dll`
is a release output. CMake files, dependencies and development tools stay in
`out/<arch>/`. Each diagnostic scanner accepts only its own PE architecture.

Only Microsoft Detours **v4.0.1**, release commit
`e4bfd6b03e50de46b47abfbd1e46b384f0c5f833`, is fetched. Its archive is checked
against SHA-256. Redistribute `out/<arch>/Detours-LICENSE.md` alongside the DLL.
No dependencies are fetched when the DLL runs.

For a trial, close a separate browser copy, put the matching DLL beside its
`chrome.exe`, and use a separate `--user-data-dir`. Remove that DLL after closing
the copy to restore normal enforcement. The browser's disk image is unchanged.

## Modules

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
  the 17 system version exports; ordinal 18 is the private scan helper.

Scanner, solver, IPC, hashing buffers and cache buffers use fixed caller-owned
storage, principally `std::array` on the stack. Shipped project code has no
`new`, `malloc`, heap-backed containers, RTTI or C++ exceptions. This is a
source-level allocation guarantee: the Windows loader, UCRT and called Windows
APIs may allocate internally. Detours' import parser still uses Windows SEH.

## Recognition and application

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
warning text or edit extension preferences. Recognition currently supports x64.
See [launch instructions](README.md#off-store-extensions).

The optional x64 CRX download gate is anchored to `apps-gallery-url` in
`CrxInstaller::InstallCrx`. The scanner identifies its existing CRX3 format path,
infers the off-store allow-reason field, then finds a unique caller whose Boolean
decision guards only the `OffStoreInstallAllowedBecausePref` store to that field.
The store and installer call must load the same stack-held installer, without a
recognized intervening frame change or overwrite of that slot. Unrecognized or
ambiguous layouts are skipped. The existing JE becomes NOPs, allowing the normal
download installer to request CRX3 verification and reach its confirmation dialog.
The CRX verifier itself is unchanged: developer proofs, signature validation,
package parsing and requested file hashes still apply. Drag-and-drop already uses
Chrome's external verifier format. See [CRX installation](README.md#installing-downloaded-crx-files).

The proxy swaps Chrome's loader imports during startup. After `chrome.dll` loads,
it locks and maps the disk image read-only, computes its SHA-256, and launches
System32 `rundll32.exe` with a helper entry point in the same DLL. The helper has
30 seconds to return a fixed 1,532-byte response with at most 64 sites. Analysis
and cache work run outside the loading browser.

A cache under `%LOCALAPPDATA%\chrome-mv2-patch\autoscan` is bound to both the
browser and scanner hashes. `CryptProtectMemory(CRYPTPROTECTMEMORY_SAME_LOGON)`
protects caller-supplied storage; the checksum, size and protocol are checked on
read. A new Windows logon, corrupt entry or cache IO failure causes a fresh scan.
Successful writes replace a temporary file atomically. Same-user code is not a
security boundary for this cache.

Protocol 4 records separate RVAs for the optional InstallVerifier and CRX download
sites. The parent validates every site, requires the former to identify a JNE
and the latter a JE, and applies all verified sites together. The scanner hash
prevents an older DLL's cache from being reused after an update.

Before applying a plan, the parent validates its identity, stock instructions,
branch direction, targets, ordering and allocation bounds. All other loaded
`.text` bytes must match the disk image, allowing checked HIGHLOW/DIR64 relocations.
The existing decision instructions are edited during startup with this order:

```text
PAGE_EXECUTE_READ -> PAGE_READWRITE -> write -> FlushInstructionCache -> PAGE_EXECUTE_READ
```

No shipped path requests `PAGE_EXECUTE_READWRITE`. Failure rolls back all edits;
a failed rollback stops the process. This code is restricted to startup before
Chrome enters the patched routines; it is not a live-patching API for running
threads. W^X and data pointer swaps do not guarantee antivirus allowlisting.

The proxy also preserves the existing child-process mitigation adjustment needed
for its unsigned DLL to load. Renderer Win32k lockdown is retained. Crypt32 is
delay-loaded for use in the helper.

## Validation and limits

Measured on November 10, 2026 with MSVC 19.51.36260, Release `/MD`:

| Target | `version.dll` | `mv2-scan.exe` |
| --- | ---: | ---: |
| x64 | 97,792 bytes | 71,680 bytes |
| x86 | 76,288 bytes | 50,176 bytes |
| ARM64 | 73,728 bytes | 48,128 bytes |

All x64 tests (4/4) and x86 tests (2/2) passed. The final scanners reproduced
166 reviewed core decisions across 21 x64 and two x86 stock images, preserving
all 21 recognized InstallVerifier gates. The new CRX download gate matched
independently reviewed addresses on 20 x64 images; the different DCHECK Chrome
159.0.8148.1 layout safely skips it. No signature tables are used by the DLL.

Isolated browser tests on Chromium 157.0.8103.39, DCHECK Chrome 159.0.8148.1 and
official Canary 159.0.8153.0 passed stock, patched, restart and restore phases
without an off-store launch flag. Canary also passed an upgrade from a pinned
older DLL: enable requests initially failed with `DISABLE_NOT_VERIFIED`, then
replacing the DLL cleared that block on the next launch. The tests covered cache
reuse across restart, MV2 request blocking, MV3 operation, renderer Win32k
lockdown, original-file hashes and test-registry cleanup.

Manual CRX trials on Chromium 157.0.8103.39 and official Canary 159.0.8153.0
exercise the Downloads keep/open actions and the native file-drop handler at
`chrome://extensions`. A developer-signed CRX3 without Web Store publisher proof
reaches **Add extension** and becomes enabled after confirmation. A tampered
archive still reports `CRX_SIGNATURE_VERIFICATION_FAILED`; a missing developer
proof still reports `CRX_REQUIRED_PROOF_MISSING`. Removing the DLL restores the
download rejection. These trials use isolated copies and fresh profiles.

ARM64 cross-compilation passed. Earlier PE/unwind validation on two real ARM64
images is retained as historical evidence; native execution remains untested.
The binary hashes, sizes and individual results are recorded in
[AUTOSCAN-RESULTS.json](AUTOSCAN-RESULTS.json).

`compact-modules` checks all three instruction formats, PE/unwind bounds, interval
extrema, native field inference, and pointer protection. x64 additionally runs
scanner, application rollback, cache and proxy export regressions. ARM64 tests
must also be run on ARM64 Windows before treating that target as runtime-validated.

The diagnostic JSON includes hashes, inferred fields, patch bytes, skipped
optional gates and unresolved candidates. Exit codes are 0 for a ready plan,
1 for a declined plan and 2 for an invocation/file error. Runtime messages in
DebugView start with `[mv2patch autoscan]` and include scan/cache timings.

`complete_enforcement_coverage_proven` remains **false**. Local interval reasoning
cannot establish that every enforcement site was discovered. x86 function bounds
are heuristic, unsupported compiler forms can escape the prescreen, and a future
Chrome release can require new instruction support or remove MV2 entirely.
Full-image hashing and code validation also add startup time on cache hits.
DRM behavior and enterprise deployment are not validated by the scanner tests.
