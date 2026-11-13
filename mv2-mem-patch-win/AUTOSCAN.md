# Compact Windows automatic scanner

This C++20 build produces `version.dll` and `secur32.dll` for x86, x64 and ARM64.
It discovers MV2 decisions from the installed `chrome.dll`, without a maintained offset table,
symbols, Capstone or Z3. A read-only `mv2-scan.exe` is available for development.

The Release build fails if the DLL or diagnostic scanner reaches **300,000 bytes**.
It uses `/O2 /GL /GS- /GR- /EHs-c- /Gw /Gy /MD` and
`/LTCG /OPT:REF /OPT:ICF`. `/MD` requires the matching Microsoft Visual C++
runtime and Windows UCRT on the target machine.

## Build

Use `build.bat` or open this folder in Visual Studio; see [README.md](README.md)
for the build, test and installation commands. Only `build/<arch>/version.dll`
is a release output. CMake files, dependencies and development tools stay in
`out/<arch>/`. Each diagnostic scanner accepts only its own PE architecture.

Microsoft Detours **v4.0.1**, commit
`e4bfd6b03e50de46b47abfbd1e46b384f0c5f833`, and BLAKE3 **1.8.7**, commit
`f3149ec5bb5449af877ba20377a11008ff499fa2`, are fetched. Both archives are checked
against SHA-256. Redistribute `out/<arch>/Detours-LICENSE.md` and
`out/<arch>/BLAKE3-LICENSE.md` alongside the DLL.
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
  `secur32.dll` forwards 98 system exports and exposes the same private helper
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
to stay within `rundll32`'s 512 KiB stack. [Edge validation](EDGE-CRX-RESULTS.json).

`version.dll` swaps Chrome's loader imports during startup. `secur32.dll` uses a
temporary main-thread clock hook and a `ChromeMain` lookup hook, and waits for
the loader lock to be released before scanning. Both use
the same runtime: it locks and maps the browser disk image read-only and computes
its full-file BLAKE3.
The parent reads a valid cached plan directly. A miss launches System32
`rundll32.exe` with a helper entry point in the same DLL. The helper has
30 seconds to return a fixed 1,532-byte response with at most 64 sites. Analysis
and cache writes run outside the loading browser; cache reads also run in the
parent after the loader call returns, never in `DllMain`.

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

The proxy also preserves the existing child-process mitigation adjustment needed
for its unsigned DLL to load. Renderer Win32k lockdown is retained. Crypt32 is
delay-loaded for cache IO in the parent and helper.

## Validation and limits

Measured on November 12, 2026 with MSVC 19.52.37029, Release `/MD`:

| Target | `version.dll` | `mv2-scan.exe` |
| --- | ---: | ---: |
| x64 | 219,648 bytes | 207,360 bytes |
| x86 | 230,912 bytes | 214,016 bytes |
| ARM64 | 157,696 bytes | 142,336 bytes |

All x64 tests (18/18) and x86 tests (14/14) passed. The final scanners reproduced
166 reviewed core decisions across 21 x64 and two x86 stock images, preserving
all 23 recognized InstallVerifier gates. The CRX download gate matched
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

ARM64 cross-compilation passed. Module and optional-gate executables passed under
Wine/QEMU, and two ARM64 images reproduced the frozen reports on the x64 analysis
target. The updated hash executable cannot run in that emulator because its
CPU-set query is unimplemented. Native ARM64 hashing, proxy ABI and browser
execution remain untested.
The binary hashes, sizes and individual results are recorded in
[AUTOSCAN-RESULTS.json](AUTOSCAN-RESULTS.json).

`compact-modules` checks all three instruction formats, PE/unwind bounds, interval
extrema, native field inference, and pointer protection. x64 additionally runs
scanner, application rollback, cache and proxy export regressions. ARM64 tests
must also be run on ARM64 Windows before treating that target as runtime-validated.

Performance experiments, compiler comparisons, unselected approaches and measured
limits are in [PERFORMANCE-RESEARCH.md](PERFORMANCE-RESEARCH.md).
Further prototypes, startup/cleanup measurements and the wider optimization
catalogue are in [PERFORMANCE-DEEP-DIVE.md](PERFORMANCE-DEEP-DIVE.md).
The next shared-reference search experiment is recorded in
[PERFORMANCE-NEXT.md](PERFORMANCE-NEXT.md).
Microsoft threading examples, processor sizing and the native/PPL comparison are
recorded in [PERFORMANCE-THREADING.md](PERFORMANCE-THREADING.md).
New stock-preflight overlap, lazy-trim experiments and the expanded optimization
catalogue are in [PERFORMANCE-FRONTIER.md](PERFORMANCE-FRONTIER.md).
Continued page-protection, worker and streaming experiments are in
[PERFORMANCE-FOLLOWUP.md](PERFORMANCE-FOLLOWUP.md).
Actual browser, dynamic TLS and read-buffer experiments are in
[PERFORMANCE-IO-STARTUP.md](PERFORMANCE-IO-STARTUP.md).

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
