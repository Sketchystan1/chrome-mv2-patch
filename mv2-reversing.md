# Chrome MV2 reverse-engineering notes

## Current implementation and future ports

Chrome blocks Manifest V2 extensions after removing the flags and enterprise
policy that previously re-enabled them. This project selects the existing
not-affected outcome of recognized enforcement checks.

The deployed implementation is the native Windows `secur32.dll` auto patcher
for x64, x86 and ARM64. It discovers decisions from the installed browser DLL,
validates the loaded code and edits memory during startup. Browser binaries on
disk stay unchanged. [The Windows README](mv2-mem-patch-win/README.md) records its
runtime contract and recognition limits; [PERFORMANCE.md](mv2-mem-patch-win/PERFORMANCE.md)
records measured artifacts and results.

Linux and macOS native auto patchers are planned using the same architecture:
automatic discovery, a checked cache, loaded-code validation and transactional
in-memory edits. The former disk patchers and milestone authoring pipeline are
retired; the last legacy `signatures.json` is retained for older releases.
The cross-platform findings below remain useful
for those ports, but do not represent a shipping Unix implementation or a fixed
list of supported future browser versions.

## 1. The source predicate

Chrome 138 introduced the `ManifestV2Handler` service. Release builds fold the
test-only bypass into the blocking path; `g_allow_mv2_for_testing` is not a usable
stable-build switch. The relevant predicate has moved and been inlined over time.

The reviewed source contract used by the native scanner is:

```text
manifest_version < 3
&& (converted_user_script || type in {1, 3, 8})
&& location != 5 && location != 10
```

The types are extension, login-screen extension and user script; locations 5 and
10 are component locations. Review Chromium's
[manifest_v2_util.cc](https://chromium.googlesource.com/chromium/src/+/refs/tags/157.0.8103.39/extensions/browser/manifest_v2_util.cc)
and [Extension::GetType()](https://chromium.googlesource.com/chromium/src/+/refs/tags/157.0.8103.39/extensions/common/extension.cc)
when the source or compiler layout changes.

A manifest-version comparison alone does not identify enforcement. Confirm the
type/location relationships, Boolean result and both branch outcomes. Calls can
have required side effects, and callers can contain additional checks. A local
predicate proof does not prove complete enforcement coverage.

## 2. Select the existing not-affected outcome

Never remove a call, change the manifest-version operand or invent a destination.
A reviewed conditional may select its existing target, fall-through or zero
operand:

| Observed instruction | Reviewed replacement | Preserved meaning |
| --- | --- | --- |
| x86/x64 short `JG` (`7F disp8`) | `JMP` (`EB disp8`) | Existing not-affected target; displacement unchanged. |
| x86/x64 near `JG` (`0F 8F disp32`) | `90 E9 disp32` | Existing not-affected target; instruction width unchanged. |
| x86/x64 inverted `JLE` (`7E` or `0F 8E`) | Complete two- or six-byte NOP sequence | Existing not-affected fall-through. |
| ARM64 `B.GT` | Condition GT → AL | Existing target; opcode and `imm19` unchanged. |
| ARM64 inverted `B.LE` | `NOP` (`0xD503201F`) | Existing not-affected fall-through. |
| ARM64 `CBZ` or `TBZ/TBNZ` | Unconditional `B` to the same resolved target | Recompute `imm26` from the sign-extended `imm19`/`imm14`. |
| ARM64 `CSEL Wd,WZR,Wm,GT` | GT → AL | Existing zero operand. |

Equivalent comparisons against 3, other signed conditions and optional
installation decisions require their own reviewed polarity. The native Windows
scanner/application validate their supported forms directly. CBZ/CSEL examples
include historical Linux/macOS research and do not imply Windows recognition of
every form in this table.

Chrome 159 introduced inverted predicates and branchless CSEL code. Its DCHECK
builds also retained diagnostic copies alongside fast copies. The Linux ARM64
management checks contained extra inlined predicates; one used a preceding
`CBZ X0` to skip only the predicate while keeping the preceding call. A window
around its `B.LE` also matched unrelated code. These are reasons to analyze
source meaning and every resolved copy, rather than assume one branch shape.

## 3. Native discovery, cache and application

Windows discovery parses PE code and function bounds, decodes supported
instructions and follows bounded control flow. It infers field roles from data
flow and verifies the predicate. Unknown instructions, ambiguous roles,
unresolved candidates and exceeded limits decline the plan.

`autoscan.cpp` proposes edits; `autoscan_runtime.cpp` and `autoscan_cache.cpp`
handle the read-only image, isolated helper and cache;
`autoscan_apply.cpp` independently checks and applies the result. Shared
instruction and proof helpers live in `lifter.hpp` and `solver.hpp`.
The native path uses no maintained byte table, PDB, Capstone or Z3.

The x86 `rundll32` host reserves only 256 KiB for its main stack. Running bounded
analysis directly on that stack overflowed before returning a plan, leaving
Chrome unpatched. The helper now joins a worker with a 1 MiB stack reserve;
the browser still enforces the helper deadline and validates its reply.

The browser's complete BLAKE3 identity, scanner SHA-256 identity and protocol
version bind the cache. Windows protects entries for the current user; temporary
writes replace entries only after completion. Cache reuse still requires
loaded-code checks, including relocations and allowed decision changes.

Application occurs in the main process at a validated startup point outside the
Windows loader lock. Browser child processes only forward the real system DLL's
functions. The application validates addresses, branch targets, instruction bytes
and the loaded code against the stock file. Pages transition execute/read →
read/write → verified edit → instruction-cache flush → original protection.
A failed edit rolls back all changes; failed rollback/protection restoration
terminates the browser.

Complete enforcement coverage remains unproven. New compiler layouts, missing
function bounds and unsupported instructions can escape recognition. Successful
discovery must be followed by runtime validation on the exact artifact.

## 4. Platform findings retained for Linux and macOS

| Platform | Gate-bearing image | Address and loader concerns |
| --- | --- | --- |
| Windows | `chrome.dll` or `msedge.dll`, PE x64/x86/ARM64 | PE RVAs, loader relocations and architecture-specific function bounds; `secur32.dll` provides the current startup hook. |
| Linux | Stripped PIE `chrome`, ELF x64/ARM64 | Section virtual addresses differ from file offsets; loaded addresses need the load bias. Function bounds, preload/startup behavior and cache ownership need native implementations. |
| macOS | Versioned `Google Chrome Framework`, thin or universal Mach-O | `slice_base + section_64.offset` locates file bytes; loaded addresses need the dyld slide. Slice identity, function bounds, loading and code signing need native implementations. |

The retained `binary_image.py` reader supports PE x64/x86/ARM64, ELF x64/ARM64
and the ARM64 slice of thin/fat Mach-O. Intel macOS was removed from the historical
patcher; it has no current runtime support. Research helper slice editing alone
does not establish support for an architecture.

Member offsets are build evidence, not stable API. During Chrome 154, nested
fields shifted by `+0x20`, and register allocation/shared bodies changed between
builds. Chrome 152 had already moved enforcement into a shared free predicate,
with some callers tail-calling or sharing bodies. Future native ports must infer
relationships from each image and account for all copies.

**Linux lessons.** The historical disk patcher needed atomic sibling replacement
to avoid `ETXTBSY`, and package/path restrictions affected installation.
The native port should leave the ELF's code on disk unchanged and validate the
actual mapped executable and its load bias. A WSL x64 launch is useful evidence
for that tested artifact, but cannot validate native Linux ARM64 or the future
loader/cache design.

**macOS lessons.** Apple Silicon refuses modified signed code unless the affected
bundle is correctly re-signed. Historical disk experiments re-signed nested
Mach-O files and bundles inside-out, with the `.app` last, preserving entitlements
and flags (including renderer JIT entitlements). Backups belonged outside the
signed `.app`, and all browser processes had to stop before signed files changed.

The retained `macho_insert_dylib.py` explores adding a load command to a scratch
main executable so a future dylib can patch the framework in memory. If padding
is insufficient, it can reclaim selected metadata commands; removal of the new
command does not restore that metadata. A future installer needs a verified
stock backup, bundle signing and native launch/removal tests. The helper supplies
none of those, and this repository currently ships no macOS patcher.

## 5. Off-store extensions and downloaded CRX files

MV2 enforcement and extension-source checks are separate. Non-policy external
extension registration avoids creating the managed-browser banner: on Windows,
Chrome reads `Software\Google\Chrome\Extensions\<id>` with the 32-bit registry
view; platform external-extension JSON serves the analogous Linux/macOS provider.
Policy-based `ExtensionSettings`/`ExtensionInstallForcelist` registration marks
Chrome managed, so the historical policy-filter bypass ("Gate B") was removed.

Official Chrome's `InstallVerifier::MustRemainDisabled` can make off-store
extensions sticky-disabled through `DISABLE_NOT_VERIFIED`. A recognized
`from_webstore()` flag test can take its existing verified path, allowing the
extension to reach the recoverable external-extension state and be enabled.
Historical x64/x86 code used `TEST ... ,8; JNE`; ARM64 used `LDRB; TBNZ ...,3`.
Observed creation-flag offsets included Windows x64/ARM64 `+0x254`, x86
`+0x17c` and macOS ARM64 `+0x24c`. These are reference-build observations.

That branded verifier enforcement was compiled for Windows/macOS; Linux had
`ENFORCE=NONE`. Unbranded or optimized builds can omit optional checks. Derive
their meaning from each actual image instead of importing a branded build's
addresses or assuming all Chrome for Testing builds behave alike.

The current Windows patcher also recognizes downloaded-CRX installation checks.
Its reviewed paths retain developer-signature and package-integrity checks while
allowing a CRX without Chrome Web Store publisher proof. Edge has separate source
and download decisions and requires both for its recognized installer path.
Chrome's unknown optional checks are skipped. See the Windows README for
architecture and runtime-validation limits.

Chrome Canary 160.0.8166.2 x86 uses a framed constant-zero external verifier
(`push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret`). Its download path calls a
security-cookie helper whose terminal trap is exactly at the trimmed function
boundary. Recognition checks the complete framed helper and accepts that exact
terminal destination while still rejecting conflicting return cleanup or other
out-of-range destinations. Independent source/disassembly review identifies the
`off_store_install_allow_reason_` field at `+0x12c`; reason 2 is
`AllowedBecausePref`. The reviewed branch at RVA `0x2c84d2a` changes `74 0E` to
`90 90`, selecting the existing external-verifier path while preserving calls,
developer proofs, package integrity and installation confirmation. These
addresses document this image; the scanner does not consume a version table.

MV2 request blocking follows MV2's normal permissions. The historical optional
MV3 `webRequestBlocking` data patches were removed; they are not part of the
native predicate patch.

## 6. Failed approaches and lasting lessons

| Approach | Observed failure | Required lesson |
| --- | --- | --- |
| Unanchored wildcard search | Hundreds of unrelated edits and startup breakpoints. | Require semantic evidence and reject ambiguous candidates. |
| Fixed register/member-offset patterns | Skipped checks after compiler/layout changes. | Recover field relationships from the current image. |
| Change compared manifest value from 2 to 3 | Extensions disappeared. | The value identifies MV2; select the existing outcome instead. |
| Toggle the test-only global | No usable symbol in stable/LTO builds. | Review reachable release code. |
| Blank a side-effecting call | Corrupted service state and startup crashes. | Keep calls and their effects. |
| Reuse beta byte windows on stable | All windows matched while MV2 stayed blocked. | Matching bytes do not establish purpose or complete coverage. |
| Trust a faulty PDB RVA parser | Verified addresses were about `0x1000` wrong. | Match image identity and use dbghelp; distinguish addresses from file offsets. |
| Scan short branches only | Missed near-branch enforcement silently. | Review every supported instruction shape and resolved copy. |
| Flip a manifest-version reason-string selector | Browser crash-looped only after an actual MV2 extension was installed. | Review both outcomes; string-literal loads and message-building calls are not a Boolean enforcement gate. |
| Include PC-relative calls/addresses in a fixed byte window | Matched one build and failed after relocation. | Native analysis must decode targets/relocations rather than inherit build-specific byte distances. |

The reason-string trap was removed from historical tables on September 9, 2026.
It matched once and passed byte verification and fresh-profile startup. The
downstream message-builder `CHECK` ran only with a real MV2 extension. Every
runtime test therefore needs an installed extension, beyond an empty-profile
launch.

## 7. Research and validation workflow

1. Fetch a stock image and matching symbols where published. Record the complete
   file hash, architecture, source version and provenance in `_scratch/`.
2. Review source and both outcomes of candidate checks. Establish independent
   required/optional address baselines; never use the scanner's output as its own
   correctness oracle.
3. Run read-only native discovery and compare against those hash-bound baselines
   with `scripts/check_autoscan_matrix.py`. Report missing, unexpected and
   unresolved decisions.
4. Run `python scripts/run_tests.py` and the relevant CMake tests. Extend native
   decoder/proof tests for a meaningful new layout instead of weakening declines.
5. Test isolated browser copies with a real off-store MV2 extension and an MV3
   control: install/enable, request blocking, disable/re-enable, cached and empty
   cache restarts, and removal. Verify on-disk browser hashes and normal sandbox
   behavior. Each future platform also needs update/cache invalidation and its
   native loading, protection and restoration checks.

The Python Capstone/Z3 scanner is retained as an x64 analysis prototype; it
emits reports and has different compiler coverage from the native implementation.
[The scripts README](scripts/README.md) documents its commands and both matrices.

Recorded native x64 behavior includes Chrome 157.0.8103.79 MV2 enablement/request
blocking and Edge 157.0.4341.46 developer-signed CRX installation, including
tampered-package and missing-developer-proof rejection. Earlier native scanner
analysis covered x64, x86 and ARM64 reference images. Historical disk/table
experiments covered Chrome 152–159 and included ELF/Mach-O scratch patch/restore
and Windows/Wine/WSL launches. Those results apply to their recorded artifacts;
they do not certify the current DLL or future Unix ports.

The rebuilt 2.0.0 x86 DLL passed Chrome Canary 160.0.8167.0 packed MV2 enablement,
request blocking, cached and empty-cache restarts, and removal; the exact browser
and patcher hashes are recorded in [PERFORMANCE.md](mv2-mem-patch-win/PERFORMANCE.md).
The later corrected DLL also passed signed CRX3 installation on Canary
160.0.8166.2 x86 through the real Downloads flow and native confirmation, with
tampered-signature and missing-developer-proof rejection, both restart types,
and removal. The same validation record binds these results to their artifacts.
Native ARM64 browser lifecycle, native macOS loading/signing, Linux ARM64,
browser updates and DRM still need validation. Preserve sandbox and signature
behavior when porting; fixture tests and bounded proofs are only part of that
evidence.
