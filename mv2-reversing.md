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

The November 18 source/disassembly review explains Stable 158.0.8127.37 x86's
additional core site. `ExtensionService::CheckManagementPolicy` inlines
`ManifestV2Handler::ShouldBlockExtensionEnable` at RVA `0x1ef6a03`; the
[tagged source](https://github.com/chromium/chromium/blob/158.0.8127.37/chrome/browser/extensions/extension_service.cc#L628)
adds `DISABLE_UNSUPPORTED_MANIFEST_VERSION` to the removal set when that predicate
is false. Stock `7F28` reaches the existing not-affected path at `0x1ef6a2d`,
which inserts `0x800000` into that set. `EB28` selects the same path while keeping
the surrounding policy checks and reason-removal operations.

Independent Capstone disassembly confirms the full version/type/location
predicate and its removal outcome. The unique policy-uninstall log text and
`extension_service.cc` file/line constants identify the stock caller against the
source. Beta 159.0.8154.6, Dev 160.0.8157.0 and Canary 160.0.8168.0 call their
already recognized shared predicate and test its Boolean result before the same
removal-set operation. Stable therefore has eight core patch sites and the other
builds have seven. This review confirms the additional MV2 decision; it does not
establish an independent baseline for every core site.

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

The helper joins an analysis worker with a 1 MiB stack reserve. The x86
`rundll32` host's 256 KiB main stack overflowed when it ran analysis directly.
The browser enforces the helper deadline and validates the reply.

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

Two reviewed x86 download layouts select the existing external CRX3 verifier by
changing `74 0E` to `90 90`. Their fall-through stores
`OffStoreInstallAllowedBecausePref` (`AllowedBecausePref`, 2) in the installer's
`off_store_install_allow_reason_` field at `+0x12c`; the same installer pointer
reaches `CrxInstaller::InstallCrx`. Calls, developer proofs, package integrity and
native confirmation remain in the path.

| Reviewed x86 image | Branch RVA | Recognition requirement |
| --- | --- | --- |
| Canary 160.0.8166.2 | `0x2c84d2a` | Complete framed constant-zero external verifier and exact terminal trap at the security-cookie helper's trimmed boundary. |
| Stable 158.0.8127.37 | `0x4903f46` | Register `SHL`/`SUB`/`SAR` in the caller and a helper with 2,327 reachable instructions. |

Canary's external verifier at RVA `0x51f4f10` is
`push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret`; its security-cookie terminal
trap is at `0x79737a5`. Recognition validates the complete frame and exact
terminal destination, rejecting conflicting return cleanup and other out-of-range
destinations.

For Stable's caller, register arithmetic leaves its destination value and flags
unknown; those results cannot establish predicate or pointer evidence. Arithmetic
on a known stack-derived address still declines, including zero shifts that could
hide an overlapping write. Every returning helper path must fit the fixed
4,096-instruction budget. Conflicting cleanup, stack changes, unmodeled memory
operations and exhausted bounds remain rejected.

These source/disassembly addresses are evidence for the stock hashes in the
[validation record](mv2-mem-patch-win/PERFORMANCE.md), rather than scanner input
or version-table entries.

MV2 request blocking follows MV2's normal permissions. The historical optional
MV3 `webRequestBlocking` data patches were removed; they are not part of the
native predicate patch.

ARM64 Edge providers can test bit zero of a private source helper's result with
either `TBZ` or `TBNZ`. The verified unaffected `TBZ` outcome is its existing
fall-through, selected with `NOP`; `TBNZ` selects its existing target with `B`.
The November 20 correction preserves that polarity when generating the optional
patch. Application independently reconstructs the same outcome. Synthetic Edge
fixtures cover both forms, rejection of the opposite outcome without writes,
rollback, idempotence and restored page protection. This fixes plan generation;
it does not establish that a browser loads the proxy during startup.

Chrome Canary 160.0.8172.0 ARM64 also exposed an unrelated comparison inside
V8's large AST visitor. Its `UBFX #7,#4; CMP #2; B.GT` tests `Literal::Type`,
not an extension's manifest version. The matching Chromium DEPS pins V8
[`3d1328cfbe3838f4213294b34108c1e8a7631619`](https://chromium.googlesource.com/v8/v8/+/3d1328cfbe3838f4213294b34108c1e8a7631619/src/ast/ast.h).
That source defines a six-bit node kind, a parenthesis bit and four literal-type
bits; literal node kind 45 and literal types 0/1/2/3/4/5 match the reviewed loads,
guard and dispatch. Generic AND/UBFX filtering is unsafe: it can also hide a
genuine predicate whose input is packed or whose extraction is bypassed.

The native exclusion therefore requires the reviewed AST origin, its exclusive
node-kind guard, one authenticated 60-case read-only switch, and a short table
case that preserves the nonvolatile table register before revisiting the tag
load. It rejects unproved entries into the origin, extraction, loop or dispatch
prefix, scanning every backed executable byte, including alignment padding.
Relocations affecting executable bytes, the switch table or relocation metadata
decline the exclusion. The ordinary function, node and proof budgets stay
unchanged; any other compiler shape retains the original unresolved candidate.

The hash-bound source/disassembly proof and rejected alternative strategies are
retained in `_scratch/t20-arm64-canary-source-proof.json`. RVAs in that evidence
are review output, never scanner inputs or version-table entries. Native
fixtures cover ordinary predicates, generic packed inputs, guard bypasses,
register clobbers, table mutations and loader adjustments; exact artifact and
browser outcomes belong in [PERFORMANCE.md](mv2-mem-patch-win/PERFORMANCE.md).

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

[PERFORMANCE.md](mv2-mem-patch-win/PERFORMANCE.md) records native Windows x64/x86
MV2 and signed-CRX lifecycle results, exact browser/DLL hashes, test counts and
unresolved startup failures. Scanner readiness, regression comparisons and
successful runtime phases are distinct evidence; none establishes complete
enforcement coverage or startup reliability.

Historical disk/table experiments covered Chrome 152–159, including ELF/Mach-O
scratch patch/restore and Windows/Wine/WSL launches. They apply to their recorded
artifacts and do not certify the current DLL or future Unix ports. Native Windows
ARM64 browser behavior, macOS loading/signing, Linux ARM64, browser updates and
DRM still need validation. Preserve sandbox and signature behavior when porting;
fixtures and bounded proofs provide only part of that evidence.
