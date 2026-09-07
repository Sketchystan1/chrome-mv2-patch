# Chrome Manifest V2 Re-Enable — Reverse-Engineering Notes

## Purpose & status

Google Chrome blocks Manifest V2 (MV2) extensions by default: the command-line flags and the `ExtensionManifestV2Availability` enterprise policy that used to re-enable them have been removed. The `chrome-mv2` patcher re-enables MV2 by flipping a single branch at each inlined copy of one predicate in the browser binary — `chrome.dll` on Windows (x64, x86, and arm64), the `chrome` ELF on Linux, and the universal `Google Chrome Framework` Mach-O on macOS (x86_64 + arm64).

This document is the *why* behind those byte edits, for all three platforms. The gate is the same C++ in the same source files; only the container, the toolchain's codegen, and the OS plumbing differ. All three scripts relocate signatures automatically across point releases and **decline without writing** on layouts they do not recognize.

**Platform status:**
- **Windows** — shipping through `chrome-mv2.ps1`. Targets **Chrome 151 and 152** (64-bit `chrome.dll`, PE32+), **Chrome 151 x86** (32-bit `chrome.dll`, PE32), and **Chrome 151 and 152 arm64** (Windows on ARM, PE32+ machine `0xAA64`, symbol-verified — §4b″); its PE edits preserve the branch-flip behavior verified against the original C++ reference patcher.
- **Linux** — shipping through `chrome-mv2.sh` (the cross-platform Unix script). Targets **Chrome 151 and 152** (64-bit x86_64 ELF, `container: "elf"`) and **Chrome 151 and 152 arm64** (aarch64 ELF, `container: "elf-arm64"`, official Google arm64 `.deb` since mid-2026 — §3b). Chrome 151's five x86_64 gate sites were derived and runtime-verified; Chrome 152's five-site table was derived from beta and statically verified, with its remaining Linux runtime check recorded in §4d. The arm64 tables reuse the `bcond` GT→AL flip and were located structurally (no arm64 Linux symbols are published) and cross-checked against the same-architecture, symbol-verified Windows/macOS arm64 tables.
- **macOS** — shipping through the same `chrome-mv2.sh` (it dispatches on the target's container magic). Targets the **arm64 (Apple Silicon)** slice of the universal `Google Chrome Framework` (`macho-arm64`), symbol-verified against Google's official dSYMs; the app is ad-hoc re-signed so it launches (§4e). Intel (x86_64) macOS support was dropped in v1.10.0.

---

## 1. Why MV2 is blocked (Chrome 138+)

Chrome 138 (2024) replaced `ManifestV2ExperimentManager` with a new `ManifestV2Handler` `KeyedService` (`extensions/browser/manifest_v2_handler.cc` + `mv2_deprecation_impact_checker.cc`). Every MV2 block reduces to two predicates:

```cpp
namespace { bool g_allow_mv2_for_testing = false; }

bool ShouldDisableLegacyExtensions() {
  if (g_allow_mv2_for_testing) return false;   // stripped in release
  return true;
}

// MV2DeprecationImpactChecker::IsExtensionAffected
bool IsExtensionAffected(int mv, Manifest::Type t, mojom::ManifestLocation loc) {
  if (mv >= 3) return false;                    // <-- the branch we flip
  if (t != kExtension && t != kLoginScreenExtension && t != kUserScript) return false;
  if (Manifest::IsComponentLocation(loc)) return false;
  return true;
}
```

`ShouldBlockExtensionInstallation`, `ShouldBlockExtensionEnable`, `DisableAffectedExtensions` (in `OnExtensionSystemReady`), and `MaybeReEnableExtension` all reduce to `ShouldDisableLegacyExtensions() && IsExtensionAffected(...)`.

### The flag cannot be flipped in the stable binary

`g_allow_mv2_for_testing` is the switch the WinDbg/Canary guides toggle. Its single writer — `ManifestV2Handler::AllowMV2ExtensionsForTesting` (`IN-TEST`, `PassKey<ScopedTestMV2Enabler>`) — is **stripped from release**. With no writer, LTO constant-folds `ShouldDisableLegacyExtensions()` to `return true` and deletes the global (confirmed via `dbghelp`: there is no symbol for it, and the disassembled gates contain no global read).

So the real, reachable gate is **`IsExtensionAffected`** — specifically its `mv >= 3` early-out.

---

## 2. The patch — flip `cmp <mv>,2 ; jg` at each inlined site

The release build **inlines** `IsExtensionAffected` into its enforcement sites. Each opens with the manifest-version check compiled as:

```asm
    cmp <manifest_version>, 2
    jg  <not_affected>          ; manifest_version >= 3  -> not an MV2 extension
```

Flipping that single `jg` to an unconditional jump forces the *"not an affected MV2 extension"* outcome for every extension — the reachable equivalent of `g_allow_mv2_for_testing == true`. **Only a branch direction changes**: no call is removed and no return value is synthesized (see §7, CARDINAL RULE).

The compiler emits the bail-out in one of two encodings, depending on how far the not-affected label sits, and both flip to a pure direction change to the same target:

| Encoding | Bytes | Flip | Reach |
| :--- | :--- | :--- | :--- |
| **short** `jg` | `7F disp8` (2 B) | `7F` → `EB` (`jmp short`, same disp8) | ±127 |
| **near** `jg` | `0F 8F disp32` (6 B) | `0F 8F` → `90 E9` (`nop ; jmp near`, same disp32) | ±2 GB |

For the near flip, the `E9` ends at the same address the `jg` did, so the identical `disp32` targets the same label — still direction-only, just length-6 instead of length-1.

### How each site is located (relocation-tolerant, never guessed)

Each site is pinned by a `.text`-**unique** ~24-byte signature that surrounds the `jg`. Location proceeds:

1. **Fast path** — check the site's known absolute RVA for the reference build.
2. **Relocation scan** — if the fast path misses, scan all of `.text` for the signature and accept it **only if it matches at exactly `expectedMatches` offsets** (normally 1; 2 for a milestone that folds two gates to byte-identical bodies). Any other count → declined, never guessed.

The matcher is exact on every signature byte **except** the `jg` opcode (`7F`/`EB`, or `0F 8F`/`90 E9`) and its **displacement**, which are wildcarded. The displacement is masked because a point release often moves the not-affected target — outside the signature window — while leaving every byte *inside* the window identical. Masking only the displacement lets such a shift relocate cleanly, while a genuine layout change still misses rather than false-matching.

A write happens only if the byte is currently the stock opcode (or is already flipped, for idempotent re-runs). If nothing matches, the patcher runs a **report-only** structural scan (the `cmp …,2 ; jg ; … ; cmp …,{1,5}` skeleton), prints candidates, and **refuses to write** — see §5.

---

## 3. The containers

### 3a. Windows — `chrome.dll` (PE32+)

`151.0.7922.76 chrome.dll`, PE32+, RSDS GUID `30dfcd7159e8bb144c4c44205044422e` (age 1). RVA → file-offset deltas (subtract to convert an RVA to a raw file offset):

| Section | RVA − file |
| :--- | :--- |
| `.text` | `0xA00` |
| `.rdata` | `0xE00` |
| `.data` | `0x1400` |

These deltas are build-specific — recompute them from the target's own section headers when porting. (The stock 152.0.7977.30 build's `.text` delta is `0xA00`, image base `0x180000000`.)

**PE fixups after the flips:**
- **Security directory**: `IMAGE_DIRECTORY_ENTRY_SECURITY` (RVA + size) is zeroed so the loader accepts the now-unsigned DLL. This also doubles as the stock/patched discriminator (a non-zero security dir means untouched stock).
- **Checksum**: `OptionalHeader.CheckSum` is recomputed over the whole file.

On a default consumer install the signature-stripped `chrome.dll` loads and runs without any registry change — confirmed on 151.0.7922.109 with no `RendererCodeIntegrityEnabled` policy set.

**32-bit (x86) `chrome.dll` (PE32).** The parser accepts PE32 (`OptionalHeader.Magic 0x10B`) as well as PE32+ (`0x20B`); the two differ only in the fixed optional-header length before the data directories (96 vs 112 bytes), so the Security-directory offset is picked by magic while the CheckSum field (offset 64) and the whole checksum algorithm are identical. Crucially, **the flip primitive is unchanged** — the `cmp <mv>,2 ; jg` idiom and the `7F`→`EB` / `0F 8F`→`90 E9` edits are byte-identical in 32- and 64-bit x86 — so only *new signatures* are needed, not a separate patch strategy. The 32-bit codegen drops the REX prefixes and uses smaller struct offsets (e.g. `IsExtensionAffected` opens `83 7A 28 02` = `cmp [edx+0x28],2` where 64-bit has `83 7A 50 02` = `cmp [edx+0x50],2`), so its byte windows differ entirely and are derived fresh. A 32-bit build is tagged `container: "pe32"` (§4) so it never cross-probes the 64-bit `pe` tables. 32-bit Chrome installs under `Program Files (x86)`; a loose copy elsewhere is reached with the script's custom-path prompt.

**arm64 `chrome.dll` (PE32+, Windows on ARM).** Copilot+/Snapdragon PCs run a **native arm64** Chrome. Its `chrome.dll` is a PE32+ exactly like x64 — same optional-header magic `0x20B`, same Security-directory trick, same checksum — but the COFF **machine field is `0xAA64`** (arm64) instead of `0x8664` (x64). `Open-PeImage` reads that field and tags the target `container: "pe-arm64"`, so it probes only arm64 tables and an x64 build never probes it, even though both are PE32+. The *code*, not the container, is what differs: arm64 has no `cmp/jg`, so the gate is `cmp w,#2 ; b.gt` and the sanctioned edit is the **same `B.cond` GT→AL flip as the macOS arm64 slice** (§4e) — `kind: "bcond"`, one byte, `imm19` preserved. The PowerShell engine gained that `bcond` kind (matcher, `Test-SigAt`, and the flip in `Invoke-PatchMilestones`) so the identical primitive now serves macOS Apple Silicon and Windows on ARM. Unlike macOS, Windows arm64 **publishes a PDB** on the Chromium symbol server, so the shipped `151-win-arm64` gates are symbol-verified (§4b″), and — unlike macOS arm64, which needs a bundle re-sign — the PE strip-and-run path (zero the Security directory, recompute the checksum) works unchanged, so arm64 is patched by default with no opt-in flag.

### 3b. Linux — one ELF

Official builds are non-component (`is_component_build = false`), so the entire browser links into a single stripped PIE executable — there is no separate `libchrome.so`:

| Property | Value (151.0.7922.108) |
| :--- | :--- |
| Path | `/opt/google/chrome/chrome` |
| Size | 290,897,224 bytes |
| Type | `ELF 64-bit LSB pie executable, x86-64`, `DYN`, stripped |
| Build ID | `014c38679139be4a5f6fa4ae33bd82ef72d07f56` |
| `.gnu_debuglink` | `chrome.debug`, CRC-32 `0x84f46212` |
| `.text` | vaddr `0x031a8000`, file offset `0x31a7000`, size `0xd6e81b5` (~215 MiB) |
| `.rodata` | vaddr `0x01969000`, file offset `0x1969000` |
| Owner / mode | `root:root`, `0755` |

**`.text` vaddr ≠ file offset.** The delta here is `0x1000` (`0x031a8000` → `0x31a7000`). Compute it from the section headers; assuming equality would silently point every signature `0x1000` into a neighbouring function.

ELF has **no security directory and no checksum**, so writing the flipped bytes is the whole job — no post-fixups. There is no versioned install subdirectory (the binary sits directly in the install dir), so version discovery cannot come from the path. Sibling files that are **not** targets but matter operationally: `chrome-sandbox` (setuid root `4755`), `chrome_crashpad_handler`, `apparmor.d/google-chrome-stable`, `CHROME_VERSION_EXTRA` (holds the channel).

**`.deb` and `.rpm` ship the identical ELF.** Google builds the Linux x86-64 `chrome` once per release and wraps that same payload in both the Debian and RPM packages. Verified on 151.0.7922.108: the `chrome` ELF extracted from `google-chrome-stable_current_x86_64.rpm` has the same **build-id** (`014c3867…`) as the installed `.deb` binary and is **byte-for-byte identical** to the stock `.deb` (the only diffs observed were the 5 gate sites, and only because the live install had already been patched — its `chrome.bak` is bit-identical to the RPM ELF). So **one `elf` signature table covers both package families** — the signatures key on the ELF, never on the packaging. An RPM host (Fedora/RHEL/openSUSE) installs to the same `/opt/google/chrome/chrome`, so the patcher's existing target enumeration and atomic-write path apply unchanged; only the revert-on-update mechanism differs (`dnf/zypper` + `rpm -V` flags the modified binary, the analogue of `apt upgrade` / `dpkg --verify`). The RPM payload is an `xz`-compressed `cpio` (`070701` newc); `rpm2cpio` isn't needed — the header's `PAYLOADCOMPRESSOR`/`PAYLOADFORMAT` tags name it and stdlib `lzma` streams one member out.

**arm64 (aarch64) Linux — `container: "elf-arm64"`.** Since mid-2026 Google ships an official arm64 `chrome` (`google-chrome-{stable,beta}_current_arm64.deb`, same `dl.google.com/linux/direct/` path as x86-64, shared version feed). It is the same single stripped PIE, but the ELF header's **`e_machine` is `0xB7` (EM_AARCH64)** instead of `0x3E` (x86-64). Both `derive_milestone.py` and `chrome-mv2.sh` read `e_machine` and tag the binary `elf-arm64` vs `elf`, so the two never cross-probe — exactly as the COFF machine field splits `pe`/`pe-arm64` on Windows. The *code* differs the same way it does on the other arm64 targets: no `cmp/jg`, so the gate is `cmp w,#2 ; b.gt` and the edit is the **same `bcond` GT(0xC)→AL(0xE) one-byte flip** as macOS/Windows arm64 (§4e/§4b″); ELF has no security directory or checksum, so the flipped bytes are the whole job (no re-sign, unlike the macOS bundle). **Google publishes no arm64 Linux debug-info** (only the `…-linux64-…` x86-64 zip exists), so unlike every other arm64 table the gates could not be symbol-named: they were located by the arm64 finder and cross-checked against the same-version, symbol-verified `…-win-arm64` / `…-macos-arm64` tables (identical `ManifestV2Handler` / `StandardManagementPolicyProvider` idiom; the arm64 instruction sequences match modulo register allocation). Inlining differs from x86-64 Linux — e.g. `151-linux-arm64` has two `UserMayInstall` inline sites and, like `151-linux`, one shared out-of-line `IsExtensionAffected` predicate — so the arm64 table is derived from the arm64 binary directly (five bodies for 151, four for 152, matching `152-win-arm64` 1:1), `--verify`ed, and confirmed on real aarch64 hardware.

### 3c. macOS — one universal (fat) Mach-O + code signing

macOS ships the browser as `Google Chrome.app`; the gate-bearing binary is the framework Mach-O at `Contents/Frameworks/Google Chrome Framework.framework/Versions/<v>/Google Chrome Framework`. It is a **universal (fat) binary** with two thin slices — **x86_64** and **arm64** — each with its own `__TEXT,__text`. The cross-platform `chrome-mv2.sh` owns this platform (its Mach-O flow, selected by container magic); `scripts/derive_milestone.py` grew a Mach-O parser that returns one `Image` per slice.

| Property | Value |
| :--- | :--- |
| Fat header | big-endian, `FAT_MAGIC 0xCAFEBABE` (32-bit `fat_arch`) / `0xCAFEBABF` (64-bit) |
| Thin slice | `MH_MAGIC_64 0xFEEDFACF`, on disk `CF FA ED FE` (little-endian) |
| cputype | x86_64 `0x01000007`, arm64 `0x0100000C` (mask cpusubtype `& 0x00FFFFFF`) |
| `__text` | `LC_SEGMENT_64 0x19` → segment `__TEXT`, section `__text` |
| Build identity | `LC_UUID 0x1B` (per slice); stable across the flip **and** the re-sign |
| Signature | `LC_CODE_SIGNATURE 0x1D` → `CS_SuperBlob` in `__LINKEDIT` |

**No vmaddr→fileoffset delta for byte location** — the opposite of ELF. `section_64.offset` is already the *slice-relative file offset*, so the absolute file offset of `__text` is `fat_arch.offset + section.offset`. (The vmaddr delta only re-enters when mapping a symbol's `n_value`.) The derivation stores `text_virt = section.addr` for `jgRVA` bookkeeping and `text_raw = fat_arch.offset + section.offset`.

**Code signing is load-bearing.** Any byte edit invalidates the `CS_SuperBlob` page hash; on Apple Silicon the kernel refuses to launch an invalid/absent signature (`Killed: 9`). Unlike the Windows PE trick (zero the Security directory and run unsigned), Mach-O has **no strip-and-run** path — the binary must be **re-signed**. A bare-Mach-O ad-hoc sign is *insufficient*: signing is bundle-scoped (the `.framework` and the enclosing `.app` seal the framework's cdhash), and **library validation** rejects an ad-hoc framework loaded by Google's Team-ID-signed main executable — so *every* component that maps the framework (the main app **and** the helper apps) must become ad-hoc too. The naïve `codesign --deep` does exactly that, but it re-signs each nested component with **no entitlements**, and that **strips the Renderer helper's `com.apple.security.cs.allow-jit`** (V8 then can't map JIT pages and renderers crash); `--preserve-metadata` on the *outer* `.app` only preserves the outer app's own entitlements, not the nested helpers'. So the script instead walks the bundle **inside-out** and signs **every nested bundle and Mach-O individually** (deepest path first, the `.app` last) with `--preserve-metadata=entitlements,flags` — re-embedding each component's own entitlements and keeping its hardened-runtime flag. `requirements` is **dropped** (not preserved): the original designated requirement pins Google's cert chain and an ad-hoc signature can't satisfy it, so codesign regenerates an ad-hoc DR instead. Then `codesign --verify --deep --strict`. **The backup must live OUTSIDE the `.app`.** An earlier design put `Google Chrome Framework.bak` + `.bak.meta` beside the framework binary *inside* the bundle; stray files inside a signed bundle break its seal, so `codesign --sign` chokes on the `.meta` and `--verify --strict` rejects the app (and a rollback that leaves those files behind keeps it invalid) — and a Keystone update swaps the whole `.app`, wiping anything inside it anyway. The backup is therefore stored in the macOS-standard app-data location keyed by the framework's build UUID (the host slice's `LC_UUID`): `«base»/Library/Application Support/chrome-mv2-patch/«uuid»/«Framework».bak`, where `«base»` is `/Library` when running with the root the `/Applications` patch needs (machine-wide, and root can write it) or `~/Library` for an unprivileged run against a user-writable copy. It captures the **original Google-signed** framework bytes *before* any edit, so `restore` copies those exact bytes back and re-signs the bundle ad-hoc inside-out — the framework bytes are byte-identical stock, though the restored signature is valid-ad-hoc rather than Google's original. `spctl` will report "rejected" for an ad-hoc app — expected and benign for an already-installed, de-quarantined app; it does not block launch.

**Other macOS specifics** (the Mach-O flow in `chrome-mv2.sh`): quit **all** Chrome processes first — macOS has no `ETXTBSY` guard and a re-signed page whose cdhash differs kills the *live* process (`SIGBUS`), not just a stale mapping; patch the real `Versions/<v>/…` file, not the `Versions/Current`/top-level symlinks; read the version from the app's `Info.plist` `CFBundleShortVersionString`; `/Applications/Google Chrome.app` is third-party, so not SIP-protected (needs only write access); Keystone auto-update replaces the whole `.app`, reverting the patch (the UUID change flags it, the analogue of `apt upgrade`). Stock macOS ships **bash 3.2** and no usable system `python3`, so the whole script (both the ELF and Mach-O flows) avoids bash-4 features and ships its table pre-tokenized (JSON via `--signatures` is optional and only then needs `python3`).

---

## 4. The per-platform site tables

The PowerShell and Bash scripts carry embedded, platform-specific milestone tables and also accept an external `signatures.json`. Runtime precedence is an explicitly selected signature file, then `signatures.json` beside the script, then the embedded table. Each script probes every applicable milestone and applies only the best unambiguous match, so one script supports several versions without their signatures interfering. Each milestone is tagged with its `container` (`pe` 64-bit PE / `pe32` 32-bit PE / `pe-arm64` arm64 PE / `elf` / `macho-arm64`) so a target never probes a table for a different container. `signatures.json` is the canonical derivation table; every shipped entry must also be synchronized into `$EmbeddedSignatures` in `chrome-mv2.ps1` (PE) or `EMBEDDED_SIGNATURES` in `chrome-mv2.sh` (ELF **and** Mach-O, in one merged pre-tokenized table).

### 4a. Windows 151 — seven short-`jg` flips (151.0.7922.76)

| Site | `jg` RVA | Effect of the flip |
| :--- | :--- | :--- |
| `IsExtensionAffected` | `0x083012E4` | the standalone predicate → not affected |
| `ShouldBlockExtensionInstallation` | `0x08301323` | don't block install |
| `ShouldBlockExtensionEnable` | `0x03291F6B` | don't block enable (also covers `chrome.management`) |
| `OnExtensionSystemReady` (inlined loop) | `0x01618C4C` | skip the per-extension disable in the startup loop |
| `MaybeReEnableExtension` | `0x08301436` | re-enable already-disabled MV2 extensions |
| `UserMayInstall` (inlined) | `0x08E736BA` | don't block **Load Unpacked** (own inlined copy; builds `IDS_EXTENSIONS_CANT_INSTALL_MV2_EXTENSION`) |
| `MustRemainDisabled` (inlined) | `0x016448AA` | don't force an installed MV2 extension back to disabled on restart |

The first analysis found only the five non-inlined sites; the patch verified on disk but Load-Unpacked still failed, because `UserMayInstall` carries its **own** inlined copy reached *before* the other five, and `MustRemainDisabled` carries a private copy that would re-disable on restart. Both must be flipped — hence seven.

### 4b. Windows 152 — a milestone rearchitecture (152.0.7977.30)

Chrome 152 is **not** a point-release relocation: Google restructured the gates, so five of the seven 151 signatures stopped matching. The old implementation located the two unchanged sites, applied them, and printed `[SUCCESS]` — but with five gates live, MV2 stayed blocked. This is why the scripts use per-milestone tables and decline partial matches by default (`… detected (2/7 …)` followed by success was the bug). What changed:

- **A shared free predicate.** `IsExtensionAffected` became `extensions::manifest_v2_util::IsExtensionAffected`, taking `(mv, type, loc)` in registers. `ShouldBlockExtensionInstallation` compiled to a 13-byte **thunk** that tail-calls it — no inlined check of its own, so flipping the free predicate covers install-blocking and there is no separate install site.
- **Two byte-identical bodies.** `ManifestV2Handler::IsExtensionAffected` and `ShouldBlockExtensionEnable` are the same `0x3e` bytes. No signature can be unique between them, so that site carries `expectedMatches = 2`: the one signature must match — and flip — **both**. A count other than 2 means the layout changed and the site is declined.
- **A near `jg`.** `MustRemainDisabled`'s bail-out is out of short range and compiled to a near `jg` (`0F 8F rel32`), which a short-jg-only scan never even saw.

| Entry | `jg` RVA | Enc. | Matches |
| :--- | :--- | :--- | :--- |
| `manifest_v2_util::IsExtensionAffected` (covers the install thunk) | `0x82d26f5` | short | 1 |
| `ManifestV2Handler::IsExtensionAffected` + `ShouldBlockExtensionEnable` (shared body) | `0x3348754` | short | **2** |
| `OnExtensionSystemReady` startup loop | `0x124109c` | short | 1 |
| `MaybeReEnableExtension` | `0x82d24d6` | short | 1 |
| `UserMayInstall` (inlined, Load-Unpacked gate) | `0x8ddc241` | short | 1 |
| `MustRemainDisabled` (inlined) | `0x15a8d31` | **near** | 1 |

Six entries → seven physical flips. `OnExtensionSystemReady` and `MaybeReEnableExtension` have byte-identical signatures across 151 and 152, so both tables match them; "most sites located wins" disambiguates cleanly (a real 152 build satisfies 6 of the 152 entries and only ~2 of 151, and vice-versa).

### 4b′. Windows 151 x86 — the same seven, 32-bit codegen (151.0.7922.109)

The 32-bit `chrome.dll` carries the **same seven gates as 64-bit 151**, all short `jg`, each matching exactly once — the milestone is `container: "pe32"`, name `151-x86`. Derived from the 32-bit build + its PDB with the standard `scripts/` recipe (§5); the PDB named all seven gate functions cleanly.

| Site | `jg` RVA | Enc. |
| :--- | :--- | :--- |
| `IsExtensionAffected` | `0x07022F9A` | short |
| `ShouldBlockExtensionInstallation` | `0x07022FE7` | short |
| `ShouldBlockExtensionEnable` | `0x029E11BE` | short |
| `OnExtensionSystemReady` startup loop | `0x00B20DB9` | short |
| `MaybeReEnableExtension` | `0x0702310D` | short |
| `UserMayInstall` (inlined) | `0x079D46E7` | short |
| `MustRemainDisabled` (inlined) | `0x0111E3EC` | short |

The bytes differ from 64-bit 151 (no REX prefixes, smaller struct offsets — §3a), but the structure is identical: seven inlined `cmp <mv>,2 ; jg` sites, same seven functions. Because the container tag differs, a 32-bit target only ever probes this table and a 64-bit target only the `pe` tables — no cross-arch false match is possible. (Note `MustRemainDisabled` is a **short** `jg` here, unlike 64-bit *152* where it went near — encoding is per-build, always sweep both.)

### 4b″. Windows 151 arm64 — the same seven, a `B.cond` flip (151.0.7922.138)

Windows on ARM runs a **native arm64 `chrome.dll`** (PE32+, machine `0xAA64`, container `pe-arm64` — §3a). It carries the **same seven gates as Windows 151 x64**, but arm64 has no `cmp/jg`: each gate is `cmp w,#2 ; b.gt not_affected`, and the sanctioned edit is the **same `B.cond` GT→AL condition flip as the macOS arm64 slice** (§4e) — `kind: "bcond"`, one byte (`b0 = (b0 & 0xF0) | 0x0E`), `imm19` preserved. That primitive was added to the PowerShell engine (matcher, `Test-SigAt`, `Invoke-PatchMilestones`) so it now serves both macOS Apple Silicon and Windows on ARM from one code path.

Unlike macOS, **Windows arm64 publishes a PDB** on the Chromium symbol server, so all seven gates were **symbol-named** exactly as the x64/x86 tables are: `scripts/fetch_symbols.py` derived the RSDS key from the dll and pulled the matching `chrome.dll.pdb` (served gzip-compressed, ~1 GB → ~5.5 GB), then `scripts/symbols_from_pdb.py` (dbghelp) attributed each `cmp #2 ; b.gt` site to its function. The full site table (`container: "pe-arm64"`, name `151-win-arm64`):

| Gate function (symbol) | jg RVA | b.cond |
| :--- | :--- | :--- |
| `ManifestV2Handler::OnExtensionSystemReady` | `0x01058388` | `bcond` |
| `StandardManagementPolicyProvider::MustRemainDisabled` | `0x0125352C` | `bcond` |
| `ManifestV2Handler::ShouldBlockExtensionEnable` | `0x02C0729C` | `bcond` |
| `MV2DeprecationImpactChecker::IsExtensionAffected` (shared predicate) | `0x02C07334` | `bcond` |
| `ManifestV2Handler::ShouldBlockExtensionInstallation` | `0x07836B6C` | `bcond` |
| `ManifestV2Handler::MaybeReEnableExtension` | `0x07836C94` | `bcond` |
| `StandardManagementPolicyProvider::UserMayInstall` | `0x082F94F8` | `bcond` |

`derive_milestone.py --verify` reports `151-win-arm64` VERIFIED 7/7 against the stock build (fetched with `fetch_chrome_binary.py --platform win-arm64`, which unwraps the current stable arm64 **enterprise MSI** — Chrome for Testing has no arm64 build), and patching a **scratch copy** of the real arm64 `chrome.dll` changes exactly fifteen bytes — the seven `b.gt`→`b.al` nibble flips (`…C`→`…E`) plus the recomputed PE checksum and the zeroed Security directory — with `restore` returning it byte-identical. Two of the seven byte-windows (`ShouldBlockExtensionEnable`, `ShouldBlockExtensionInstallation`) are identical to the macOS arm64 slice of the same version; the other five differ in register allocation (different ABI), which is why the mac table does **not** transfer and the Windows table is derived from the Windows dll. Because Windows arm64 is symbol-verified and uses the strip-and-run PE path (no bundle re-sign), it is patched by default (no opt-in flag), like the now-default-on macOS arm64 slice. **CI:** a native-arm64 GitHub runner (`windows-11-arm`) runs both the synthetic-fixture engine test and a real-dll job that fetches the current stable arm64 `chrome.dll`, re-verifies the shipped table fits, and round-trips patch → idempotent re-patch → byte-identical restore. Only the final *launch* of a patched arm64 Chrome is not exercised — but Windows has no code-signing launch gate (the patch just zeroes the Authenticode dir and fixes the checksum, unlike macOS's mandatory re-sign), and the functional MV2 re-enable is the same shared C++ already A/B-proven on Linux/macOS, so that gap is far smaller than §4e's.

**Chrome 152 arm64 (`152-win-arm64`, 152.0.7977.42).** Derived the same way from the beta arm64 `chrome.dll` (fetched via `--platform win-arm64 --channel beta`) + its PDB. Chrome 152's rearchitecture folds the gates into **four** sites: `OnExtensionSystemReady`, `MaybeReEnableExtension`, and two shared bodies (`ShouldBlockExtensionEnable`/`IsExtensionAffected`, and `MustRemainDisabled`/`UserMayInstall`) each matching `expectedMatches=2`. The two shared bodies are only *mask-equivalent* — their `cmp`/follow-up bytes are identical and only the wildcarded `B.cond` displacement differs — so the table dedupes on the masked signature (a raw-string compare would ship a redundant fifth site that flags the other copy as spuriously "RELOCATED"). `--verify` reports 4/4 and a scratch-copy patch flips six `b.gt`→`b.al` bytes (two sites × two copies + two singletons), restoring byte-identical.

### 4c. Linux 151 — five sites, derived and verified (151.0.7922.108)

Disassembling the resolved gates on 151.0.7922.108 shows the **identical skeleton to Windows** — `cmp <manifest_version>, 2 ; jg not_affected`, short `jg` (`0x7F`) at the enforcement sites:

```
; MV2DeprecationImpactChecker::IsExtensionAffected  (the shared predicate)
67d9f10:  83 7e 50 02    cmp  DWORD PTR [rsi+0x50], 0x2
67d9f14:  7f 2f          jg   67d9f45              ; -> xor eax,eax ; ret  (not affected)

; ManifestV2Handler::ShouldBlockExtensionInstallation
98d3cc4:  83 fe 02       cmp  esi, 0x2
98d3cc7:  7f 1f          jg   98d3ce8

; ManifestV2Handler::ShouldBlockExtensionEnable
98d3d0a:  83 fa 02       cmp  edx, 0x2
98d3d0d:  7f 29          jg   98d3d38
```

So the flip carries over unchanged (`7F` → `EB`, same disp8). The `.text` vaddr → file-offset conversion was validated against these three addresses: raw bytes at `vaddr − 0x1000` match the disassembly exactly.

**The full site table (`container: "elf"`, name `151-linux`):**

| Site | `jg` RVA | Enc. | Effect of the flip |
| :--- | :--- | :--- | :--- |
| `MV2DeprecationImpactChecker::IsExtensionAffected` (shared predicate) | `0x67D9F14` | short | the reachable gate → not affected; also covers the `ManifestV2Handler` thunk and the out-of-line `OnExtensionSystemReady` / `MaybeReEnableExtension`, which **call** it |
| `ManifestV2Handler::ShouldBlockExtensionInstallation` | `0x98D3CC7` | short | don't block install |
| `ManifestV2Handler::ShouldBlockExtensionEnable` | `0x98D3D0D` | short | don't block enable |
| `StandardManagementPolicyProvider::UserMayInstall` (inlined) | `0xA3224A3` | **near** | don't block Load-Unpacked (its `jg` shares the target with the adjacent allowed-type exit) |
| `StandardManagementPolicyProvider::MustRemainDisabled` (inlined) | `0x5E5DB24` | short | don't force an installed MV2 extension back to disabled on restart |

**Architecture note — Linux 151 resembles Windows *152*, not 151.** `ManifestV2Handler::IsExtensionAffected` (`0x98d3cb0`) is a bare 14-byte thunk that tail-calls the shared predicate and carries no gate; `MaybeReEnableExtension` (`0x98d3df0`) and the tiny `OnExtensionSystemReady` (`0x67d9af0`, 0x24 bytes) both **call** the shared predicate out-of-line rather than inlining a `cmp/jg` — so, unlike Windows, there is no separate `OnExtensionSystemReady` flip site; the shared-predicate flip covers them. The two `StandardManagementPolicyProvider` copies **are** inlined and need their own flips, and `UserMayInstall`'s is a **near** `jg` — invisible to a short-only sweep, the §7 lesson. Six gate symbols, five physical flips.

**Flip verified by execution.** Beyond byte-diffing (5 edits, 6 bytes, all direction-only — §7 CARDINAL RULE), the shared predicate was mapped and called in-process against a synthetic Extension: **stock** returns 1 (affected) for `mv=2` and 0 for `mv=3`; **patched** returns 0 for both — MV2 unblocked, MV3 unchanged. Chrome itself starts and renders cleanly on the patched binary (headless, full install tree). The derivation used the `.symtab`-direct dump (`scripts/symbols_from_elf.py`, ~3 min) rather than `nm -SC`, which is impractically slow on the 1.4 GB `chrome.debug` with 3 GB RAM.

---

### 4d. Linux 152 — the same five gates, rearchitected like Windows 152 (152.0.7977.30 beta)

Derived from the `google-chrome-beta` `.deb` (`--platform linux --channel beta`), the first Linux entry taken from beta rather than stable. Linux 152 picks up exactly the Windows 152 rearchitecture (§4b), so the 151 signatures mostly stop matching: of the five `151-linux` entries only the shared predicate's bytes survive, and that lone carry-over is the *whole* overlap between the two tables.

| Site | `jg` RVA | Enc. | Matches | Effect of the flip |
| :--- | :--- | :--- | :--- | :--- |
| `manifest_v2_util::IsExtensionAffected` (free predicate) | `0x0985B449` | short | 1 | not affected; also covers `ShouldBlockExtensionInstallation`, a 16-byte thunk that tail-jumps here |
| `ManifestV2Handler::IsExtensionAffected` / `ShouldBlockExtensionEnable` (shared body) | `0x0985B0F4` | short | 1 | don't block enable; also covers the out-of-line `OnExtensionSystemReady` / `MaybeReEnableExtension` calls |
| `ManifestV2Handler::MaybeReEnableExtension` (inlined) | `0x0985B238` | short | 1 | re-enable already-disabled MV2 extensions |
| `StandardManagementPolicyProvider::UserMayInstall` (inlined) | `0x0A256BAA` | **near** | 1 | don't block **Load Unpacked** |
| `StandardManagementPolicyProvider::MustRemainDisabled` (inlined) | `0x0599A69A` | **near** | 1 | don't force an installed MV2 extension back to disabled on restart |

Three differences worth recording against the other tables:

- **ICF folds the shared body, so `expectedMatches` is 1, not 2.** `ManifestV2Handler::IsExtensionAffected` and `ShouldBlockExtensionEnable` are the same *address* here (`0x985b0f0`, `0x47` bytes), not two byte-identical copies at different addresses as on Windows 152. One symbol, one site, one flip — the `expectedMatches = 2` of the Windows entry would be *wrong* on Linux.
- **`MaybeReEnableExtension` regained its own inlined copy.** On Linux 151 it called the shared predicate out-of-line and needed no site of its own; on 152 it carries an inlined `cmp/jg` again, which is the extra entry relative to §4c. `OnExtensionSystemReady` (`0x422d810`, `0x24` bytes) still only calls out, so it still has no site — the count stays five, but not the same five.
- **Both `StandardManagementPolicyProvider` gates are now near `jg`.** On Linux 151 only `UserMayInstall` was; `MustRemainDisabled` was short. A short-only sweep would now miss *two* sites — §7's lesson, third platform.

Byte-diff of the patched scratch copy: **7 bytes across 5 edits, all direction-only** — three short `7F` → `EB`, two near `0F 8F` → `90 E9`, every disp8/disp32 preserved and the file size unchanged (§7 CARDINAL RULE). `restore` reproduces the stock binary byte-for-byte.

**Table disambiguation, both directions.** The one shared signature means each table partially matches the other's build, and "most sites located wins" resolves it with margin: on the 152 beta ELF `152-linux` satisfies 5/5 and `151-linux` 1/5; on the 151.0.7922.108 stable ELF `151-linux` satisfies 5/5 and `152-linux` 1/5. Both were confirmed by running the Linux script against a scratch copy, not just `--verify`. This is the guard-rail the third-party beta signatures in §7 lacked: a beta-derived entry is safe to ship precisely because it is container- and milestone-tagged and every site is accepted only on an exact match count, so on a stable build it declines instead of matching an unrelated function.

**Not yet runtime-tested.** The 151 entry was confirmed by executing the patched predicate in-process and a headless startup (§4c); this one is verified statically (on-disk bytes + Linux-script acceptance) on a Windows host. Chrome 152 beta on a Linux box is the remaining check before treating it as proven.

---

### 4e. macOS — the universal framework, x86_64 + arm64 (151.0.7922.138)

Both slices of the universal `Google Chrome Framework` carry the **same seven gates as Windows 151**; only the container and (for arm64) the branch encoding differ. All fourteen sites were **symbol-verified** against the official dSYMs (see below), then confirmed to relocate cleanly against both the consumer framework (unwrapped from the `.dmg`) and the Chrome for Testing build. Distinct container tags (the Intel x86_64 slice and the arm64 `macho-arm64` slice) keep the slices from cross-probing, exactly like `pe`/`pe32`/`elf`. *(Historical: the Intel x86_64 slice was dropped in v1.10.0 — macOS ships `macho-arm64` only.)*

**Symbols do exist for macOS — via the dSYM endpoint.** Google serves per-arch dSYM archives at `https://dl.google.com/chrome/mac/{channel}/dsym/googlechrome-{version}-{arch}-dsym.tar.bz2` (the endpoint Chromium's `tools/mac/download_symbols.py` uses; `arch` ∈ `x86_64`,`arm64`). They are **UUID-matched to consumer Chrome**, so they line up with the framework unwrapped from the consumer `.dmg`, *not* the Chrome for Testing build (same version string, different `LC_UUID` — verified: CfT arm64 `4c4c447e…` vs consumer `4c4c4467…`). `scripts/fetch_symbols.py` streams the ~2.4 GB archive, keeps only the DWARF Mach-O's `LC_SYMTAB` (the symtab/strtab sit near the front, so it never decompresses the multi-GB debug sections), verifies the slice `LC_UUID`, and emits `nm`-style lines for `scripts/derive_milestone.py --symbols`. That is how every gate below was named and attributed by function.

**x86_64 slice (Intel) — seven short/near sites, byte-identical idioms to Linux/Windows.** The flip primitive is unchanged (`7F`→`EB`, `0F 8F`→`90 E9`). The shared-predicate, enable, install-thunk, `OnExtensionSystemReady`, and `MaybeReEnableExtension` signatures are byte-for-byte the Windows/Linux 151 bytes. *(This slice was dropped in v1.10.0; the table below is retained as a derivation record.)*

| Site | `jg` RVA | Enc. |
| :--- | :--- | :--- |
| `ManifestV2Handler::IsExtensionAffected` | `0x071364A4` | short |
| `ManifestV2Handler::ShouldBlockExtensionInstallation` | `0x071364F7` | short |
| `ManifestV2Handler::ShouldBlockExtensionEnable` | `0x04727A9D` | short |
| `ManifestV2Handler::OnExtensionSystemReady` | `0x030822AA` | short |
| `ManifestV2Handler::MaybeReEnableExtension` | `0x07136608` | short |
| `StandardManagementPolicyProvider::UserMayInstall` (inlined) | `0x07B4CFF9` | **near** |
| `StandardManagementPolicyProvider::MustRemainDisabled` (inlined) | `0x01B652F7` | short |

An earlier structural-only pass shipped **five** x64 sites (mirroring Linux) and missed `OnExtensionSystemReady` + `MaybeReEnableExtension` — the same "found some, MV2 still blocked" trap as §4a/§7. The dSYM symbols caught the omission; the shipped table is now the complete seven.

**arm64 slice (`macho-arm64`) — the same seven, a new flip primitive.** arm64 has no `cmp/jg`; the `mv >= 3` early-out compiles to:

```asm
    cmp  w?, #2          ; SUBS WZR, Wn, #2
    b.gt not_affected    ; taken when mv>=3  (cond GT = 0xC)
```

The sanctioned flip rewrites **only the branch condition GT→AL**, keeping `imm19` so it targets the same not-affected label — the direction-only analogue of `jg`→`jmp`. `B.cond` word = `0x54000000 | (imm19<<5) | cond`; `cond` is the **low nibble of the little-endian byte0**, so exactly one byte changes: `b0 = (b0 & 0xF0) | 0x0E` (`kind: "bcond"`). Matching is **bit-level**: a word matches iff `(w & 0xFF000010) == 0x54000000` (opcode fixed, bit4=0 to exclude `BC.cond`) and `(w & 0xF) ∈ {0xC stock, 0xE patched}`, with `imm19` wildcarded. `NV` (`0xF`) is *not* written and, if read, is treated as unexpected → declined. All seven arm64 gates (same functions as the x64 table) were symbol-named from the arm64 dSYM.

**Decline, don't guess — the arm64 shapes that break the assumption.** `cmp #3`/`b.ge` (semantically equivalent but anchors on `#2`), `cbz/cbnz/tbz`, and a fully branchless `ccmp/csel` predicate all simply miss the `cmp #2 ; b.gt` anchor → declined. A fall-through polarity validator (the `cmp #1`/`#5` `Manifest::Type` checks must follow the branch) rejects an inverted gate where flipping to AL would force the *wrong* outcome. Register fields are baked into every arm64 word, so a byte-window signature is more release-brittle than x86 (the §7 register-allocation lesson, amplified) — expect arm64 to need re-derivation more often, and to decline cleanly when it does.

**Verification gap.** The tables are byte-grounded and symbol-verified, and cross-check against both consumer and CfT builds. What remains unverified off-Mac is *runtime*: the arm64 flip **semantics** and the whole `codesign` re-seal are exercised in **GitHub Actions on real Intel and Apple Silicon runners** (fetch → `--verify` → patch a scratch `.app` → inside-out ad-hoc re-sign → `codesign --verify --deep --strict` → headless launch → **functional MV2 A/B** → `restore` to byte-identical stock), *not* by long-term daily use. The MV2 A/B (`.github/mv2_probe.py`) is a stock-vs-patched *differential*: it loads a Manifest V2 extension whose persistent background page pings a local listener the instant the extension is enabled — a disabled extension never loads its background page, so silence means disabled — and asserts the **patched** build enables the extension the **stock** build disables. The differential is necessary because by 151/152 the MV2 disable is a compiled-in feature default (`ExtensionManifestV2Unsupported`/`ExtensionManifestV2Disabled`); `--enable-features`/`--disable-features` no longer toggle it, so the flip is the only lever left, and a CfT build that happens not to enforce the deprecation is reported *inconclusive* (the byte-level `--verify` stays authoritative) rather than passed as a false positive. `macho-arm64` is symbol-verified and CI-proven on real Apple Silicon (the launch → MV2 A/B → restore above), so it is patched by default like the x86_64 slice — no opt-in flag.

**Chrome 152 (`152-macos-arm64`, 152.0.7977.42; the Intel x86_64 milestone was later dropped in v1.10.0).** Consumer *stable* mac still shipped 151 when these were derived, but Chrome-for-Testing (which the CI verifies against) had already promoted 152 — so the shipped 151 mac tables no longer covered CfT stable, and 152 mac tables were needed to keep CI green. The 152 framework came from the consumer **beta** `.dmg` (`…/mac/universal/beta/googlechromebeta.dmg`, unwrapped with 7-Zip off-Mac) and the matching beta dSYMs (`fetch_symbols.py` now auto-tries the `/beta/` dSYM path after `/stable/` 404s). 152's rearchitecture yields **six** x64 sites (two distinct gates inside `ShouldBlockExtensionInstallation`, one `near` `UserMayInstall`) and **four** arm64 `bcond` sites (a shared body folds `ShouldBlockExtensionInstallation`/`UserMayInstall`, `expectedMatches=2`); both slices `--verify` fully against the real beta framework. arm64 is patched by default, exactly like 151.

---

## 5. Porting to a new Chrome version

When Chrome bumps a milestone it may reorder `Extension` fields or change codegen, and the signatures stop matching. The patcher declines and prints structural candidates. Re-deriving is a bounded, cross-platform job — the mechanism never changes, only the bytes. The toolkit lives in `scripts/` (see `scripts/README.md`); it is dependency-free and works on both PE and ELF, both `jg` encodings.

1. **Get a stock binary** and its symbols. `python scripts/fetch_chrome_binary.py`
   downloads the channel's current installer, unwraps it, and leaves the bare
   gate binary in `_scratch/` (`--platform win64|win|win-arm64|linux|mac-arm64`,
   `--channel`, `--version` for the Chrome for Testing fallback, `--list` to just
   print current versions); a `.bak` or hand-copied binary works too. `win-arm64`
   is fetched from the stable/beta arm64 **enterprise MSI** (Chrome for Testing
   has no arm64 build, so `--version` can't pin it — use `--url` for an older
   build). Then `python scripts/fetch_symbols.py <target>` pulls the matching PDB
   (Windows, incl. arm64) or `chrome.debug` (Linux) into `_scratch/`, dispatching
   on the file's magic. A very fresh channel whose symbols aren't indexed yet
   returns HTTP 404 — pick one that exists.
2. **Name the gate functions** (optional but strongly recommended — a symbol-free scan surfaces ~150 gate-shaped idioms). Windows: `python scripts/symbols_from_pdb.py <chrome.dll> --json syms.json` (dbghelp memory-maps the multi-GB PDB; IDA/Ghidra OOM). Linux: `python scripts/symbols_from_elf.py _scratch/chrome.debug _scratch/syms.txt` (see §6 step 2 for why not `nm -SC`).
3. **Find, name, and emit** the milestone entry:
   ```
   python scripts/derive_milestone.py <binary> --symbols syms.(json|txt) --name <ver> --json
   ```
   The finder scans `.text` for `cmp <mv>,2 ; jg` in **both** encodings, applies the same follow-up (`cmp reg,{1,5}` type / `cmp byte[reg+disp32],0` location) and the same masking the runtime scripts use, and reports each site's match count. Each real site shows `matches=1` (or `2` for a shared body); a `matches>2` site needs a wider signature.
4. **Add** the entry to `signatures.json` (`container` = `pe` 64-bit / `pe32` 32-bit / `pe-arm64` arm64 / `elf`) and synchronize it into the matching embedded table: `$EmbeddedSignatures` in `chrome-mv2.ps1` for Windows (all three PE containers) or `EMBEDDED_SIGNATURES` in `chrome-mv2.sh` for Linux. Keep older milestones — each script probes all applicable entries and applies the best match. An external JSON can update signatures without editing the script, but the self-contained release scripts must embed every supported entry.
5. **Re-verify**: `python scripts/derive_milestone.py <binary> --verify` must print `ALL SITES VERIFIED: True` (a milestone fully covers the build). Run `python scripts/run_tests.py`, then patch a **scratch copy**, confirm on-disk bytes, and GUI-test. Partial or ambiguous layouts are declined by default; developer overrides exist for investigation, not normal releases.

**If the `cmp …,2 ; jg` skeleton is gone entirely** (Google changed the check, or added a manifest-parser floor that hard-rejects MV2 earlier), the flip strategy no longer applies; re-analyze the gate logic from source (`manifest_v2_handler.cc` / `mv2_deprecation_impact_checker.cc` at the new `branch-heads/*` tag) before touching any bytes.

---

## 6. Linux derivation — the recipe used (151 + 152, done) & scope

The 151 and 152 tables are derived, shipped, and verified (§4c, §4d). The exact steps, for the next milestone:

1. Fetch the binary and symbols — `python scripts/fetch_chrome_binary.py --platform linux [--channel beta]` unwraps the `.deb` and leaves the bare ELF in `_scratch/`, then `python scripts/fetch_symbols.py <that ELF>` pulls the matching `chrome.debug` (≈1.46 GB, ~1388 MiB inflated). Build-id and `.gnu_debuglink` CRC are checked both ways. Passing the fetched binary rather than `/opt/google/chrome/chrome` is what makes the whole derivation runnable from a Windows host.
2. Name the gate functions. `nm -SC chrome.debug` is correct but **impractically slow** on a 1.4 GB debug file with limited RAM (demangling + sort ran past 10 min on the 3 GB WSL box). Instead dump `.symtab` directly — a ~250-line stdlib script that streams the symbol + string tables and emits `nm -S`-style lines finishes in ~3 min. Mangled names embed the source identifier verbatim (`…19IsExtensionAffected…`), so `derive_milestone.py`'s keyword filter matches without demangling.
3. `python scripts/derive_milestone.py <chrome> --symbols syms.txt --name <ver> --json` — on 151 this surfaces exactly the five sites, each `matches=1`, sweeping short **and** near. (derive tags the ELF entry as `<ver>-linux` automatically, matching the shipped naming; pass just the bare version.)
4. The two inlined copies fall inside `StandardManagementPolicyProvider::{UserMayInstall,MustRemainDisabled}`, so the symbol filter attributes them by function range directly — no manual DWARF `DW_TAG_inlined_subroutine` walk was needed on this build. The out-of-line callers (`OnExtensionSystemReady`, `MaybeReEnableExtension`) are *not* separate sites — they call the shared predicate, which the first flip covers.
5. Add the entry to `signatures.json` (`container: "elf"`) and to `EMBEDDED_SIGNATURES` in `chrome-mv2.sh`; `--verify` -> `ALL SITES VERIFIED: True`, then run the script tests and patch a scratch **copy of the whole install tree** (the binary needs its sibling `.pak`/`icudtl.dat` to start) — never the live install in place. Confirm the flip by executing the patched predicate (see §4c) and by a headless startup.

**Scope: x86-64 only for now.** Chrome shipped official arm64 Linux `.deb`s in 2026, so aarch64 is a real future target. The flip primitive is no longer the blocker — the `B.cond` GT→AL edit (`kind: bcond`) is already shipped and verified for macOS and Windows arm64 (§4b″, §4e), and Linux aarch64 would reuse it unchanged. What's missing is a derived Linux aarch64 gate table: no arm64 Linux debug-info archive appears to be published (four plausible URL names all 404), so its gates would need structural derivation or another symbol source. Ship x86-64 first.

**Linux patcher specifics** (implemented in `chrome-mv2.sh`):
- **Atomic write.** Writing a running binary in place fails with `ETXTBSY`; the script writes a sibling temp file, `fsync`s, and `rename()`s over the target — atomic, and it preserves the path so the AppArmor profile keyed on it still applies (`root:root 0755` re-applied).
- **A mid-session swap is not "done".** Running Chrome keeps the old inode mapped; a full restart applies the patch.
- **Snap/Flatpak cannot be patched** (read-only squashfs / OSTree) — detect and decline. Ubuntu's own `chromium` is a snap and a different build entirely.
- **`apt upgrade` reverts the patch** (like Chrome's updater on Windows); `dpkg --verify` will flag the modified binary — expected. On RPM hosts the analogue is `dnf`/`zypper` upgrading `google-chrome-stable` and `rpm -V google-chrome-stable` reporting the changed `chrome` (`5` = MD5/digest differs) — same cause, same expected flag. Google ships the same `/opt/google/chrome` for both, so no package-specific handling is needed; the identical ELF means the identical signature table (§3b).
- **AppArmor (`.deb`/Ubuntu) vs SELinux (`.rpm`/Fedora, RHEL).** The atomic sibling-write + `rename()` preserves the target path, so the AppArmor profile keyed on it still applies; on SELinux systems the file context is likewise path-derived, but if a relabel is ever needed the script leaves the path in place for `restorecon` to fix. Neither MAC layer blocks the in-place edit as root.
- **`LD_PRELOAD` cannot reach the gate** — it is inlined, internal, and LTO'd, not an exported dynamic symbol.

---

## 7. Superseded approaches & lessons

**CARDINAL RULE: only flip the direction of an existing branch to its existing target. Never delete or blank a call, and never invent control flow.** An earlier approach blanked a side-effecting `call` (to force a return value) — the call was invoked purely for its side effects, so deleting it corrupted `KeyedService` state and crashed the browser on startup. Byte-level verification did not catch it: the replacement bytes were structurally valid instructions, so the crash was semantic, not structural. A branch-direction flip is the only sanctioned edit.

| Approach | Symptom | Root cause |
| :--- | :--- | :--- |
| Unanchored wildcard byte search | `STATUS_BREAKPOINT` on startup | Scanning the ~250 MB `.text` for a short pattern hit 200+ unrelated instructions in V8/Blink and corrupted them. |
| Fixed register in the pattern (`80 BF …`) | Patch skipped; MV2 still blocked | Register allocation is non-deterministic between releases; the object pointer was in a different register. |
| `cmp [rax+0x18], 2` → `3` | All installed extensions vanished | That operand *identifies* MV2 extensions during parsing; changing the compared value broke recognition of every extension. Flip the branch, not the data. |
| Toggle `g_allow_mv2_for_testing` (WinDbg-style) | No such symbol in stable | Its only writer is test-only and stripped; LTO constant-folds the gate and deletes the global. Works only on Canary/debug. |
| Blank a side-effecting `call` to fake a return | Browser crashes on startup | See CARDINAL RULE. |
| Third-party beta signatures (onlytrisdev `patch-chrome-151.bat`) | All 20 patterns *found*, MV2 still blocked | Authored against a **beta** build; on stable every pattern matched an *unrelated* function, so the writes corrupted innocent code. |
| Trusting PDB `PROC` RVAs from a hand-rolled parser | "Verified" the wrong bytes; MV2 still blocked | An in-house PDB parser landed ~`0x1000` low, so every address pointed into a neighbouring function. **Resolve symbols with `dbghelp`, not a bespoke parser.** (The same class of bug as assuming `.text` vaddr == file offset on ELF — §3b.) |
| `derive_milestone.py` `rva()` fed a slice-relative index but subtracting `text_raw` | Symbol-filtered derive emitted `sites: []` (every candidate's RVA fell outside its gate function) | The finder returns positions relative to the `.text` slice; `rva()` must be `pos + text_virt`, not `pos − text_raw + text_virt`. Latent because the shipped 64-bit tables came from the C++ tool and full signature verification did not depend on `jgRVA`; the current scripts use it as a fast path and fall back to a full masked scan. Fixed when deriving 151-x86. Same "off by a section delta" family as the PDB-parser and ELF-offset bugs. |
| Short-jg-only scan (pre-152) | Missed `MustRemainDisabled` silently | It compiled to a near `jg`. **Always sweep both encodings.** (Linux 151's `UserMayInstall` is likewise a near `jg` — same lesson, second platform.) |
| In-process gate verification passed the Extension in `rdi` | Stock predicate returned 0 (not affected) for an MV2 input — the opposite of the source, so the "test" proved nothing | `IsExtensionAffected` reads its argument from **`rsi`** (`cmp [rsi+0x50],2`): it is a method, so `rdi` is the unused `this` and the Extension is the *second* SysV arg. Passing it in `rdi` fed the gate garbage. Once handed `(this=0, ext)`, stock returned 1 for `mv=2` / 0 for `mv=3` as the C++ predicts, and the patched bytes returned 0 for both — read the register the code actually dereferences, don't assume arg0. |
| Legacy string-anchored engine (former "Stage C", 138–150) | Removed | Targeted versions that have long since auto-updated away, using the fragile techniques above. Removed in favour of declining cleanly and reporting candidates. (Recoverable from git history.) |

**Other standing rules:** never guess bytes (anchor on the longest fixed run, require an exact match count, or decline); a partial match is not success (write what was found but report it partial — a false "success" on a half-patched build is worse than declining).

---

## 8. Tooling notes

- **Stock binary download**: `scripts/fetch_chrome_binary.py` (stdlib + 7-Zip) downloads a channel's current offline installer, unwraps the nested container chain (Windows `.exe`/`.msi` → `updater.7z` → `chrome.7z` → `Chrome-bin/`; Linux `.deb` → `data.tar.xz` → `opt/google/chrome/`), and leaves just the gate binary — the `chrome.dll` (PE32+ x64/arm64 or PE32 x86; the arm64 build comes from the stable/beta **arm64 enterprise MSI**), the `chrome` ELF, or the macOS universal framework Mach-O (fetched via Chrome for Testing) — in `_scratch/`, arch-tagged and magic-checked (the arm64-vs-x64 `chrome.dll` split is by COFF machine field). `--version` falls back to the Chrome for Testing archive (unbranded — re-verify against the real install), except `win-arm64`, which has no CfT build (`--url` pins an older one).
- **Symbol download**: `scripts/fetch_symbols.py` (stdlib-only) derives the RSDS key from a PE and pulls the exact PDB from the Chromium symbol server, reads an ELF's build-id + `.gnu_debuglink` and streams `debug-info/chrome.debug` out of the per-version zip via HTTP range requests, or (macOS) reads the framework's per-slice `LC_UUID` and streams only the matching dSYM's `LC_SYMTAB` from the `dl.google.com` dSYM endpoint (trying `stable` then `beta`) — verified against the binary's build identity every way. Output lands in `_scratch/` (gitignored).
- **PDB query without IDA/Ghidra** (Windows): the PDB is multi-GB; IDA/Ghidra OOM. `scripts/symbols_from_pdb.py` uses `dbghelp.dll` via `ctypes` — `SymInitialize`, `SymLoadModuleExW` (first load ~2 min), `SymEnumSymbolsW`. RVA = symbol address − image base.
- **ELF symbol names without `nm`** (Linux): `nm -SC` on the 1.4 GB `chrome.debug` demangles and sorts the whole file and runs many minutes (impractical on a small-RAM box). `scripts/symbols_from_elf.py` streams just `.symtab` + its string table and emits `nm -S`-style lines in ~3 min; the finder's keyword filter matches the still-mangled names. Feed its output to `derive_milestone.py --symbols`.
- **Derivation/verification**: `scripts/derive_milestone.py` is stdlib-only (no capstone/pyelftools/pefile), parses PE (PE32 `pe32`, PE32+ x64 `pe`, and PE32+ arm64 `pe-arm64` — split by the COFF machine field), ELF (x86_64 `elf` and aarch64 `elf-arm64` — split by `e_machine`), and universal Mach-O, and anchors its `.text` scans on the longest fixed byte run so a pure-Python pass over ~250 MB is fast. It mirrors the match-count, masking, and report-only scan rules in the runtime scripts, extended to the near-`jg` and arm64 `bcond` encodings.
- The canonical derivation table is `signatures.json`. Its original 151/152 entries were derived from a Windows-only C++ reference patcher (preserved in git history at commit `e12fe16`); new milestones are authored into the JSON, verified with `scripts/derive_milestone.py --verify`, and synchronized into the appropriate embedded script table.

---

## 9. Beyond MV2 — permission-feature data patches (`featurebyte`)

MV2 re-enable is a `.text` branch flip. A separate need — letting an **MV3** extension use the `webRequestBlocking` permission without being policy-installed — is a different gate entirely, and the patch is a **`.rdata` data-byte overwrite**, not a branch. This is the `featurebyte` kind (Chrome 155, `pe`/x64; `chrome-mv2.py` + `chrome-mv2.ps1`).

### The gate

`webRequestBlocking` is defined in `extensions/common/api/_permission_features.json` as two rules:

```json
"webRequestBlocking": [
  { "channel":"stable", "extension_types":["extension","legacy_packaged_app"], "max_manifest_version": 2 },
  { "channel":"stable", "extension_types":["extension"], "location":"policy", "min_manifest_version": 3 }
]
```

Rule 1 grants the permission to any MV2 extension (no location restriction); rule 2 grants it to MV3 **only** when policy-installed. An MV3, non-policy extension fails rule 1 on `max_manifest_version` and rule 2 on `location`. **The chosen edit flips rule 1's `max_manifest_version` from 2 to 3** — MV3 now satisfies rule 1, and *nothing else changes* (zero blast radius). Rejected alternative: neutering the shared `SimpleFeature::GetManifestAvailability` location check would open every `location: policy`/`component` feature (incl. privileged component/private APIs) to any extension.

### Why it is data, not code

`tools/json_schema_compiler/feature_compiler.py` compiles the JSON into **C++20 designated-initializer POD structs** (`SimpleFeatureData`) in `.rdata` — the constraints (`location`, `min_manifest_version`, `max_manifest_version`, …) are struct fields, not `set_*()` calls. So the reachable edit is a single byte in `.rdata`. **This representation landed in the 154.0.8037 branch point** — 154.0.8025 and earlier have zero such structs, 155.0.8038 (and 154.0.8037) have them — so `featurebyte` needs a 154.0.8037+ build; 151/152/154.0.8025 use the older representation and the site simply does not match there.

### Struct layout (64-bit) and the exact 155 win64 target

`SimpleFeatureData = { FeatureData feature; SimpleFeatureConfig config; }`. `FeatureData` = `string_view name`(16) + `StaticCString alias`(8) + `StaticCString source`(8) + `bool no_parent`(8, padded) = **0x28**. `SimpleFeatureConfig` then lays out (each `StaticSpan` = `{ptr,size}` 16 B; each `std::optional<int/enum>` = `{value,has_value}` 8 B), giving these struct-relative offsets used by the locator:

| Field | Offset | Rule-1 value (155) |
| :--- | :--- | :--- |
| `extension_types` span size | `+0x60` | `2` |
| `location` has_value | `+0xB4` | `0` (none) |
| `min_manifest_version` has_value | `+0xBC` | `0` (none) |
| **`max_manifest_version` value** | **`+0xC0`** | **`2` → patch to `3`** |
| `max_manifest_version` has_value | `+0xC4` | `1` |

On stock `155.0.8038.0` `chrome.dll`: rule-1 struct at RVA `0x10228E10`; the byte to flip is at RVA `0x10228ED0` (file offset `0x10227AD0`), stock `0x02` → `0x03`.

### Locating it — name-anchored, not a byte window

The config-tail byte pattern recurs ~22× in the binary, so a signature window cannot pin the feature. The locator is structural (mirrored in `chrome-mv2.py` `find_feature_site`, `chrome-mv2.ps1` `Find-FeatureByteSite`, and `derive_milestone.py` `locate_featurebyte`):

1. Fast path: check the recorded `structRVA`.
2. Else scan `.rdata` for the `"<feature>\0"` literal → for each, scan `.rdata` for 8-byte little-endian pointers to it (`imagebase + literalRVA`) — each is a struct's `.name` field, i.e. the struct base.
3. Decode the struct against the site's `verify` map (offset→byte) and require the patch byte to be `stock` or `patched`; accept only when exactly `expectedMatches` structs qualify (else decline).

On **PE** the `.name` pointers sit in `.rdata` in-file. On **ELF/Mach-O** the equivalent structs live in `.data.rel.ro` with the `.name` slots emitted as relocations (zero on disk; the vaddr is a `.rela.dyn` addend), so a non-PE locator must resolve pointers through the relocations — deferred, which is why `featurebyte` ships PE-x64 only for now.

### Site schema and the `optional` flag

```json
{ "name":"…", "kind":"featurebyte", "optional":true,
  "feature":"webRequestBlocking", "structRVA":"0x10228E10",
  "patchOff":192, "stock":2, "patched":3,
  "verify":{ "96":2, "180":0, "188":0, "196":1 }, "expectedMatches":1 }
```

It rides **inside the `155` milestone** but is marked `optional`: optional sites are located and patched best-effort yet excluded from the milestone's satisfied/total ranking, so a miss (e.g. a future point-release struct move) can never drop `155` to partial or block the MV2 gates. `derive_milestone.py --feature webRequestBlocking <chrome.dll>` re-derives the site; `--verify` reports it as `feat opt`.

> **REMOVED from the shipped tables as of v1.10.0.** No milestone carries a `featurebyte` site anymore: the Gate B ExtensionSettings force-install path (below) grants the same MV3 `webRequestBlocking` capability on 155, so the site was redundant. The `featurebyte` kind itself remains supported by all three engines (for custom tables / future re-introduction — e.g. the proven-feasible 155-x86 layout).

### Gate B — honoring off-store `ExtensionSettings` on unmanaged Chrome (a `jg` flip)

A related capability: letting the `ExtensionSettings` / `ExtensionInstallForcelist` policy force-install a **self-hosted (off-Web-Store)** extension on an *unmanaged* Chrome. On unmanaged Chrome `chrome://policy` reports such an entry "ignored — not from a trusted source": `FilterSensitivePolicies()` (`components/policy/core/common/policy_loader_common.cc`) `[BLOCKED]`-prefixes any force-install entry whose `update_url` ≠ the Web Store URL, and `PolicyLoaderWin::LoadChromePolicy` calls it via `if (ShouldFilterSensitivePolicies()) FilterSensitivePolicies(&policy);`.

Unlike Gate A this is **not new** — it is stable code in 152–155 — and the flip is a **plain `jg`**, so it reuses the existing `short` kind (no new machinery). Located structurally on 155 (no usable public symbols — the policy functions are LTO-inlined; `symbols_from_pdb.py` enumerates none, so this was pinned by string anchors, the same method as the arm64 tables):

- `FilterSensitivePolicies` is the `.text` function that references all three of `[BLOCKED]`, `https://clients2.google.com/service/update2/crx`, and `EnterpriseCheck.InvalidPoliciesDetected` (its unique behavior). On 155 win64 that is `0x01FF4500`.
- It has two callers: `0x1FF3EF0` (does `ParsePolicy(…)` → guard → `FilterSensitivePolicies(&policy)` = `LoadChromePolicy`) and `0x6F4FC10` (references `local_test_id` / `%i_%i_%i` / `namespace` = the `chrome://policy/test` local-test loader, not the platform path).
- In `LoadChromePolicy`, `ShouldFilterSensitivePolicies()` is inlined to `cmp dword [rsi+0x18], 1 ; jg <skip>` — filter runs when `[rsi+0x18] <= 1` (untrusted). The gate at **RVA `0x01FF3FFF`** (`7F`), preceded by `mov rdi,[rsp+0x120] ; cmp dword[rsi+0x18],1`, followed by `lea rcx,[rsp+0x48] ; call FilterSensitivePolicies`.

**Flip `7F`→`EB`** (`jg`→`jmp`, same target `0x1FF400B`): the filter call is always skipped, so platform-source `ExtensionSettings`/`ExtensionInstallForcelist` are honored regardless of management state — direction-only, CARDINAL-RULE compliant. Shipped as a **required** `short` site in the `155` (and every Windows `pe`) milestone (`sig 488BBC2420010000837E18017F0A488D4C2448`, `jgOff 12`); a miss now drops the milestone to partial (fail-closed) rather than enabling MV2 without ExtensionSettings. **Blast radius:** all sensitive platform policies are honored on unmanaged Chrome — but setting those registry keys already requires local admin, and the alternate `chrome://policy/test` caller is left untouched. Verified byte-flip on stock 155 (`0x01FF35FF` file offset, `7F`→`EB`) in both `chrome-mv2.py` and `chrome-mv2.ps1`.

#### Gate B cross-platform (v1.10.0): the guard's shape per platform

`ShouldFilterSensitivePolicies()` is `AsyncPolicyLoader::ShouldFilterSensitivePolicies()` — `platform_management_trustworthiness_ < TRUSTED` — **compiled only on Windows and macOS** (`#if IS_WIN || IS_MAC` in `async_policy_loader.cc`); on Linux it is `return false`, so there is **no gate and nothing to flip** — Linux never filters (verified on 155-linux: the `FilterSensitivePolicies` loop calls it unconditionally per source). The trust value is an `optional<ManagementAuthorityTrustworthiness>` at `+0x18` (has_value byte at `+0x1C` on all four mac arches; `+0x18`/`+0x1C` likewise on win-arm64).

The guard's compiled shape per container (all sites **required** as of v1.10.0 — no longer optional; verified `--verify` on stock binaries, masked-match count 1):

| container | kind | stock shape | flip |
|---|---|---|---|
| pe (x64) | `short` | `cmp dword [rsi+0x18],1 ; jg` | `7F`→`EB` (shipped 152/154/155/154-cft) |
| pe32 (x86) | `short` | `cmp dword [eax+0x10],1 ; jg` (field at +0x10 on x86) | `7F`→`EB` — identical sig shape on 152/154/155 |
| macho-arm64 | `cbz` (new kind) | `mov x0,x20 ; bl SFSP ; cbz w0,<skip> ; b` | `CBZ 0x34xxxxxx`→`B 0x14yyyyyy` with the **same resolved target**: imm26 is *recomputed* from the sign-extended imm19 (layouts differ — for a negative disp the sign extension fills the bits where CBZ's Rt lived; `0x34FFDF60`→`0x17FFFEFB`, never `0x14FFDF60`) |
| pe-arm64 | `bcond` | `ldrb [x20,#0x1C] ; tbz (DCHECK) ; ldr w,[x20,#0x18] ; cmp #1 ; b.gt <skip>` | plain GT(0xC)→AL(0xE) — the existing bcond flip, no new machinery |
| elf / elf-arm64 | — | guard compiled out (`return false`) | N/A — Linux never filters |

On macOS `ShouldFilterSensitivePolicies()` is a real out-of-line function (`ldrb w?,[x0,#0x1C]; ldr w?,[x0,#0x18]; cmp #2; cset w0,lt; ret` — the x64 equivalent uses `setl`), and `PolicyLoaderMac::Load` selects it via the `kUseManagementServiceForSensitivePolicies` feature (enabled by default) before guarding the `FilterSensitivePolicies(&chrome_policy)` call. The other FSP caller on every platform is the `chrome://policy/test` local-test loader (`local_test_id`/`%i_%i_%i` refs), which calls FSP unconditionally and is left untouched.

The `cbz` matcher decodes both encodings and compares **resolved targets** (a foreign unconditional B must not read as "ours, already patched"); Rt is pinned in the stock form only (the rewrite's imm26 sign extension overwrites those bits). The `stockOpcode` field (near/short) pins the sig's stock pair at load time — the sig bytes at `jgOff` stay the single runtime source of truth, so no matcher signature changed. Chrome-version removals/updates as of v1.10.0: the 151 milestones are gone; **macOS Intel (x86_64) support is dropped — macOS ships `macho-arm64` only** (154 mac arm64 is covered by the 152-macos-arm64 table, 5/5 on 154.0.8025). Gate B is now a **required** gate (no longer optional): 152-x86/154-x86/155-x86/152-macos-arm64/155-macos-arm64/154-win-arm64 and the `pe` milestones all carry it, and the Win-x86 (pe32) Gate B signatures were re-derived to be build-robust (operand-free — no build-specific `call rel32`).

