# Chrome Manifest V2 Re-Enable — Reverse-Engineering Notes

## Purpose & status

Google Chrome blocks Manifest V2 (MV2) extensions by default and has removed the
flags and enterprise policy that used to re-enable them. The `chrome-mv2` patcher
re-enables MV2 by flipping a single branch at each inlined copy of one predicate
in the browser binary. This document is the *why* behind those byte edits. The
per-build byte tables themselves are **not** here — `signatures.json` is canonical
and `scripts/audit_signatures.py --binary <file>` reports coverage.

The gate is the same C++ across platforms; only the container, the toolchain's
codegen, and the OS plumbing differ. All engines relocate signatures across point
releases and **decline without writing** on layouts they do not recognize.

**Supported (v1.10.x):** Chrome **152 / 153 / 154 / 155**.
- **Windows** (`chrome-mv2.ps1`): x64 `pe`, x86 `pe32`, arm64 `pe-arm64` (PE32+, COFF
  machine `0xAA64`). PE edits strip the signature and run unsigned.
- **Linux** (`chrome-mv2.sh`): x86-64 `elf`, aarch64 `elf-arm64`. One stripped PIE;
  `.deb` and `.rpm` ship the identical ELF.
- **macOS** (`chrome-mv2.sh`): Apple-Silicon `macho-arm64` slice of the universal
  `Google Chrome Framework`, ad-hoc re-signed so it launches. Intel x86_64 was
  dropped in v1.10.0.

`chrome-mv2.py` is a stdlib-only universal port (PE + ELF + Mach-O). All three
scripts fetch `signatures.json` from the GitHub raw URL at runtime (no embedded
tables — see §4). The in-process launchers (`mv2-mem-patch-win`, `mv2-mem-patch-mac`)
reuse the same signature model.

---

## 1. Why MV2 is blocked (Chrome 138+)

Chrome 138 introduced the `ManifestV2Handler` KeyedService. Every MV2 block reduces
to two predicates:

```cpp
bool ShouldDisableLegacyExtensions();          // folds to `return true` in release
bool IsExtensionAffected(int mv, Manifest::Type t, mojom::ManifestLocation loc) {
  if (mv >= 3) return false;                    // <-- the branch we flip
  if (t != kExtension && t != kLoginScreenExtension && t != kUserScript) return false;
  if (Manifest::IsComponentLocation(loc)) return false;
  return true;
}
```

`g_allow_mv2_for_testing` (the switch the WinDbg/Canary guides toggle) is written
only by an `IN-TEST` function stripped from release, so LTO constant-folds
`ShouldDisableLegacyExtensions()` to `true` and deletes the global. The only
reachable gate is `IsExtensionAffected`'s `mv >= 3` early-out.

---

## 2. The patch — flip the branch at each inlined site

The release build inlines `IsExtensionAffected` into its enforcement sites; each
opens with the manifest-version check. **Only a branch direction changes** — no
call is removed, no return value synthesized (see §6, CARDINAL RULE).

| Arch | Stock | Flip | `kind` |
| :--- | :--- | :--- | :--- |
| x86/x64 short | `7F disp8` (`jg`; any Jcc via `stockOpcode`) | `EB` (`jmp short`), disp kept | `short` |
| x86/x64 near | `0F 8F disp32` (`jg`) | `90 E9` (`nop;jmp near`), disp kept | `near` |
| arm64 | `cmp w,#2 ; b.gt` (`54… cond=0xC`) | cond → AL `0xE`, `imm19` kept | `bcond` |

Two more kinds rewrite an AArch64 conditional to an unconditional `B` to its
existing target: **`cbz`** (a `cbz`/`cbnz`, imm19; still supported but no shipped
milestone uses it since Gate B was removed — §8) and **`tbz`** (a test-bit
`tbz`/`tbnz`, `0x36`/`0x37` family, imm14 — the arm64 InstallVerifier gate, §8). For
both, the `B`'s imm26 is recomputed from the stock branch's sign-extended offset
(imm19 or imm14). The `short` kind's stock opcode defaults to `7F` (`jg`); a site may
pin any conditional with a `stockOpcode` field — the InstallVerifier gate flips a
`75` (`jne`).

### How each site is located (relocation-tolerant, never guessed)

Each site is pinned by a `.text`-unique signature around the branch:

1. **Fast path** — check the recorded RVA for the reference build.
2. **Relocation scan** — else scan `.text` for the signature's longest fixed run and
   accept **only if it matches at exactly `expectedMatches` offsets** (1, or 2 for a
   folded/shared body). Any other count → declined.

The matcher is exact on every byte **except** masked fields: the branch opcode +
displacement (`short`/`near`), the `b.cond`/`cbz`/`tbz` word's variable field
(`b.cond` condition; `cbz` `imm19` + Rt; `tbz` `imm14`, with the `0x36`/`0x37`
family, op, bit-position and Rt pinned), and — for `cbz` — any **embedded `BL`/`B`
word**, whose PC-relative `imm26` is build-specific (opcode class is still verified).
Masking only the volatile fields lets a point-release relocate cleanly while a real
layout change still misses.

A write happens only if the byte is currently the stock opcode (idempotent on
re-run). If nothing matches, the engine prints structural candidates and refuses to
write.

---

## 3. The containers

**Windows `chrome.dll` (`pe`/`pe32`/`pe-arm64`).** PE32+ (x64/arm64) or PE32 (x86),
split by COFF machine field (`0x8664`/`0xAA64`/`0x14C`). After the flips: zero
`IMAGE_DIRECTORY_ENTRY_SECURITY` (loader accepts the unsigned DLL; doubles as the
stock/patched discriminator) and recompute `OptionalHeader.CheckSum`. No registry
change needed on a default consumer install. The flip primitive is identical across
the three; only the byte windows (register allocation, struct offsets) differ, and
the container tag keeps them from cross-probing.

**Linux `chrome` (`elf`/`elf-arm64`).** One stripped PIE; no security dir, no
checksum — the flipped bytes are the whole job. **`.text` vaddr ≠ file offset**
(compute the delta from section headers). `.deb`/`.rpm` ship the byte-identical ELF,
so one table covers both. `e_machine` (`0x3E`/`0xB7`) splits the two containers.
Atomic sibling-write + `rename()` avoids `ETXTBSY` and preserves the AppArmor/SELinux
path. Snap/Flatpak are read-only → declined.

**macOS universal framework (`macho-arm64`).** The gate binary is
`…/Google Chrome Framework.framework/Versions/<v>/Google Chrome Framework`, a fat
Mach-O; only the arm64 slice is supported. `section_64.offset` is already the
slice-relative file offset (no vmaddr delta for byte location). **Code signing is
load-bearing:** any edit invalidates the page hashes and Apple Silicon refuses to
launch. There is no strip-and-run path — the bundle must be **re-signed inside-out**
(every nested Mach-O/bundle individually, deepest first, `.app` last, with
`--preserve-metadata=entitlements,flags` so the renderer keeps `allow-jit`;
`requirements` dropped so an ad-hoc DR is regenerated). **The backup must live
outside the `.app`** (a stray file breaks the seal; Keystone swaps the whole app):
`«/Library or ~/Library»/Application Support/chrome-mv2-patch/«framework-UUID»/…bak`.
Quit all Chrome processes first (a changed cdhash `SIGBUS`es the live process).

---

## 4. Site tables & the field shift

`signatures.json` is canonical and is fetched at runtime from the GitHub raw URL
(`https://github.com/Sketchystan1/chrome-mv2-patch/raw/master/signatures.json`).
Each script's precedence is: an explicit `--signatures`/`-Signatures` path →
`signatures.json` beside the script → the URL fetch. There are **no embedded tables**
(the old `$EmbeddedSignatures`/`EMBEDDED_SIGNATURES` blobs and
`scripts/sync_embedded.py` were removed), so the default path now requires network,
and `chrome-mv2.sh` now requires `python3` on the default path (it previously used a
pre-tokenized embed to avoid it). Editing `signatures.json` is the whole job — but it
must be **pushed** so the raw URL serves the change. Each milestone is
`container`-tagged so a target only probes its own container, and the runtime applies
the **best full match** (`satisfied == total`); equal-rank partials tie and the engine
declines.

Architectural notes that matter more than the raw bytes:

- **152 rearchitecture.** `IsExtensionAffected` became a shared free predicate;
  `ShouldBlockExtensionInstallation` is a thunk that tail-calls it. Some gates fold
  to byte-identical bodies (`expectedMatches=2`) or ICF to one address
  (`expectedMatches=1`). Always sweep **both** `jg` encodings — `MustRemainDisabled`
  went `near`.
- **The +0x20 field shift at 154.0.8037.** The inlined manifest-version member moved
  (arm64 `[Xn,#0x30]→#0x50`; x64 inner `MOV EAX,[RCX+0x30]→+0x50`; outer `+0x228`
  unchanged). So per platform: **152/153** = un-shifted, **154.0.8037+/155** =
  shifted. Every 154 build is therefore bracketed — early-154 matches the 152-family
  table, late-154 matches the 155-family — so **no standalone `154` table is needed**
  on x64/x86/linux/mac; the win64 `154` table was removed in v1.10.1 as dead weight
  that risked a tie. `154-win-arm64` stays because there is no `155-win-arm64`; the
  early-154 `154-x86`/`154-linux` stay because early-154 diverges from 152 on those
  codegens.
- **macOS no longer needs a per-milestone table.** When Gate B existed, its `cbz`
  tail (`ldrsb w8,[sp,#imm]`) frame slot moved between 152 (`#0x6f`) and 153/155
  (`#0x8f`), forcing a separate `153-macos-arm64` (152 bcond + the 153 cbz). With Gate
  B removed (§8) the 4 MV2 bcond gates are layout-stable across 152/153, so
  `152-macos-arm64` covers both and `153-macos-arm64` was dropped as a redundant tie.

---

## 5. Porting to a new Chrome version

Bounded and cross-platform; the mechanism never changes, only the bytes. Toolkit in
`scripts/` (dependency-free; see `scripts/README.md`).

1. **Fetch** the stock binary (`fetch_chrome_binary.py --platform … [--channel|--version]`)
   and, where published, symbols (`fetch_symbols.py`): PDB (PE, incl. arm64),
   `chrome.debug` (Linux x64), or the dSYM symtab (mac). No symbols for CfT, arm64
   Linux, or LTO-inlined policy code → locate structurally.
2. **Derive**: `port_milestone.py <bin> --name <ver> --prev <prev> [--moved old:new] --merge`
   learns field offsets, folds shared bodies, and picks the shortest signature with
   **no build-specific PC-relative immediate** (`audit_signatures.py`'s
   `pc_relative_spans` now flags arm64 `BL`/`B` and x86 `jmp rel32`, not just
   `adrp`/`lea`/`call`).
3. **Verify**: `derive_milestone.py <bin> --verify` → `ALL SITES VERIFIED: True`;
   `audit_signatures.py --binary <bin>` → the intended milestone is selected, no tie,
   no uncovered gate; `run_tests.py`; then patch a **scratch copy** and GUI-test.

**Two traps a clean `--verify` + fresh-profile launch both miss:**
- **A `cmp,2 ; jg` may select a _reason string_, not a bool.** Disassemble **both**
  branches: a real gate reads the manifest-version field and returns a bool; a
  string-selector loads string-literal addresses (`lea rip→.rdata` / `adrp+add` /
  `mov imm32`) and converges into a message builder guarded by a downstream `CHECK`.
  Flipping it crash-loops the browser, and it matches exactly once so `matches>2`
  never flags it.
- **The runtime GUI test MUST have a real MV2 extension installed** (off-store via
  the non-policy external-extensions provider — §8), not just a fresh profile — the
  reason-string path only runs then.

If the `cmp,2 ; jg` skeleton is gone entirely, re-analyze the gate from source
before touching bytes.

---

## 6. Superseded approaches & lessons

**CARDINAL RULE: only flip the direction of an existing branch to its existing
target. Never delete or blank a call, and never invent control flow.** Blanking a
side-effecting `call` (to fake a return value) produced structurally valid bytes but
corrupted `KeyedService` state and crashed on startup — byte verification cannot
catch a semantic break.

| Approach | Symptom | Root cause |
| :--- | :--- | :--- |
| Unanchored wildcard byte search | `STATUS_BREAKPOINT` on startup | A short pattern hit 200+ unrelated `.text` sites and corrupted them. |
| Fixed register in the pattern | Patch skipped; MV2 still blocked | Register allocation varies between releases. Anchor on the longest fixed run, mask the volatile fields. |
| `cmp [reg+off],2` → `3` (edit the data) | All extensions vanished | That operand *identifies* MV2 during parsing. Flip the branch, not the data. |
| Toggle `g_allow_mv2_for_testing` | No such symbol in stable | Test-only writer stripped; LTO folds the gate. Works only on Canary/debug. |
| Blank a side-effecting `call` | Crash on startup | See CARDINAL RULE. |
| Third-party **beta** signatures on stable | All patterns *found*, MV2 still blocked | Every pattern matched an unrelated function on stable and corrupted it. Container- + milestone-tag and require an exact match count. |
| Trusting a hand-rolled PDB parser's RVAs | "Verified" the wrong bytes | Parser landed ~`0x1000` low. Resolve symbols with `dbghelp`. Same "off by a section delta" family as assuming ELF `.text` vaddr == file offset. |
| Short-`jg`-only scan | Missed `MustRemainDisabled` silently | It compiled to a `near jg`. Always sweep both encodings. |
| Flipping a `cmp,2 ; jg` that selects a **reason string** ("type!=PLATFORM_APP variant", added in the 154 pass) | **Crash-loops on launch** — but only once a real MV2 extension is installed, so scratch-copy startup misses it | It matched a message-string selector (`adrp→.rdata` string loads + a downstream `CHECK`), not an enforcement gate. Removed from all tables 2026-09-09; `154-cft` deleted. Detection rule as in §5. |
| macOS Gate-B `cbz` sig with the call's `BL`/`B` in the anchor | Matched only the one build it was cut from → mac policy force-install silently failed on other 152 builds | The `cbz` sits between a relative `BL` (before) and `B` (after); a fixed-byte anchor pinned their build-specific `imm26`. **Fix (v1.10.1): the `cbz` matcher masks embedded `BL`/`B` (opcode class still checked) and the sig extends past the `B` to an invariant tail** (`mov x20,x0 ; ldrsb w8,[sp,#imm]`) for a unique anchor. `pc_relative_spans` now flags `BL`/`B` so this can't recur. |

**Standing rules:** never guess bytes (anchor on the longest fixed run, require an
exact match count, or decline); a partial match is not success (report it partial —
a false "success" on a half-patched build is worse than declining).

---

## 7. Tooling notes

- `fetch_chrome_binary.py` (stdlib + 7-Zip): downloads a channel's offline installer
  and unwraps the container chain to the bare gate binary in `_scratch/`. `--version`
  falls back to Chrome for Testing (unbranded — re-verify); `win-arm64`/arm64-linux
  have no CfT (`--channel`, or `--url` to pin).
- `fetch_symbols.py` (stdlib): PDB via RSDS key, `chrome.debug` via range requests,
  or the dSYM `LC_SYMTAB` streamed from `dl.google.com`; verifies build identity.
- `symbols_from_pdb.py` (dbghelp/ctypes) and `symbols_from_elf.py` (streams `.symtab`,
  faster than `nm -SC` on the multi-GB debug file) name gate functions.
- `derive_milestone.py` (stdlib, no capstone/pefile): the finder + `--verify`, parses
  PE/ELF/Mach-O and mirrors the runtime match-count/masking rules for all five kinds
  (`short`/`near`/`bcond`/`cbz`/`tbz`).
- `port_milestone.py` wraps it to author a milestone; `audit_signatures.py` catches
  ties, build-pinned sigs, weak anchors, and (with `--binary`) uncovered gates.
  `run_tests.py` drives the PE/ELF/Mach-O suites. (`sync_embedded.py` was removed with
  the embedded tables — §4.)

---

## 8. Beyond MV2 — off-store install with no "managed by your organization" banner

MV2 re-enable is one gate; a second capability (**Route A**) lets an off-store,
**self-hosted** extension install and auto-update from its own `update.xml` without
any enterprise policy — so Chrome never shows the "managed by your organization"
banner.

**Why the banner appears, and how Route A avoids it.** The banner is driven by *any*
platform policy (`ShouldDisplayManagedUi` → `HasMachineLevelPolicies`), so the old
`ExtensionSettings`/`ExtensionInstallForcelist` force-install route (formerly "Gate
B", now **removed**) always flips Chrome to managed. Instead, install via the
**non-policy external-extensions provider** — the Windows registry key
`Software\Google\Chrome\Extensions\<id>` with an `update_url` value (write the
**32-bit view**: `reg add … /reg:32`, since Chrome reads `Extensions` with
`KEY_WOW64_32KEY` — or HKCU, which needs no admin), or `external_extensions.json` on
Linux/macOS. That yields ManifestLocation `kExternalPrefDownload`, which is **not** a
policy location, so the profile stays unmanaged and Chrome still auto-updates the
extension from its self-hosted `update.xml`.

**The gate: `InstallVerifier::MustRemainDisabled` → force `IsFromStore`.** On official
Chrome (`#if GOOGLE_CHROME_BRANDING && (IS_WIN || IS_MAC)`,
`GetExperimentStatus()==ENFORCE`) the `InstallVerifier` disables any non-Web-Store
extension with a **sticky** `DISABLE_NOT_VERIFIED` (the Enable toggle greys out).
`MustRemainDisabled` inlines `IsFromStore()`, whose first test is the
`from_webstore()` creation-flag bit; flipping that test to always take the "from
store" path makes `MustRemainDisabled` return false, so the extension installs and
lands in the recoverable `DISABLE_EXTERNAL_EXTENSION` state (one Enable click).
Unbranded CfT is `ENFORCE=NONE`, so the flip is a no-op there.

Enforcement is compiled **only on Windows and macOS** (like the old Gate B); on Linux
(`elf`/`elf-arm64`) it is `NONE`, so there is **no gate** and off-store installs
already work. All sites are **`optional`** (additive to MV2 re-enable — a build where
the site does not match must never fail the core patch).

| container | kind | flip |
| :--- | :--- | :--- |
| pe (x64) | `short` (`stockOpcode 0x75`) | `test byte[ext+0x254],8 ; jne <verified>` → `jne`→`jmp` |
| pe32 (x86) | `short` (`stockOpcode 0x75`) | same, `creation_flags` at `ext+0x17c` |
| pe-arm64 | `tbz` | `ldrb w,[ext,#0x254] ; tbnz w,#3,<verified>` → `tbnz`→`B` (same target) |
| macho-arm64 | `tbz` | `ldrb w,[ext,#0x24c] ; tbnz w,#3,<verified>` → `tbnz`→`B` (same target); mac `creation_flags` is at `ext+0x24c`, **not** `+0x254` like Windows |
| elf / elf-arm64 | — | compiled out (`ENFORCE=NONE`) |

Verified on branded 153 (win64, win-arm64) and CfT 155.0.8038.0 (win64, x86); the x86
and arm64 sigs are build-robust and reused across 152/154/155 via signature scan. The
**`mv2-mem-patch-win`** DLL applies these in-process — its short-flip path was fixed
to honor `stockOpcode` (use the sig's own byte at `jgOff`, not a hardcoded `0x7F`) so
the `jne` gate applies, and it gained the `tbz` kind for arm64.

> **Removed: Gate B.** "Gate B" (skip `FilterSensitivePolicies` to
> honor off-store `ExtensionSettings` on unmanaged Chrome) was removed from every
> table — it required the policy route that triggers the managed banner, which Route
> A avoids. It remains supported by the engines for custom tables but ships in no
> milestone. (The historical Gate-B `cbz` masking lesson in §6 still applies to the
> `cbz` kind generally.) The `featurebyte` `.rdata` patch (Gate A, MV3
> `webRequestBlocking`) was dropped in v1.10.0's table rework and re-added to the
> `155` table only — the 152/154 feature layout differs, so the current
> `SimpleFeatureData` offsets find no rule-1 struct there.
