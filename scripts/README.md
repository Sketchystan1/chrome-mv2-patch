# scripts — MV2 gate derivation toolkit

Cross-platform, dependency-free tooling to fetch symbols for, derive, and verify
the Chrome MV2 gate signatures used by `../chrome-mv2.ps1` (Windows) and
`../chrome-mv2.sh` (Linux + macOS). The canonical editable table is `../signatures.json`.
Works for any future Chrome version on x86, x86-64, and arm64:
64-bit PE `chrome.dll` (container `pe`), 32-bit PE `chrome.dll` (container
`pe32`), 64-bit **arm64** PE `chrome.dll` on Windows-on-ARM (container
`pe-arm64`, the same `bcond` flip as macOS arm64), the ELF `chrome` on Linux —
x86_64 (`elf`) and **arm64** (`elf-arm64`, same `bcond` flip) — and the universal
`Google Chrome Framework` Mach-O on macOS — its arm64 slice (`macho-arm64`;
Intel x86_64 support was dropped in v1.10.0).
Replaces the old single-build `port152/` workspace.

Full rationale: [`../mv2-reversing.md`](../mv2-reversing.md) §"Porting to a new version".

| Script | What it does | Deps |
| :--- | :--- | :--- |
| `port_milestone.py` | **Start here to add a version.** One command: learn the build's Extension field offsets, keep only real gates, fold linker-shared bodies into one `expectedMatches=N` site, pick the shortest signature with no build-specific PC-relative immediate, carry site names from `--prev`, and `--merge`/`--sync`. | stdlib only |
| `audit_signatures.py` | Audit the table for what silently breaks patching: equal-rank ties (two milestones the runtime can't choose between, so it declines), signatures pinned to one build (`pc_relative_spans` flags arm64 `adrp`/`adr`/`BL`/`B` and x86 `lea rip`/`call`/`jmp rel32`), weak anchors, malformed sites. With `--binary`, also reports which milestone would be selected and runs a completeness pass that does **not** use the `cmp,2;jg` finder. | stdlib only |
| `sync_embedded.py` | Rewrite both embedded fallback tables from `signatures.json`, per entry (adds, updates **and** removals). `--check` reports drift for CI. | stdlib only |
| `fetch_chrome_binary.py` | Download the stock, gate-bearing binary itself — a channel's current `chrome.dll` (PE64/PE32), Linux `chrome` (ELF), or the macOS universal framework Mach-O (`mac-arm64`, always via Chrome for Testing) — unwrap it and drop it in `_scratch/`, named after the version the **binary** reports (release feeds have advertised a different one). `--version` falls back to Chrome for Testing. | stdlib + 7-Zip |
| `fetch_symbols.py` | Download the symbols matching a binary — PDB (PE) from the Chromium symbol server, `chrome.debug` (ELF) streamed from the per-version zip, or the macOS dSYM's symtab streamed from `dl.google.com/…/dsym/` (emits `nm`-style names directly). Verifies build identity and discards a mismatch: Chrome-for-Testing builds have no published symbols, and a version's Linux `debug-info` zip belongs to the *official* build. Saves to `_scratch/` (gitignored). | stdlib only |
| `derive_milestone.py` | The low-level finder: gate sites (`cmp <mv>,2 ; jg`, short **and** near, plus arm64 `bcond`), an unfiltered candidate report, and `--verify` for an existing table. `port_milestone.py` wraps it. | stdlib only |
| `symbols_from_elf.py` | Linux: dump an ELF's `.symtab` as `nm -S`-style lines, fast and low-memory — a stand-in for `nm -SC` on the multi-GB `chrome.debug` (see note in step 2). | stdlib only |
| `symbols_from_pdb.py` | Windows only: name gate functions from a PDB via `dbghelp`. Optional — used to filter/name candidates. Official `win-arm64` PDBs are published too (multi-GB). | Windows + PDB |

The test suite is Python too and lives flat in this folder (no subfolder):
`run_tests.py` (entry point) drives `test_linux.py` (ELF), `test_macos.py`
(Mach-O), `test_windows.py` (PE, Windows-only), and `test_derive.py`
(arm64 finder unit checks); `make_macho_fixture.py` builds a synthetic universal
Mach-O and `_testutil.py` holds the shared fixture builders/helpers. Run all of
it with `python scripts/run_tests.py`.

The steps are independent (each uses its own tmp dir and only reads the shared
tables) and spawn/IO-bound rather than CPU-bound — the harness itself does almost
no computation, it waits on child processes — so they run **concurrently in two
waves**. Wave 1 is the fast, deterministic set (table audits, the PowerShell PE
suite, and the pure-Python universal port that already covers PE + ELF + Mach-O);
if anything there fails the run stops before wave 2 starts, so a real regression
still fails in seconds. Wave 2 is the bash black-box tests (`test_linux.py` /
`test_macos.py`), which shell out to `chrome-mv2.sh`; on a Windows host they go
through the git-bash/WSL launcher where every patch/restore/check spawn is slow
(`test_linux.py` can exceed a few minutes) and the environment is fragile — that
slowness/failure is a WSL artifact, not a table defect (those tests use synthetic
fixtures, never `signatures.json`). Parallelizing the waves cut the fast run from
~91s to ~53s here; because the cost is spawn/IO latency, not compute, rewriting
the harness in a faster language would not help (it would spawn the same bash).
Use `python scripts/run_tests.py --fast` (or `MV2_TEST_FAST=1`) to skip the bash
black-box pair; CI still runs them on native Linux/macOS, and `test_pyport.py`
covers the same ELF/Mach-O patch logic cross-platform via the `MV2_TEST_*` toggles.


## Verify the shipping table still fits a build

```
python scripts/derive_milestone.py <stock chrome.dll|chrome>  --verify
# -> "ALL SITES VERIFIED: True" when a milestone fully covers the binary

python scripts/audit_signatures.py --binary <stock chrome.dll|chrome>
# -> which milestone the runtime would SELECT, whether anything ties, and whether
#    the binary holds a gate no site covers
```

`--verify` only asks whether each recorded site still matches. The audit is the
one that catches a table which verifies yet still fails in practice: a milestone
that ties with another (the runtime declines rather than guess), or a gate that is
present in the binary and covered by nothing.

## The short version: port a milestone

```
python scripts/fetch_chrome_binary.py --platform win64 --version 155.0.8038.0
python scripts/port_milestone.py _scratch/chrome-155.0.8038.0-win64.dll \
       --name 155 --prev 154 --moved 0x30:0x50 --merge --sync
python scripts/audit_signatures.py --binary _scratch/chrome-155.0.8038.0-win64.dll
python scripts/run_tests.py
```

`port_milestone.py` prints the field offsets it learned, every linker-shared body
it folded, any signature it could not make build-independent, and which sites it
could not carry a name for (a gate that is new this version has no previous name
to inherit — write one by hand). `--moved old:new` tells the name-carry which
Extension field offsets shifted since `--prev`; omit it if nothing moved.

> **Gotcha — a `cmp <mv>,2 ; jg` can be a reason-string selector, not a gate.**
> The `IsExtensionAffected (type!=PLATFORM_APP variant)` site added in the 154
> pass turned out to match a *message-string builder* (it picks the
> MV2-deprecation warning text), not an enforcement gate. Flipping it crash-loops
> the browser with a `CHECK`/`STATUS_BREAKPOINT` — but **only after a real MV2
> extension is installed**, so a fresh-profile launch and a clean `--verify` both
> pass. It was removed from all 11 tables on 2026-09-09 (`154-cft` deleted as a
> redundant dup of `152`). When adding any `cmp,2;jg` site, disassemble **both**
> branches: a real gate reads the manifest-version field (`[member+0x30]`, x86
> `+0x164`) and returns a bool; a string-selector loads string-literal addresses
> (`lea rip→.rdata` / `adrp+add` / `mov imm32`) and converges — reject it. It
> matches exactly once, so the `matches>2` rule never flags it. Full postmortem:
> `../mv2-reversing.md` §5 and §7. Runtime-test with an MV2 extension installed,
> never just an empty profile.

## Derive a new milestone by hand (e.g. Chrome 153)

The long form, for when `port_milestone.py` reports something it could not resolve.

1. **Get a stock binary** for the new version. `fetch_chrome_binary.py`
   downloads the channel's current installer, unwraps it, and leaves just the
   gate binary in `_scratch/`:
   - Windows x64: `python scripts/fetch_chrome_binary.py --platform win64`
   - Windows x86: `python scripts/fetch_chrome_binary.py --platform win`
   - Windows arm64: `python scripts/fetch_chrome_binary.py --platform win-arm64`
     (fetches the current stable arm64 build from the arm64 enterprise MSI;
     Chrome for Testing has no arm64 build, so pin an older build with
     `--url <per-build installer>` rather than `--version`, or hand-copy an
     arm64 `chrome.dll`.)
   - Linux:       `python scripts/fetch_chrome_binary.py --platform linux`
   - Linux arm64: `python scripts/fetch_chrome_binary.py --platform linux-arm64`
     (fetches the current stable/beta build from the arm64 `.deb`; shares the
     `linux` version feed. Chrome for Testing has no arm64 Linux build, so it
     can't pin an older `--version` — use `--channel stable`/`beta`, or hand-copy
     an arm64 `chrome`.)
   - macOS ARM:   `python scripts/fetch_chrome_binary.py --platform mac-arm64`

   Defaults to the host's platform and the `stable` channel; `--channel beta`
   or `--version X.Y.Z.W` (Chrome for Testing fallback) pick another build, and
   `--list` just prints the current versions. A `.bak` or hand-copied
   `chrome.dll`/`chrome` works just as well — the fetch is a convenience, not a
   requirement.
2. **Get symbols** to name/filter candidates (optional but recommended — a
   symbol-free scan surfaces ~150 gate-shaped idioms). `fetch_symbols.py`
   downloads them into `_scratch/`:
   - Windows: `python scripts/fetch_symbols.py <chrome.dll>` then
     `python scripts/symbols_from_pdb.py <chrome.dll> --symdir _scratch --json _scratch/syms.json`
   - Linux: `python scripts/fetch_symbols.py <the ELF from step 1>` then
     `python scripts/symbols_from_elf.py _scratch/chrome.debug _scratch/syms.txt`
     (feeds `--symbols`). Prefer `symbols_from_elf.py` over `nm -SC chrome.debug`:
     `nm` demangles and sorts the whole 1.4 GB debug file and runs many minutes
     (and can thrash a small-RAM box); the dumper streams just `.symtab` in a
     few minutes, and the finder's keyword filter matches the still-mangled
     names fine.
   - macOS: symbols come from Google's official dSYMs. `fetch_symbols.py` reads
     the framework's per-slice UUID, streams the matching
     `googlechrome-{ver}-{arch}-dsym.tar.bz2`, keeps only its `LC_SYMTAB`
     (symtab/strtab sit near the front, so the multi-GB DWARF is never fully
     decompressed), and writes `_scratch/mac-<arch>-syms.txt` for `--symbols`.
     The dSYMs are UUID-matched to **consumer** Chrome (unwrap the `.dmg`), not
     Chrome for Testing (same version, different UUID). A universal binary emits
     one milestone per slice (`--json` returns both). See mv2-reversing.md §4e.
3. **Find + emit** the entry:
   ```
   python scripts/derive_milestone.py <binary> --symbols syms.(json|txt) --name 153 --json
   ```
   Each site should show `matches=1` (or `2` for a byte-identical shared body).
   A `matches>2` site needs a wider signature.
4. **Add** the emitted entry to the `milestones` array in
   `../signatures.json`, then copy the platform entry into the matching embedded
   table: `$EmbeddedSignatures` in `../chrome-mv2.ps1` for `pe`/`pe32`/`pe-arm64`,
   or the pre-tokenized `EMBEDDED_SIGNATURES` in `../chrome-mv2.sh` for `elf`
   (Linux) and `macho-arm64` (macOS).
   The scripts use an explicit signature path first, then `signatures.json`
   beside the script, then their embedded table. Keep the JSON and embedded copy
   synchronized.
5. **Re-verify**: `python scripts/derive_milestone.py <binary> --verify` must
   print `ALL SITES VERIFIED: True`.
6. **Run the script tests**:
   `python scripts/run_tests.py` from the repository root.
7. Patch a scratch copy, inspect the changed bytes, and GUI/runtime-test on the
   target platform.

The original 151/152 entries were derived from a Windows-only C++ reference
patcher (preserved in git history at commit `e12fe16`); new versions are added to
`signatures.json` directly, per the steps above. `152-linux` was derived on a
**Windows** host from the fetched beta `.deb` — no Linux box is needed for steps
1-5, only for the final GUI/runtime test.

**32-bit (x86) Chrome** is handled the same way: point the same three commands at
a 32-bit `chrome.dll`. `derive_milestone.py` tags it `container: "pe32"` (vs `pe`
for 64-bit), and `symbols_from_pdb.py` reads the PE32 `ImageBase`, so a 32-bit
build only ever probes/verifies against `pe32` milestones. The shipped `151-x86`
entry was derived this way from a 32-bit `chrome.dll` + its matching PDB.

**Windows-on-ARM (arm64) Chrome** is handled the same way too, but its
`chrome.dll` is a PE32+ like x64 — the COFF machine field (`0xAA64` arm64 vs
`0x8664` x64) is what `derive_milestone.py` reads to tag `container: "pe-arm64"`,
so arm64 and x64 never cross-probe. arm64 has no `cmp/jg`; the gate is
`cmp w,#2 ; b.gt` and the flip rewrites only the `B.cond` condition GT→AL (kind
`bcond`, byte-for-byte the same flip as the macOS arm64 slice — see
mv2-reversing.md). The shipped `151-win-arm64` entry was derived from the
consumer arm64 `chrome.dll` (fetched via `--url`) and symbol-verified against its
PDB (`symbols_from_pdb.py` reads the PE32+ `ImageBase` regardless of machine).

**Linux arm64 (aarch64) Chrome** (official Google `.deb` since mid-2026) is the
ELF counterpart: `derive_milestone.py` reads `e_machine` (`0xB7` aarch64 vs `0x3E`
x86_64) to tag `container: "elf-arm64"`, so it never cross-probes the x86_64 `elf`
table, and it uses the same `bcond` `cmp w,#2 ; b.gt` GT→AL flip as Windows/macOS
arm64. **Google publishes no arm64 Linux debug-info zip** (only `…-linux64-…`), so
unlike the other arm64 tables the gates can't be symbol-named. They are located
structurally by the arm64 finder and cross-checked against the same-version,
already symbol-verified `…-macos-arm64` / `…-win-arm64` tables (identical
`ManifestV2Handler` / `StandardManagementPolicyProvider` gates; the arm64
instruction idiom matches modulo register allocation). The shipped
`151-linux-arm64` / `152-linux-arm64` entries were derived this way from the
fetched arm64 `.deb`, `--verify`ed, and confirmed on real aarch64 Linux hardware.

**Open-source Chromium** is derived the same way but from the continuous-build
snapshots, and its gate is different: Chromium is **not PGO-built**, so it keeps a
single out-of-line `manifest_v2_util::IsExtensionAffected` predicate and *calls*
it everywhere instead of inlining it into 5-7 sites. A Chromium milestone is
therefore typically a **single site**, and its bytes do not match the Chrome
table of the same version (verified: Chrome `152-linux` matches a Google-built
Chromium 152 at only 1 of 5 sites). Fetch a snapshot with
`fetch_chrome_binary.py --browser chromium` (`--milestone N` resolves the branch
position via chromiumdash and picks the nearest snapshot; `--position N` or the
trunk `LAST_CHANGE` also work; there is **no** Linux-arm64 snapshot). Symbols:
- **Windows** — run `fetch_symbols.py <chrome.dll>` as for Chrome: it reads the
  PE's RSDS key and pulls the exact matching PDB by GUID from the Chromium
  symbol server (`chromium-browser-symsrv.commondatastorage.googleapis.com`), so
  you do **not** need the whole `chrome-win32-syms.zip`. Then `symbols_from_pdb.py`
  names the gate.
- **Linux / macOS** — the snapshot binary is itself **unstripped** (full symtab),
  so gates are symbol-named straight from it (`symbols_from_elf.py` / `nm`); there
  is **no** separate `.debug`/`.dsym` file in the Linux/Mac snapshot dirs, and the
  distro `chromium-dbg`/`-dbgsym` packages match a *distro* build's toolchain, not
  the Google snapshot these tables target.

Name the entry `<ver>-chromium`
(+`-linux`/`-macos-arm64`/… per container), keep the container tag unchanged, and
sync it into the embedded tables like any other milestone. Because Chromium and
Chrome entries share a container, runtime milestone selection prefers the
**most-specific full match** (most sites), so neither cross-matches the other.

Shipped (single-site unless noted, `--verify`ed on disk): `152-chromium-linux`
(elf, symbol-derived) and `152-chromium` (pe) — located structurally as the only
`cmp <mv>,2 ; jg` with the `0x10A` manifest-type bitmask (`mov r32,0x10A ; bt`).
Plus `151-chromium-linux` (elf, Google build) and one **distro** build,
`151-chromium-linux-xtradeb` (Ubuntu `ppa:xtradeb/apps`) — see the distro note
below. Not yet shipped, and why:

- **pe32 (Windows x86)** — Chromium's non-PGO 32-bit build compiles the gate with
  the branch **inverted** (`cmp [ebp+8],2 ; jle`, i.e. the not-affected path is
  the fall-through), where Chrome uses `jg`. The `7F→EB` primitive can't express
  that (flipping `7E` would make MV2 stay off); it needs a condition-inverting
  flip and its own verification, so it is deliberately left unshipped.
- **pe-arm64 / macho-arm64** — the arm64 free predicate can't be pinned by the
  x86 `0x10A` fingerprint (that constant is common in arm64 `.text`); name it from
  the win-arm64 PDB (`fetch_symbols.py` → the symbol server) and confirm the
  `b.cond` polarity matches the existing `bcond` GT→AL flip before shipping, then
  cross-check macho-arm64 against it.
- **elf-arm64** — Google publishes no Linux-arm64 Chromium snapshot, so there is
  no binary to derive from here.

**Distro builds** (a Linux distribution's own Chromium package) use a different
toolchain than Google's and are declined until derived from *their* binary. They
are usually **stripped and heavily inlined**, so the single-predicate model does
NOT apply — e.g. the Ubuntu `xtradeb` 151 build inlines the check into **four**
enforcement sites (`OnExtensionSystemReady`, `MaybeReEnableExtension`,
`ManagementSetEnabledFunction::CheckManifestV2Deprecation`,
`StandardManagementPolicyProvider::MustRemainDisabled`). To derive one: fetch its
debug symbols (Launchpad PPAs publish a small `chromium-dbgsym` `.ddeb`, build-id
matched — `pool/main/c/chromium/chromium-dbgsym_<ver>_amd64.ddeb`), dump them with
`symbols_from_elf.py`, and run `derive_milestone.py <binary> --symbols …`.
**Gotcha:** the finder's keyword filter can miss a gate (it dropped
`CheckManifestV2Deprecation`), so cross-check by attributing *every* `cmp,2;jg`
site to its enclosing symbol and keeping all that land in an extension/manifest/
policy function. A distro entry is build-version-specific — re-derive after the
package updates.

A Chromium table still needs the runtime Load-Unpacked MV2 A/B (a disk verify does
not prove the single predicate covers every path — see mv2-reversing.md §5).

## Permission-feature data patches (`featurebyte`, Chrome 155+ pe/x64)

Beyond the MV2 branch flip, the tables can carry a **`featurebyte`** site: a
name-anchored `.rdata` data-byte overwrite that changes one field of a compiled
permission-feature `SimpleFeatureData` struct. The shipped use is granting
`webRequestBlocking` to MV3 extensions by flipping that feature's rule-1
`max_manifest_version` from 2 to 3 (see mv2-reversing.md §9).

Derive/emit the site for a feature (PE x64 only):

```
python scripts/derive_milestone.py <chrome.dll> --feature webRequestBlocking
```

It finds the feature's rule-1 struct (extension_types size 2, a set
`max_manifest_version`, no location/min), and prints the site dict
(`structRVA`, `patchOff`, `stock`/`patched`, `verify`). Add it to the target
milestone as an **`optional`** site so a miss never blocks MV2, then
`--verify` (reports it as `feat opt`) and `audit_signatures.py --binary`.
`sync_embedded.py` carries the extra fields into the ps1 embedded table (it is
`pe`, so it never reaches the ELF/Mach-O `sh` table). The representation is new
in Chrome 155; 154 and earlier do not carry these structs.

The masking and match-count rules mirror both runtime scripts:
`Find-AffectedJgSites` / `Invoke-PatchMilestones` in `chrome-mv2.ps1` and
`find_site_matches` / `probe_slice` in `chrome-mv2.sh`. A table that
verifies here must still be synchronized into the appropriate embedded table
and exercised through the script tests.

## Gate B cross-platform notes (v1.10.0)

Gate B ("skip FilterSensitivePolicies", honoring off-store `ExtensionSettings`
on unmanaged Chrome) is a **required** site (v1.10.0) in every supported
milestone except Linux (the guard is `#if IS_WIN || IS_MAC` — Linux compiles
`ShouldFilterSensitivePolicies()` to `return false` and never filters, so it
needs no gate). A build whose Gate B does not match now reports partial
(fail-closed) rather than enabling MV2 without ExtensionSettings:

- **pe32 (x86)**: plain `short` `cmp dword [reg+0x10],1 ; jg` — the trust
  field sits at `+0x10` on x86 (vs `+0x18` on x64). Its signature was
  **re-derived build-robust** (v1.10.0): the operand-free window
  `8B7D10837810017F0953E8` (`jgOff 7`), which ends at the `call` opcode so the
  build-specific `call rel32` operand stays outside the sig — verified unique on
  152/154.8025/154.8037/155. (Derived from the `ExtensionInstallForcelist`
  string construction: the function building that 25-byte literal via
  `movups`/`movdqu` is FilterSensitivePolicies; its guarded E8 caller is
  `PolicyLoaderWin::LoadChromePolicy`.)
- **macho-arm64**: `cbz` kind — `mov x0,x20 ; bl SFSP ; cbz w0,<skip> ; b`,
  rewritten to the unconditional `B` with the same resolved target (imm26
  recomputed from the sign-extended imm19). Because the CBZ sits between a
  relative `bl` and a relative `b`, the matcher **masks embedded `BL`/`B` words**
  (opcode class still checked) and the signature extends past the `b` to an
  invariant tail (`mov x20,x0 ; ldrsb w8,[sp,#imm]`) for a unique anchor — so it
  is build-robust rather than pinned to one build. That tail's frame slot is
  per-milestone (`#0x6f` on 152, `#0x8f` on 153/155), so mac carries both
  `152-` and `153-macos-arm64` (153 keeps 152's un-shifted bcond layout).
  `derive_milestone.py --verify` handles the kind; the locator is string-anchored
  (FSP refs `[BLOCKED]`/CWS/`EnterpriseCheck.InvalidPoliciesDetected` via ADRP+ADD).
- **pe-arm64**: plain `bcond` — `ldr w,[x20,#0x18] ; cmp #1 ; b.gt`, flipped
  GT→AL with the existing machinery. The arm64 PE `.pdata` directory holds
  **8-byte (BeginRVA, UnwindRVA)** entries, not the x64 12-byte
  RUNTIME_FUNCTION triples — parse accordingly when locating functions.
- The `stockOpcode` field (short/near kinds) pins the sig's stock opcode at
  load time; the sig bytes at `jgOff` remain the runtime source of truth.

