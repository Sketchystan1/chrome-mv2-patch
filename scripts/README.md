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
| `port_milestone.py` | **Start here to add a version.** One command: learn the build's Extension field offsets, keep only real gates, fold linker-shared bodies into one `expectedMatches=N` site, pick the shortest signature with no build-specific PC-relative immediate, carry site names from `--prev`, and `--merge` into `signatures.json`. | stdlib only |
| `audit_signatures.py` | Audit the table for what silently breaks patching: equal-rank ties (two milestones the runtime can't choose between, so it declines), signatures pinned to one build (`pc_relative_spans` flags arm64 `adrp`/`adr`/`BL`/`B` and x86 `lea rip`/`call`/`jmp rel32`), weak anchors, malformed sites. With `--binary`, also reports which milestone would be selected and runs a completeness pass that does **not** use the `cmp,2;jg` finder. | stdlib only |
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
       --name 155 --prev 154 --moved 0x30:0x50 --merge
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
4. **Add** the emitted entry to the `milestones` array in `../signatures.json`.
   That's the only copy — the scripts fetch `signatures.json` from the GitHub raw
   URL at runtime (precedence: an explicit `--signatures` path → `signatures.json`
   beside the script → the URL). There are no embedded tables to keep in sync, but
   **push `signatures.json`** so the raw URL serves the new milestone.
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
`--verify` (reports it as `feat opt`) and `audit_signatures.py --binary`. The
representation is new in Chrome 155; 154 and earlier do not carry these structs.

The masking and match-count rules mirror both runtime scripts:
`Find-AffectedJgSites` / `Invoke-PatchMilestones` in `chrome-mv2.ps1` and
`find_site_matches` / `probe_slice` in `chrome-mv2.sh`. A table that
verifies here must still be exercised through the script tests.

## InstallVerifier gate cross-platform notes (Route A — off-store install, no managed banner)

The InstallVerifier gate (`InstallVerifier::MustRemainDisabled` → force `IsFromStore`)
lets an off-store extension installed via the **non-policy** external-extensions
provider stay enabled without the "managed by your organization" banner (full
rationale: [`../mv2-reversing.md`](../mv2-reversing.md) §8). It **replaced Gate B**,
which was removed — Gate B needed the `ExtensionSettings` policy route that triggers
the banner. Enforcement is compiled **only on Windows and macOS**; Linux is `NONE`
(no gate). All sites are `optional`.

- **pe (x64)** / **pe32 (x86)**: `short`, `stockOpcode 0x75` — the inlined
  `IsFromStore` from_webstore test `test byte[ext+OFF],8 ; jne <verified>`, flipped
  `jne`→`jmp`. `creation_flags` is at `ext+0x254` (x64) / `ext+0x17c` (x86).
- **pe-arm64 / macho-arm64**: `tbz` — `ldrb w,[ext,#0x254] ; tbnz w,#3,<verified>`,
  the `tbnz` rewritten to an unconditional `B` to the same target. The `tbz` kind is
  the sibling of `cbz`: stock detect `(w & 0x7E000000)==0x36000000`, a matched site
  pins `(w & 0xFFF8001F)` (family/op/bit-position/Rt) with imm14 wild, patched word
  `0x14000000 | (sign_extend((w>>5)&0x3FFF,14) & 0x03FFFFFF)` (e.g. `0x37180188` →
  `0x1400000C`).
- **macho-arm64**: the unbranded CfT framework dead-code-eliminates the inline
  (ENFORCE folds to false off-brand), so it must be derived from a **branded**
  `Google Chrome Framework`. Fetch it off-Mac with
  `fetch_chrome_binary.py --platform mac-arm64 --branded` (downloads the universal
  `.dmg`, carves the arm64 slice with 7-Zip), then `fetch_symbols.py --chrome-version`
  (the consumer dSYM is UUID-matched to that `.dmg`). mac `creation_flags` sits at
  `ext+0x24c` (not `+0x254` like Windows): `ldrb w,[ext,#0x24c] ; tbnz w,#3,<verified>`.

Deriving: locate `InstallVerifier::MustRemainDisabled` (win64/x86 via the vtable off
the `"InstallVerifier"` provider-name string, or PDB; arm64 via PDB / structurally),
find the inlined `from_webstore` test, and `build_site` a window trimmed to exclude
any RIP-relative/`adrp` immediate. The gate must come from a **branded** binary (the
`ENFORCE` path is `#if GOOGLE_CHROME_BRANDING`); CfT confirms the offset/structure but
its flip is a no-op. The `stockOpcode` field (short/near) pins the sig's stock opcode
at load time; the sig bytes at `jgOff` remain the runtime source of truth.

