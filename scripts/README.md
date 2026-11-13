# scripts — MV2 gate derivation toolkit

Cross-platform tooling to fetch symbols for, derive, and verify
the Chrome MV2 gate signatures used by `../chrome-mv2.ps1` (Windows) and
`../chrome-mv2.sh` (Linux + macOS). The canonical editable table is `../signatures.json`.
The core analysis tools use the Python standard library; the experimental
Windows scanner additionally uses Capstone and Z3.
Supported containers on x86, x86-64, and arm64:
64-bit PE `chrome.dll` (container `pe`), 32-bit PE `chrome.dll` (container
`pe32`), 64-bit **arm64** PE `chrome.dll` on Windows-on-ARM (container
`pe-arm64`, the same `bcond` flip as macOS arm64), the ELF `chrome` on Linux —
x86_64 (`elf`) and **arm64** (`elf-arm64`, same `bcond` flip) — and the universal
`Google Chrome Framework` Mach-O on macOS — its arm64 slice (`macho-arm64`;
Intel x86_64 support was dropped in v1.10.0).
Replaces the old single-build `port152/` workspace.

Full rationale: [`../mv2-reversing.md`](../mv2-reversing.md) §"Porting to a new version".

Chrome 159 introduces inverted JLE/B.LE checks and a CSEL predicate. The
`derive_milestone.py` finder still finds JG/B.GT only; review these new forms from
source and disassembly.
The matcher, hardener, verifier, and audit support `short-nop`, `near-nop`,
`bcond-nop`, and `csel`, plus 64-bit CBZ. Put 159 tables in `milestones_v2` so older
DLLs ignore them. Both arrays are read by updated engines and verification tools.
Windows requires `version.dll` 1.16.0 or later; updating JSON alone is insufficient.

| Script | What it does | Deps |
| :--- | :--- | :--- |
| `port_milestone.py` | **Start here to add a version.** One command: learn the build's Extension field offsets, keep only real gates, fold linker-shared bodies into one `expectedMatches=N` site, pick the shortest signature with no build-specific PC-relative immediate, carry site names from `--prev`, and `--merge` into `signatures.json`. | stdlib only |
| `audit_signatures.py` | Audit the table for what silently breaks patching: equal-rank ties (two milestones the runtime can't choose between, so it declines), signatures pinned to one build (`pc_relative_spans` flags arm64 `adrp`/`adr`/`BL`/`B` and x86 `lea rip`/`call`/`jmp rel32`), weak anchors, malformed sites. With `--binary`, also reports which milestone would be selected and runs a completeness pass that does **not** use the `cmp,2;jg` finder. | stdlib only |
| `fetch_chrome_binary.py` | Download the stock, gate-bearing binary itself — a channel's current `chrome.dll` (PE64/PE32), Linux `chrome` (ELF), or the macOS universal framework Mach-O (`mac-arm64`, always via Chrome for Testing) — unwrap it and drop it in `_scratch/`, named after the version the **binary** reports (release feeds have advertised a different one). `--version` falls back to Chrome for Testing. | stdlib + 7-Zip |
| `fetch_symbols.py` | Download the symbols matching a binary — PDB (PE) from the Chromium symbol server, `chrome.debug` (ELF) streamed from the per-version zip, or the macOS dSYM's symtab streamed from `dl.google.com/…/dsym/` (emits `nm`-style names directly). Verifies build identity and discards a mismatch: Chrome-for-Testing builds have no published symbols, and a version's Linux `debug-info` zip belongs to the *official* build. Saves to `_scratch/` (gitignored). | stdlib only |
| `derive_milestone.py` | The low-level finder: gate sites (`cmp <mv>,2 ; jg`, short **and** near, plus arm64 `bcond`), an unfiltered candidate report, and `--verify` for an existing table. `port_milestone.py` wraps it. | stdlib only |
| `scan_windows.py` | Experimental Windows x64 discovery without a maintained table or symbols: infer field relationships, follow both branch outcomes, and check the local predicate with Z3. Reports unresolved candidates; optional `--plan` generates current-binary windows for a reviewed runtime experiment. | Capstone + z3-solver |
| `symbols_from_elf.py` | Linux: dump an ELF's `.symtab` as `nm -S`-style lines, fast and low-memory — a stand-in for `nm -SC` on the multi-GB `chrome.debug` (see note in step 2). | stdlib only |
| `symbols_from_pdb.py` | Windows only: name gate functions from a PDB via `dbghelp`. Optional — used to filter/name candidates. Official `win-arm64` PDBs are published too (multi-GB). | Windows + PDB |

The test suite is Python too and lives flat in this folder (no subfolder):
`run_tests.py` (entry point) drives `test_linux.py` (ELF), `test_macos.py`
(Mach-O), `test_windows.py` (PE, Windows-only), `test_memory.py` (the legacy C++
table-based memory engine, with MSVC/Detours headers), `test_derive.py`
(arm64 finder unit checks), and `test_scan_windows.py`
(skipped unless Capstone and Z3 are installed); `make_macho_fixture.py` builds a synthetic universal
Mach-O and `_testutil.py` holds the shared fixture builders/helpers. Run all of
it with `python scripts/run_tests.py`.

Checks run concurrently in two waves: table/engine checks first, then the Bash
ELF/Mach-O tests. Use `--fast` to skip the slower Bash wave. On Windows, put Git
Bash on PATH before the WSL launcher because the fixtures use `/c/...` paths.
`test_memory.py` skips when MSVC or the Detours headers are unavailable; run
`mv2-mem-patch-win/build.bat` first.

The compact DLL's CMake tests and diagnostic scanner use
`mv2-mem-patch-win/out/<arch>/`; see its [build instructions](../mv2-mem-patch-win/README.md).
`check_autoscan_matrix.py` and `test_autoscan_runtime.py` use the x64 tools there
by default, with the runtime DLL at `mv2-mem-patch-win/build/x64/version.dll`.
For the carrier beside `chrome.exe`, use
`--dll mv2-mem-patch-win/build/x64/secur32.dll`. Its runtime matrix also removes
the cached scan plan before restarting the same profile to check a cold scan.

On an x64 Windows host with MSVC ARM64 tools and WSLC, run
`python scripts/test_memory.py --arm64`. This cross-compiles the legacy engine tests
and runs them with `linaro/wine-arm64:10.2` (Wine + QEMU). It also executes the ARM64
`bcond`, `bcond-nop`, `csel`, and `tbz` predicates before and after patching, checks
repeat application and memory protection, and fails if its prerequisites are missing.
The default test suite still runs x64; browser MV2 runtime testing is separate.


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

## Signature-free Windows research

`scan_windows.py` accepts a Windows x64 `chrome.exe` or `chrome.dll` and reads
neither `signatures.json` nor debug symbols. It follows basic blocks, recovers
field relationships, and uses Z3 to check the decoded MV2 predicate's routing.
Its optional analysis dependencies are Capstone and `z3-solver`:

```powershell
uv run --with capstone --with z3-solver scripts/scan_windows.py <chrome.exe> --json scan-report.json
uv run --with capstone --with z3-solver scripts/test_scan_windows.py
```

The recognizer uses the source contract in Chromium's
[`manifest_v2_util.cc`](https://chromium.googlesource.com/chromium/src/+/refs/tags/157.0.8103.39/extensions/browser/manifest_v2_util.cc)
and [`Extension::GetType()`](https://chromium.googlesource.com/chromium/src/+/refs/tags/157.0.8103.39/extensions/common/extension.cc):

```text
manifest_version < 3
&& (converted_user_script || type in {1, 3, 8})
&& location not in {5, 10}
```

It finds signed 32-bit comparisons with 2 or 3, follows JG/JLE/JGE/JL outcomes,
and checks equality chains or the `0x10A` type mask. It derives field offsets
from their data flow. Windows unwind metadata supplies function ranges; small
leaf predicates use aligned padding. Neither requires a PDB. The decoder follows
blocks after RET and handles partial registers, conditional moves and Boolean
returns. Missing type-range guards and wrong location polarity fail the solver
check. The investigated CSP selectors are excluded.

The separate [native Windows x64 DLL](../mv2-mem-patch-win/AUTOSCAN.md) builds on
this research and performs discovery at startup without an exported JSON plan.
Its compiler coverage and validation results differ from this Python prototype.

This is a read-only research tool. A successful local predicate proof does not
prove complete enforcement coverage or the purpose of every caller. Candidates
that pass the prescreen but cannot be verified are reported as unresolved;
different instruction forms or missing function boundaries can escape that
prescreen entirely. Analysis is bounded, calls are opaque, and the enum values
still depend on Chromium's source contract. Every report explicitly sets
`complete_enforcement_coverage_proven` to `false`.

`--plan FILE` generates JSON compatible with the existing runtime, containing
byte windows derived from the current binary. No maintained signature table is
read. Plan export declines unresolved candidates, unverified extra matches and
branch forms the runtime cannot apply. Check the plan's `binary_sha256` against
the tested DLL before use: the existing runtime does not enforce this additional
hash field. A reviewed local experiment must configure the runtime to read this
file without its normal remote table refresh. The default installers still use
`signatures.json`. No permission-feature or InstallVerifier patches are generated.

**Measured on stripped Chromium 157.0.8103.39, Windows x64 (2026-11-08):** the
supplied `chrome.exe` resolved to `157.0.8103.39/chrome.dll`. The scanner found
5,765 branch heads, verified seven predicates and left no unresolved prescreened
candidates. The generated plan contains six windows covering seven decisions.
A sandboxed launch of a scratch copy rejected MV2 stock, then ran both MV2 and
MV3 with that plan. The original and copied `chrome.dll` hashes stayed unchanged.
A packed MV2 extension installed through the non-policy external provider also
passed disable/enable and restart checks. Removing the plan restored its
unsupported-manifest disabled state. MV2 request blocking worked with the core
plan alone. The test proxy redirected only the external-extension registry
source to a temporary subtree; no extension was registered with installed
browsers, and the subtree was removed afterward.

Other local Windows scans illustrate the limits: 153.0.8010.37 verified seven
predicates but left two candidates unresolved; 156.0.8060.2 verified seven with
none unresolved; 159.0.8148.0 verified six and left two unresolved. The latter
includes a startup loop whose hoisted type mask cannot be established across
an opaque call. The 153 and 159 results therefore decline plan export.

The optional MV3 `webRequestBlocking` patches were removed from all shipping
tables. Custom `featurebyte` descriptors remain supported by the existing engines.

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

