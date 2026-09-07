# Agent Workspace Guidelines and Manifest V2 Patcher References

## Repository overview

This repository ships two self-contained patch scripts:

- `chrome-mv2.ps1` is the Windows implementation. It patches PE32+ x64 (`pe`),
  PE32 x86 (`pe32`), and PE32+ arm64 (`pe-arm64`, Windows on ARM — the machine
  field `0xAA64` selects it, and it uses the same `bcond` flip as macOS arm64)
  `chrome.dll` files.
- `chrome-mv2.sh` is the cross-platform Unix implementation (Linux **and**
  macOS in one script). It detects the target container from the file magic and
  patches either the x86-64 ELF `chrome` executable (`elf`), or the universal
  `Google Chrome Framework` Mach-O — the arm64 slice (`macho-arm64`, a `B.cond`
  GT→AL flip); then ad-hoc re-signs the app so it launches. (Intel x86_64 macOS
  support was dropped in v1.10.0.)

There is no compiled patcher or build step. Do not add instructions for the
removed Go application, `cmd/chrome-mv2`, `internal/app`, `build.bat`, or
platform executables. The PowerShell and cross-platform Bash scripts own all
runtime behavior: target discovery, signature loading, layout matching,
patching, backup and restore safety, elevation/signing, diagnostics, and output.

The patch re-enables Manifest V2 (MV2) extensions by flipping the existing
`IsExtensionAffected` conditional branches in Chrome's browser binary. It uses
per-milestone signature tables and applies only a complete, unambiguous match by
default.

Before modifying patching logic, read
[`mv2-reversing.md`](../mv2-reversing.md). It records the rationale, verified
gate layouts, container details, porting procedure, and failed approaches that
must not be repeated.

## Cardinal rule

Only flip the direction of an existing branch to its existing target:

- short `jg`: `7F disp8` -> `EB disp8`
- near `jg`: `0F 8F disp32` -> `90 E9 disp32`
- arm64 `b.cond` (`bcond` kind — macOS arm64 and Windows on ARM): rewrite ONLY
  the condition nibble GT(0xC) -> AL(0xE) in the little-endian branch word; the
  opcode (0x54), bit4, and the entire `imm19` displacement are preserved.

Never delete or blank a `call`, edit the compared manifest-version value, or
invent control flow. Structurally valid but semantically wrong edits have
previously crashed Chrome or hidden extensions. See `mv2-reversing.md` section
7 before changing the byte strategy.

## Runtime ownership

Keep platform behavior in its owning script:

- Windows/PE logic: `chrome-mv2.ps1`
- Linux/ELF **and** macOS/Mach-O logic: `chrome-mv2.sh` (one cross-platform
  script; the container is dispatched by file magic). The Mach-O path does fat
  parsing, per-slice patching, `LC_UUID` identity, and inside-out ad-hoc
  `codesign` re-seal; the ELF path uses GNU build-id identity and `/proc`-based
  process handling. The whole script must stay bash-3.2 compatible (stock macOS)
  and needs no `python3` on the default path.
- Cross-platform signature derivation only: `scripts/*.py`

The runtime scripts intentionally implement the same safety contract:

- Strictly validate signature data and image bounds.
- Probe the recorded RVA first, then relocate with a masked `.text` scan.
- Mask only the jump opcode and displacement.
- Require each site's exact `expectedMatches` count.
- Choose the best milestone and decline ambiguous or incomplete layouts by
  default. Selection prefers a **full** match (every site satisfied) over any
  partial one, and among full matches the one with the **most sites** (most
  specific) - so Chrome and Chromium tables that share a container tag never
  cross-match. A genuine equal-rank collision (two fulls of the same size)
  declines.
- Treat stock and already-patched opcodes as valid for idempotent reruns.
- Verify prepared and written output.
- Preserve a validated, build-specific stock backup.
- Report structural candidates without modifying an unknown layout.

Do not assume implementation details are interchangeable. PowerShell parses PE,
strips the Authenticode Security directory, and recomputes the PE checksum.
Bash parses ELF or Mach-O, preserves ownership/mode, atomically replaces the
binary, and (macOS only) ad-hoc re-signs the bundle inside-out.

## Signature sources

`signatures.json` is the canonical editable table used by the derivation tools
and external override mode. The patch scripts are also self-contained and carry
platform-specific embedded copies:

- `$EmbeddedSignatures` in `chrome-mv2.ps1` contains the Windows `pe`, `pe32`,
  and `pe-arm64` milestones.
- `EMBEDDED_SIGNATURES` in `chrome-mv2.sh` contains the Linux `elf` and the macOS
  `macho-arm64` milestones together, **pre-tokenized** (pipe-delimited
  records) so the default path needs no `python3`/JSON parser. Each runtime
  script skips milestones whose container it does not own.
- `EMBEDDED_SIGNATURES` in `chrome-mv2.py` (the universal stdlib port) carries a
  full copy of **every** container's milestones. **`sync_embedded.py` does NOT
  manage this one** — regenerate it by hand whenever `signatures.json` changes
  (strip `_comment`, one compact milestone per line), or it silently ships a
  stale table.

Runtime precedence is an explicitly supplied signature file, then a
`signatures.json` beside the script, then the embedded table. A file in the
caller's current directory must not be loaded implicitly.

When adding or changing a milestone, update `signatures.json` and the matching
embedded table in the same change — run `python scripts/sync_embedded.py` (rewrites
the ps1 + sh tables per entry, including removals), and regenerate the
`chrome-mv2.py` copy by hand (the tool does not touch it). A release must not
depend on an external JSON file merely because the embedded copy was forgotten.
Keep older milestones so the scripts can continue probing supported Chrome
versions. `python scripts/sync_embedded.py --check` fails when the two drift, and
`run_tests.py` runs it.

## Derivation toolkit

The tools under `scripts/` fetch stock Chrome artifacts and symbols, derive new
milestones, and verify signature tables. They do not patch installed Chrome.
See [`scripts/README.md`](../scripts/README.md) for the complete workflow.

- `fetch_chrome_binary.py`: fetch and unwrap a stock `chrome.dll` (x64, x86, or
  arm64 `win-arm64` via the enterprise MSI), Linux `chrome`, or the macOS
  universal framework (`mac-arm64`) into `_scratch/`. Requires Python
  and 7-Zip. `--browser chromium` instead fetches an open-source Chromium
  continuous-build snapshot (`--milestone`/`--position`, else trunk `LAST_CHANGE`;
  no Linux-arm64 snapshot exists). Chromium is NOT PGO-built, so its MV2 gate is a
  single shared `manifest_v2_util::IsExtensionAffected` predicate (not Chrome's
  5-7 inlined sites) — derive it as a `<ver>-chromium` milestone (same container
  tag). Snapshots are unstripped, so Linux/mac gates are symbol-named from the
  binary itself.
- `fetch_symbols.py`: fetch the matching PDB (Windows), `chrome.debug` (Linux),
  or stream the official dSYM's symtab (macOS) into `_scratch/`. It verifies the
  symbols against the binary's own build identity and discards a mismatch —
  **Chrome-for-Testing artifacts have no published symbols**, and the Linux
  `debug-info` zip for a given version belongs to the *official* build, so its
  addresses land in unrelated functions on a CfT binary. Prefer an official
  installer/MSI build whenever symbol names matter.
- `symbols_from_pdb.py`: resolve Windows PDB symbols through `dbghelp`. Official
  `win-arm64` PDBs are published (multi-GB; needs recent SDK debugging tools), so
  arm64 gates on Windows *can* be symbol-named.
- `symbols_from_elf.py`: stream Linux `.symtab` data without the cost of `nm -SC`.
- `derive_milestone.py`: find short/near (`jg`) and arm64 `bcond` gate sites,
  emit a milestone (one per Mach-O slice), and verify a table against a stock
  binary. This is the low-level finder; it reports every gate-shaped idiom.
- `port_milestone.py`: **the porting driver — use this, not raw `derive_milestone`.**
  Learns the Extension field offsets from the build, keeps only candidates carrying
  the real gate markers, folds linker-shared bodies into one `expectedMatches=N`
  site, picks the shortest signature that is free of build-specific PC-relative
  immediates, carries site names over from `--prev` and carries forward any prior
  site the finder cannot reproduce (Gate B / `featurebyte`), and can `--merge`/`--sync`.
- `audit_signatures.py`: audit the table for the defects that silently break
  patching — equal-rank ties, fragile signatures, weak anchors, malformed sites —
  and with `--binary` also report which milestone the runtime would select and run
  a completeness pass that does not use the `cmp,2;jg` finder.
- `sync_embedded.py`: rewrite both embedded fallback tables from `signatures.json`,
  replacing/inserting/deleting per entry. `--check` reports drift for CI.

Porting checklist (the scripts do the analysis; do not do it by hand):

1. `python scripts/fetch_chrome_binary.py --platform <p> [--version V]` — the file
   is named after the version the **binary** reports, which is not always the one
   the release feed advertised.
2. Optional but preferred: `python scripts/fetch_symbols.py <binary>`, then
   `symbols_from_pdb.py` / `symbols_from_elf.py`.
3. `python scripts/port_milestone.py <binary> --name <ver> --prev <prev> --moved old:new`
   Read its report: it prints the learned field offsets, every folded body, any
   signature it could not make portable, and which sites still need a name.
4. Name any site it could not carry a name for, then re-run with `--merge --sync`
   (or edit `signatures.json` and run `scripts/sync_embedded.py`).
5. `python scripts/audit_signatures.py --binary <binary>` — require 0 failures.
   Every marker it reports as needing review must be disassembled before anything
   is added; the classifier already accounts for the known non-gate shapes
   (`jne`/`b.ne` equality tests, inverted `b.hs`, branchless `csel`/`cmov`, the
   Extension initializer, and folded second copies).
6. `python scripts/run_tests.py` (it now includes the table audit and the
   embedded-table drift check).
7. Patch only a scratch copy for byte inspection, then perform a platform GUI
   or runtime test before declaring the milestone supported.

Two table-level failure modes are invisible from any single binary, so never skip
step 5 or 6:

- **Equal-rank tie.** Two milestones in one container with identical signature
  sets rank equally, and the runtime declines rather than guess. `152-macos-arm64`
  and `154-macos-arm64` were byte-identical, so every 152/154 macOS-ARM install was
  refused. When a new version's gates are unchanged, extend the existing entry
  instead of adding a duplicate.
- **Build-specific signatures.** A window holding an `adrp`/`adr` or a
  `lea rip+disp` encodes a distance within one image, so the site matches only the
  artifact it was derived from. Two builds of the *same* version differ this way.

Do not hand-patch a live install while deriving signatures. If the
`cmp <mv>,2 ; jg` skeleton disappears, stop and re-analyze Chrome's gate logic
from source before changing bytes.

## Verification

Run the full local suite from the repository root:

```bash
python scripts/run_tests.py
```

The suite (`scripts/run_tests.py`, pure Python) audits `signatures.json` and the
embedded-table sync, then exercises synthetic PE (incl. an
arm64 `pe-arm64` fixture), ELF, and Mach-O (fat) fixtures, parses all three
runtime scripts, and covers patch, restore, check, malformed signatures, partial
layouts, ambiguity, host-aware slice selection (each Mac patches only its own
CPU's slice), backup validation, and race protection. It drives the shell
patchers via `bash` and the PowerShell patcher via `pwsh` (the PE test is
skipped off-Windows). A native-arm64 `windows-11-arm` GitHub runner also
round-trips patch/restore against a real arm64 `chrome.dll`. The real-macOS
runtime proof (patch → ad-hoc re-sign → headless launch → functional MV2 A/B →
restore, on Apple Silicon) runs in GitHub Actions
(`.github/workflows/tests.yml`), since it needs `codesign` and real hardware. The
MV2 A/B (`.github/mv2_probe.py`, a CI helper — not part of the derivation
toolkit) loads a Manifest V2 extension whose persistent background page pings a
local listener the instant it is enabled, and asserts the patched build enables
what the stock build disables. At Chrome 151/152 the MV2 disable is a compiled-in
feature default, so `--enable-features` cannot toggle it and the stock-vs-patched
differential is the only lever; a build that does not enforce the deprecation is
reported as inconclusive, never a false pass.

For focused syntax checks:

```powershell
$tokens = $null; $errors = $null
[Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path .\chrome-mv2.ps1), [ref]$tokens, [ref]$errors) | Out-Null
$errors
```

```bash
bash -n chrome-mv2.sh
```

For a real stock artifact, also run:

```text
python scripts/derive_milestone.py <stock chrome.dll|chrome|Google Chrome Framework> --verify signatures.json
python scripts/audit_signatures.py --binary <that same artifact>
```

The audit is the stronger of the two: `--verify` only asks whether each recorded
site still matches, while the audit also reports which milestone the runtime would
actually select, whether anything ties, and whether a gate exists in the binary
that no site covers.

Use the read-only runtime diagnostics when appropriate:

```powershell
.\chrome-mv2.ps1 check "C:\path\to\chrome.dll" -Quiet
```

```bash
./chrome-mv2.sh check /path/to/chrome --quiet
./chrome-mv2.sh check "/Applications/Google Chrome.app" --quiet
```

Never weaken a decline, backup, identity, bounds, or post-write check merely to
make a new Chrome build pass. A declined unknown layout is the safe and expected
result until its signatures are derived and verified.
