# Agent Workspace Guidelines — Chrome Manifest V2 Patcher

Full rationale, gate layouts, and failed approaches live in
[`mv2-reversing.md`](../mv2-reversing.md); the derivation workflow lives in
[`scripts/README.md`](../scripts/README.md). Read `mv2-reversing.md` before
changing any patching logic. This file is the short operating contract.

## Repository shape

The platform scripts and legacy Windows memory engine share one signature model. Do not
reintroduce the removed Go or Python patchers:

- `chrome-mv2.ps1` — installs the Windows memory DLL; retains the PE buffer engine
  and legacy restore: `pe` (x64), `pe32` (x86), `pe-arm64` (Win-on-ARM).
- `chrome-mv2.sh` — Unix, dispatched by file magic: Linux `elf`/`elf-arm64` and the
  macOS `macho-arm64` framework slice (then ad-hoc re-signs the app). Must stay
  bash-3.2 clean; it fetches `signatures.json` from the URL and tokenizes it with
  `python3`, so `python3` is now required on the default path too. Intel macOS was
  dropped in v1.10.0.
- `scripts/*.py` — derivation/verification only; they never patch an install.
- `mv2-mem-patch-win` — Windows in-process patcher, built with its own `build.bat`.

This branch's Windows DLL (`build.bat` or Visual Studio) uses compact native
discovery on x86, x64 and ARM64 without signature tables. DLLs go in `build/`;
generated files, dependencies and test tools go in ignored `out/`. See
[`mv2-mem-patch-win/AUTOSCAN.md`](../mv2-mem-patch-win/AUTOSCAN.md) for its bounded
proof and runtime contract. Existing installers download the published release.

The patch re-enables MV2 by flipping the `IsExtensionAffected` branch at each
inlined site, using per-milestone, container-tagged tables, applying only a
complete unambiguous match by default. Supported: Chrome **152–159**.

## Cardinal rule

Force the predicate's existing not-affected outcome, after reviewing both paths:

- short `jg`: `7F`→`EB` (disp8 kept); a site may pin any Jcc via `stockOpcode` (the
  InstallVerifier gate flips a `75` `jne`). near `jg`: `0F 8F`→`90 E9` (disp32 kept).
- arm64 `bcond`: rewrite only the condition nibble GT(0xC)→AL(0xE); opcode `0x54`,
  bit4, and `imm19` preserved.
- arm64 `cbz`/`tbz`: a `cbz` (imm19) or test-bit `tbz`/`tbnz` (`0x36`/`0x37`
  family, imm14) → unconditional `B` to the **same resolved target** (imm26 recomputed
  from the sign-extended imm19/imm14). `tbz` is the arm64 InstallVerifier flip; `cbz`
  can also use a 64-bit X register, with register and width pinned.

- Chrome 159 inverted checks: `short-nop` (`7E disp8`) and `near-nop`
  (`0F 8E disp32`) become complete NOP sequences; `bcond-nop` (`B.LE`) becomes
  `1F2003D5`. Each selects the existing not-affected fall-through.
- `csel` accepts only `CSEL Wd,WZR,Wm,GT`; GT→AL selects its existing zero operand.
- Linux ARM64 159 uses a CBZ guard whose existing target skips only the MV2 predicate.

Never delete/blank a `call`, edit the compared manifest-version value, or invent
control flow — structurally valid but semantically wrong edits have crashed Chrome
or hidden extensions. See `mv2-reversing.md` §6 before changing the byte strategy.

## Runtime ownership & safety contract

Keep platform behavior in its owning script (`ps1` = PE strip-Authenticode +
checksum; `sh` = ELF atomic-replace / Mach-O fat parse + inside-out ad-hoc
`codesign`). All table-based engines implement the same contract:

- Validate signature data and image bounds; probe the recorded RVA, then relocate
  with a masked `.text` scan.
- Mask only volatile fields: the jump opcode + displacement; the `bcond`/`cbz`/`tbz`
  word's variable field (`bcond` condition + `imm19`; `cbz` `imm19`, register/width pinned; `tbz`
  `imm14`, family/op/bit-position/Rt pinned); and, for `cbz`, any embedded `BL`/`B`
  (opcode class still checked — its `imm26` is build-specific).
- Require each site's exact `expectedMatches`; select the **best full match** (most
  sites) and **decline** equal-rank ties or partial/unknown layouts.
- Treat stock and already-patched opcodes as valid (idempotent reruns); preserve a
  validated, build-specific backup outside any signed bundle; report candidates
  without modifying an unknown layout.

Never weaken a decline, backup, identity, bounds, or post-write check to make a new
build pass — a declined unknown layout is the safe, expected result.

## Signature sources

`signatures.json` is canonical and the **only** copy. The engines fetch it from
the GitHub raw URL
(`https://github.com/Sketchystan1/chrome-mv2-patch/raw/master/signatures.json`) at
runtime; precedence is an explicit `--signatures`/`-Signatures` path →
`signatures.json` beside the script → the URL. There are **no embedded tables** (the
`$EmbeddedSignatures`/`EMBEDDED_SIGNATURES` blobs and `scripts/sync_embedded.py` were
removed). Publish the table with the matching engine changes so the raw URL and
release DLL stay compatible. Consequences: the default path now needs network, and
`chrome-mv2.sh` now needs `python3` on the default path (to tokenize the fetched
JSON). Keep older milestones so the scripts keep covering supported versions.

## Deriving / porting a milestone

Use the scripts, not hand analysis (`scripts/README.md` has the full workflow):
`fetch_chrome_binary.py` → `fetch_symbols.py` → **`port_milestone.py`** (the driver:
learns field offsets, folds shared bodies, picks the shortest signature free of
build-specific PC-relative immediates, carries site names from `--prev`) →
`audit_signatures.py --binary` → `run_tests.py` → patch a **scratch copy** and
GUI/runtime-test (with a real MV2 extension installed off-store via the non-policy
external-extensions provider — the reason-string trap in §5/§6 is invisible on a
fresh profile).

Two table-level failures are invisible from a single binary — never skip the audit:

- **Equal-rank tie.** Two milestones in one container with identical signature sets
  rank equally and the runtime declines. When a new version's gates are unchanged,
  reuse/extend the existing table instead of adding a duplicate (e.g. Chrome 154 mac
  and linux are covered by the 152/155 tables; adding a `154-*` clone would tie).
  Removing Gate B made `152-` and `153-macos-arm64` identical, so `153-macos-arm64`
  was dropped.
- **Build-specific signatures.** A window holding an `adrp`/`adr`, `lea rip+disp`,
  arm64 `BL`/`B`, or `call/jmp rel32` encodes a distance within one image and matches
  only that build. `audit_signatures.py`'s `pc_relative_spans` flags all of these;
  keep it at 0 hits. (`cbz`/`tbz` sites embed a branch word — the matcher masks the
  volatile field instead; trim the sig to exclude any other PC-relative immediate.)

Chrome 159 tables belong in `milestones_v2`. New readers concatenate both arrays;
older Windows DLLs otherwise mistake unknown instruction kinds for short branches.
Ship `version.dll` 1.16.0 or later with these tables, and the updated Unix script.
The old `jg`/`b.gt` finder cannot author inverted/CSEL sites automatically: review
the source and both outcomes, then verify the complete resolved address set.

If the `cmp <mv>,2 ; jg` skeleton disappears, stop and re-analyze the gate from
source before changing bytes.

## Verification

```bash
python scripts/run_tests.py                 # audits + PE/ELF/Mach-O suites
bash -n chrome-mv2.sh                        # sh syntax
python scripts/derive_milestone.py <stock binary> --verify   # each site still matches
python scripts/audit_signatures.py --binary <stock binary>   # selection + ties + uncovered gates
```

The audit is the stronger check: `--verify` only asks whether recorded sites match,
while `audit --binary` reports which milestone the runtime selects, whether anything
ties, and whether a gate in the binary is covered by nothing. Real-macOS runtime
proof (re-sign → launch → MV2 A/B → restore, Apple Silicon) and native Windows ARM64
browser behavior still need target hardware. `python scripts/test_memory.py --arm64`
runs the legacy table-based engine and patched ARM64 instructions under WSLC with
Wine/QEMU on x64 Windows. The release workflow only builds the Windows DLLs.

Read-only diagnostics: `./chrome-mv2.sh check <path> --quiet` /
`.\chrome-mv2.ps1 check <path> -Quiet`. Do not hand-patch a live install while
deriving signatures.
