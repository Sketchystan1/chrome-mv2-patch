# Agent Workspace Guidelines — Chrome Manifest V2 Patcher

Full rationale, gate layouts, and failed approaches live in
[`mv2-reversing.md`](../mv2-reversing.md); the derivation workflow lives in
[`scripts/README.md`](../scripts/README.md). Read `mv2-reversing.md` before
changing any patching logic. This file is the short operating contract.

## Repository shape

Three self-contained patchers share one signature model; there is **no compiled
patcher or build step** (do not reintroduce the removed Go app / `build.bat`):

- `chrome-mv2.ps1` — Windows PE: `pe` (x64), `pe32` (x86), `pe-arm64` (Win-on-ARM).
- `chrome-mv2.sh` — Unix, dispatched by file magic: Linux `elf`/`elf-arm64` and the
  macOS `macho-arm64` framework slice (then ad-hoc re-signs the app). Must stay
  bash-3.2 clean and need no `python3` on the default path. Intel macOS was dropped
  in v1.10.0.
- `chrome-mv2.py` — stdlib-only universal port (all containers).
- `scripts/*.py` — derivation/verification only; they never patch an install.
- `mv2-mem-patch-{win,mac}` — in-process launchers reusing the same tables.

The patch re-enables MV2 by flipping the `IsExtensionAffected` branch at each
inlined site, using per-milestone, container-tagged tables, applying only a
complete unambiguous match by default. Supported: Chrome **152 / 153 / 154 / 155**.

## Cardinal rule

Only flip the direction of an existing branch to its existing target:

- short `jg`: `7F`→`EB` (disp8 kept); near `jg`: `0F 8F`→`90 E9` (disp32 kept).
- arm64 `bcond`: rewrite only the condition nibble GT(0xC)→AL(0xE); opcode `0x54`,
  bit4, and `imm19` preserved.
- arm64 `cbz` (macOS Gate-B only): `CBZ w0`→unconditional `B` to the **same resolved
  target** (imm26 recomputed from the sign-extended imm19).

Never delete/blank a `call`, edit the compared manifest-version value, or invent
control flow — structurally valid but semantically wrong edits have crashed Chrome
or hidden extensions. See `mv2-reversing.md` §6 before changing the byte strategy.

## Runtime ownership & safety contract

Keep platform behavior in its owning script (`ps1` = PE strip-Authenticode +
checksum; `sh` = ELF atomic-replace / Mach-O fat parse + inside-out ad-hoc
`codesign`). All engines implement the same contract:

- Validate signature data and image bounds; probe the recorded RVA, then relocate
  with a masked `.text` scan.
- Mask only volatile fields: the jump opcode + displacement; the `bcond`/`cbz` word's
  condition + `imm19`; and, for `cbz`, any embedded `BL`/`B` (opcode class still
  checked — its `imm26` is build-specific).
- Require each site's exact `expectedMatches`; select the **best full match** (most
  sites) and **decline** equal-rank ties or partial/unknown layouts.
- Treat stock and already-patched opcodes as valid (idempotent reruns); preserve a
  validated, build-specific backup outside any signed bundle; report candidates
  without modifying an unknown layout.

Never weaken a decline, backup, identity, bounds, or post-write check to make a new
build pass — a declined unknown layout is the safe, expected result.

## Signature sources — keep them in lockstep

`signatures.json` is canonical. Every entry is also embedded in each shipped script:

- `$EmbeddedSignatures` in `chrome-mv2.ps1` — PE milestones only.
- `EMBEDDED_SIGNATURES` in `chrome-mv2.sh` — ELF + Mach-O, pre-tokenized.
- `EMBEDDED_SIGNATURES` in `chrome-mv2.py` — **every** container.

`python scripts/sync_embedded.py` rewrites the **ps1 and sh** tables (adds/updates/
removals; `--check` fails on drift and `run_tests.py` runs it). It does **NOT** touch
the `.py` blob — regenerate that by hand from `signatures.json` (compact, one
milestone per line, `_comment` stripped) or it silently ships stale. Runtime
precedence: an explicitly supplied file → `signatures.json` beside the script →
embedded. Keep older milestones so the scripts keep covering supported versions.

## Deriving / porting a milestone

Use the scripts, not hand analysis (`scripts/README.md` has the full workflow):
`fetch_chrome_binary.py` → `fetch_symbols.py` → **`port_milestone.py`** (the driver:
learns field offsets, folds shared bodies, picks the shortest signature free of
build-specific PC-relative immediates, carries names/Gate-B/`featurebyte` from
`--prev`) → `audit_signatures.py --binary` → `run_tests.py` → patch a **scratch
copy** and GUI/runtime-test (with a real MV2 extension force-installed — the
reason-string trap in §5/§6 is invisible on a fresh profile).

Two table-level failures are invisible from a single binary — never skip the audit:

- **Equal-rank tie.** Two milestones in one container with identical signature sets
  rank equally and the runtime declines. When a new version's gates are unchanged,
  reuse/extend the existing table instead of adding a duplicate (e.g. Chrome 154 mac
  and linux are covered by the 152/155 tables; adding a `154-*` clone would tie).
- **Build-specific signatures.** A window holding an `adrp`/`adr`, `lea rip+disp`,
  arm64 `BL`/`B`, or `call/jmp rel32` encodes a distance within one image and matches
  only that build. `audit_signatures.py`'s `pc_relative_spans` flags all of these;
  keep it at 0 hits. (The macOS Gate-B `cbz` is the one gate that must embed branches
  — it masks them instead, and its frame-slot tail is per-milestone, which is why
  mac has both `152-` and `153-macos-arm64`.)

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
proof (re-sign → launch → MV2 A/B → restore, Apple Silicon) and the arm64 Windows
real-dll round-trip run in GitHub Actions, since they need real hardware.

Read-only diagnostics: `./chrome-mv2.sh check <path> --quiet` /
`.\chrome-mv2.ps1 check <path> -Quiet`. Do not hand-patch a live install while
deriving signatures.
