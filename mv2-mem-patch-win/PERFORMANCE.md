# Windows patcher performance and validation

These records cover the November 14, 2026 performance campaign and November
17–18 compatibility tests. Results belong to the exact browser and patcher
artifacts listed below. Installation and runtime behavior are documented in the
[Windows README](README.md); source and proof details are in the
[reversing notes](../mv2-reversing.md).

`_scratch/` paths refer to retained local, ignored research evidence. Reproduction
commands run from the repository root with matching native test targets and a
fresh, short work directory. Rebuilding creates a new artifact to identify and
validate; it does not inherit the recorded results.

## Startup costs

| Startup state | Work performed |
| --- | --- |
| Valid protected cache | Complete stock-file BLAKE3 identity, cache authentication, loaded-code validation and transactional patching. |
| Cache miss or rejected cache | The same checks, plus isolated helper discovery and a new protected plan. |

The parent locks and maps the stock file read-only. The DPAPI-protected cache
binds browser BLAKE3, scanner SHA-256 and protocol version. Helper discovery has a
30-second deadline. Patch pages transition RX → RW → edit/verify → flush → RX;
failed rollback or protection restoration terminates the browser.

Selected improvements include `/O2`/LTCG, upstream SIMD hashing, adaptive hash
workers with a 16 MiB threshold, bounded shared reference searches, function-trim
reuse, combined allocation/readability validation and process-only initial-thread
capture. Full-file identity, ambiguity rejection, bounds, loader-lock calibration,
loaded-code equality, protection and rollback remain required.

## November 14, 2026: discovery performance

Of the 160-route catalogue's 113 remaining experiments, **107 ran and six were
skipped**: 30 component/design wins and 77 no-gain results. The final campaign
selected the x86 reference filter (61) and contiguous runtime-table reads (65).

| Complete discovery endpoint | Before → after | Paired reduction | Confirmation |
| --- | --- | --- | --- |
| x86 reference filter; unbranded Chrome for Testing 157.0.8103.78 | 2,514.022 → 844.536 ms | 66.37% | 16/16 pairs faster; 34 identical reports. |
| Runtime-table reads; Chrome 157.0.8103.79 x64 | 313.734 → 303.934 ms | 3.40% | 16/16 pairs faster; 34 identical reports. |
| Runtime-table reads; Edge x64 | 281.711 → 260.428 ms | 7.60% | 16/16 pairs faster; 34 identical reports. |

These retained-stock-view `Analyze` measurements affect cache misses. The x86
image is authentic, unmodified and unbranded. The separate improvements cannot be
added together or presented as browser-start gains.

Twelve alternating cached Chrome launches per DLL all succeeded. Medians were
774.239 → 775.125 ms; paired median reduction was 1.14%, with 7/12 faster.
**No cached browser-start improvement was established.** The endpoint was browser
resume to owned DevTools RPC completion. All 234 instruction checks and 78
sandbox-renderer observations passed; all 24 cache hits preserved bytes and mtime.

### Unselected experiments

| Experiment | Decision |
| --- | --- |
| 4/8 MiB hash thresholds | Browser confirmation gave paired -1.23% / -0.30%, 6/12 faster each. Keep 16 MiB. |
| Atom compiler tuning | Initial 8.43% screening gain fell to 2.16%, 7/12 faster. Compiler flags stay unchanged. |
| Instrumented PGO and function ordering | No consistent browser gain; optimized PGO populations had worse tails or mixed pairs. |
| Fused hashing/code comparison | Repaired prototype passed safety checks but lost against current assembly by paired 4.96% on Chrome and 22.04% on Edge. |
| Combined discovery routes 65/60/130 | Slower than route 65 alone. |
| Acquire-state proxy read | Browser reduction was 9.16%, only 4/6 pairs faster; kernel savings do not establish startup attribution. |
| Persistent disk patch | Isolated startup gain was 25.13%, 6/6 faster; signature/update/restore requirements differ from the deployed memory patcher. |
| Broker/helper protocol redesigns | Corrected prototypes passed 397 authentication, header, EOF and deadline checks; architecture changes remain experimental. |

Six unavailable hardware/privilege routes were skipped: AVX2, AVX-512, native
Windows ARM64, two multi-node NUMA routes and privileged SPGO sampling.

### Validation and artifact identities

The recorded DLL passed stock, patched, cached restart, empty-cache restart and
removal with packed MV2 request blocking and MV3 controls: **45 instruction checks
and 39 renderer checks**. Stock files stayed unchanged; isolated proxy and private
registry state were restored. Native CTest passed **20/20 x64 and 17/17 x86**;
ARM64 cross-built. Confirmation also passed 943,106 reference/alignment/collision
assertions and 85,248 adversarial runtime-table/unwind/stride comparisons.

The earlier reviewed scanner matrix reproduced 166 core decisions across 21 x64
and two x86 images, 23 InstallVerifier gates and 20 CRX download gates; two ARM64
analysis reports matched. Edge 157.0.4341.46 x64 passed signed CRX3 installation,
enablement, restart and removal, with tampered packages and missing developer
proofs rejected. Shared store detection stayed unchanged. Ordinary Chrome/Edge
window startup passed on a private desktop without a timed performance endpoint.

Earlier failures included a 30-second patch-verification timeout, a WebSocket
observer timeout and failed PGO training whose cause cleanup masked. Initial
broker/helper and fused-comparison failures were repaired and retained. Later
passes do not explain the unresolved failures. This campaign did not validate
native x86/ARM64 browser behavior, browser updates or DRM.

| November 14 deployment artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| x64 `secur32.dll` | 243,200 | `3e5238381af1280bdce4fdfb31d85f9e45ac7535eecea21468cbf90c25366898` |
| x86 `secur32.dll` | 245,760 | `15f6d0cf296e15350081839e433a524d0c190993bce6cfd70d7d15c078c37ddd` |
| ARM64 `secur32.dll` | 172,544 | `b97d23862dc688e3a94bd3fb905cea381a05da00a32914023963a4974c9ef01a` |

### Evidence

Commit `7f803bfd2900907f24b427c614067988ba91ce02` preserves the complete report,
route catalogue and execution ledger:

```sh
git show 7f803bf:mv2-mem-patch-win/PERFORMANCE.md
```

Sources, raw results, failed populations and logs are retained in
`_scratch/performance-evidence-2026-11-14.zip`. `ARCHIVE.json` lists hashes and
omitted temporary content. Key records are `outcomes.json`, `final-summary.json`,
`final-selected/results.json`, `discovery/confirm61/results.json`,
`discovery/confirm65/results.json`, `final-checks/` and
`_scratch/all-experiments-life/results.json`. Copied browsers, profiles, duplicate
dependencies and regenerable intermediates were removed.

## November 17, 2026: x86 regressions

### Canary 160.0.8167.0: helper startup and off-store enablement

The rebuilt 2.0.0 x86 DLL passed an isolated lifecycle with branded Canary
**160.0.8167.0**. The old helper could overflow `rundll32`'s 256 KiB stack before
returning a plan. Analysis now uses a joined worker with a 1 MiB stack reserve.
Recognition also handles a verified provider-argument reload before the off-store
flag check, preserving Canary's diagnostic calls and high-byte operations.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Stock Canary x86 `chrome.dll` | 272,000,664 | `496b63e201072bd4dccfe185dfd0ff50fbf0eb1f8c7c95b05109aa0c05472201` |
| Tested x86 `secur32.dll` | 247,296 | `8236f3f34596d012215242b51a30b1df2d43c3f888c5d36f9a598bd24421562d` |

Packed external MV2 enablement, background execution, request blocking,
disable/re-enable, cached and empty-cache restarts, MV3 controls and removal
passed. All **40 instruction checks and 39 renderer sandbox checks** passed;
stock DLL hashes stayed unchanged and private registry cleanup completed. The
scanner found seven core decisions and InstallVerifier; CRX download recognition
was absent, so downloaded-CRX installation was not validated.

Stock disassembly binds the off-store branch at RVA `0x2f0953e` to its verified
target `0x2f0958c`; the other path stores `DISABLE_NOT_VERIFIED` (`0x100`) at
`0x2f09581`. The extension reload from `[ebp+8]` precedes the flag test, while
`SETNE BH` and `TEST BL,BH` retain their diagnostic behavior.

Native CTest passed **18/18 x86 and 20/20 x64**, including real x86 `rundll32`
cold/cached helper checks and unsafe provider-reload rejection. ARM64 cross-built.
The full Capstone/Z3 fixture and installer run passed on repeat; its first
attempt failed an installer process-identity check.

Evidence: `_scratch/x86-160-recheck/results.json`, per-phase reports and
`_scratch/x86-160-recheck.log`. Earlier failed attempts remain in
`_scratch/x86-old/`, `_scratch/x86-thread/` and `_scratch/x86-160-final/`.
Fixture logs are `_scratch/canary160-fixture-tests.log` and
`_scratch/canary160-fixture-recheck.log`; the ARM64 build log is
`_scratch/canary160-arm64-build.log`.

```text
python scripts/test_autoscan_runtime.py _scratch/canary160-x86-runtime-matrix.json --arch x86 --work _scratch/x86-160-new
```

### Canary 160.0.8166.2: signed CRX installation

The corrected 2.0.0 x86 DLL passed signed off-store CRX3 installation on branded
Canary **160.0.8166.2**. Stock Chrome rejected the same package with
`CRX_REQUIRED_PROOF_MISSING`. Recognition added the bounded framed constant-zero
external verifier and a security-cookie terminal trap at its trimmed boundary.
The [reversing notes](../mv2-reversing.md#5-off-store-extensions-and-downloaded-crx-files)
record the source/branch review; verifier calls and user confirmation remain.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Stock Canary x86 `chrome.dll` | 272,436,376 | `87ef34817cfcb2c6fb3443aa94621b0f980102ae81a256c6666db297d4e148ba` |
| Tested x86 `secur32.dll` | 247,808 | `641c0089f9c6ac67c190ceea6380c06f609389355d864bb4d74a7ec5de709cb4` |
| Local `mv2-patch-2.0.0-canary160-crx-fix-win-x86.zip` | 114,932 | `486274bf032c031d7007661507084e97c88e3b4bd1a49d51d8bd68ab41cd4e29` |

The seven-phase Downloads/native-confirmation run passed signed installation,
MV2 enablement/request blocking, disable/re-enable, MV3 controls, cached and
empty-cache restarts, and removal restoring both restrictions. Tampering produced
`CRX_SIGNATURE_VERIFICATION_FAILED`; removing developer proofs produced
`CRX_REQUIRED_PROOF_MISSING`. Neither control installed. Seven core and two
optional decisions yielded **63 instruction checks and 59 renderer sandbox
checks**. Both browser executable/DLL hashes stayed unchanged; registry cleanup
completed. The ZIP contains only the batch installer and tested DLL; the earlier
`mv2-patch-2.0.0-canary160-fix-win-x86.zip` lacks this CRX fix.

Native CTest passed **18/18 x86 and 20/20 x64**, including framed-verifier,
terminal-trap and conflicting-cleanup fixtures. ARM64 cross-built. The complete
Capstone/Z3 portable and installer suite, including both CDP syntax checks, passed.

An earlier `_scratch/crx160full/` attempt retained stock bytes at empty-cache
startup and captured no patcher trace; its cause remains unknown. Two subsequent
full runs passed, as did five consecutive empty-cache restarts with all nine
decisions, MV2/MV3 controls, unchanged hashes and registry cleanup.

Evidence: `_scratch/crx160final/results.json`, per-phase logs,
`_scratch/crx160final.log`, `_scratch/canary160-crx-package.json`,
`_scratch/canary160-crx-final-native-x86.log` and
`_scratch/canary160-crx-final-fixtures.log`. Other successful results remain in
`_scratch/crx160q/`, `_scratch/mv28166/results.json`,
`_scratch/crx160cold/results.json` and `_scratch/crx160cold.log`.

```text
python scripts/test_autoscan_crx.py _scratch/canary160-8166-runtime-matrix.json --arch x86 --work _scratch/crx160-new
```

## November 18, 2026: Stable and Canary architecture matrix

This matrix tested 2.0.0 at commit `183a1af`, **before the Stable x86 CRX discovery
fix below**, against consumer Stable **158.0.8127.37** and Canary
**160.0.8168.0** in x64, x86 and ARM64. PE machine, file version and complete
identities were checked. Stable ARM64 came from Google's enterprise MSI; the
other five artifacts came from versioned consumer installers.

All six read-only reports were ready, with no error or unresolved candidate.
Independent address baselines were not authored for these new images; readiness
is supported by the existing source predicate and native fixtures, and does not
prove complete enforcement coverage.

| Channel/version | Architecture | Core + optional decisions | Browser verification |
| --- | --- | --- | --- |
| Stable 158.0.8127.37 | x64 | 7 + 2 | Signed CRX3 and MV2 lifecycle passed. |
| Stable 158.0.8127.37 | x86 | 8 + 1 | External MV2 lifecycle passed on rerun; CRX download check unrecognized. |
| Stable 158.0.8127.37 | ARM64 | 7 + 2 | Scanner/fixture evidence only. |
| Canary 160.0.8168.0 | x64 | 7 + 2 | Signed CRX3 and MV2 lifecycle passed on rerun. |
| Canary 160.0.8168.0 | x86 | 7 + 2 | Signed CRX3 and MV2 lifecycle passed. |
| Canary 160.0.8168.0 | ARM64 | 7 + 2 | Scanner/fixture evidence only. |

ARM64 analysis used the historical x64-built `out/x64/arm64-scan.exe` from commit
`aba8082`, plus ARM64 module/optional fixtures in x64 CTest. The ARM64 deployment
DLL cross-built; no native ARM64 browser ran.

Three seven-phase CRX runs and one five-phase Stable x86 external-extension run
passed **26 browser phases, 234 instruction-memory checks and 218 renderer
sandbox checks**. They covered stock rejection, MV2 execution/request blocking,
MV3 controls, cached/empty-cache restarts and removal. CRX runs also covered
Downloads/native confirmation and tampered-signature/missing-proof rejection.
Both browser executable/DLL hashes stayed unchanged and private registry cleanup
completed. Stable x86 downloaded-CRX installation was not validated in this matrix.

Initial concurrent cached restarts failed on Stable x86 and Canary x64. Stable
x86's launcher returned 1, with cleanup masking the primary exception. Canary
x64 retained stock `0F 8E 7E 04 00 00` at RVA `0x154d5e4` instead of six NOPs,
then returned 1. Sequential full reruns with debugger capture passed using the
same hashes. **The causes remain unresolved; reruns do not establish reliability.**

Native CTest passed **20/20 x64 and 18/18 x86**. Portable readers, scanner
fixtures, Capstone/Z3 research checks, Mach-O self-tests and both CDP syntax checks
passed. The first combined run failed installer process identification after
force-closing a test browser; the isolated complete installer rerun passed.

| Stock `chrome.dll` | SHA-256 |
| --- | --- |
| Stable x64 | `4ac0b0fe3bf1998dd403ac09b1f2bd5295e91d28c7ed55d534b4732565d8ac63` |
| Stable x86 | `becbf5d2e36bd480736502489284d39955a44ae86aae7ba0e8e1cac0c0311baa` |
| Stable ARM64 | `b31377053940c78b29c3a6d9d73abd94b0fe2665f9f7488e369421c62e4a4e50` |
| Canary x64 | `9d5bca6961cb3465968895e37dacd6bb037b7124980d2d8c77ff4060f796a1c8` |
| Canary x86 | `bda93cb38cfc17a0df1012cea757cd0baa157258aa2d1820faa941a56d021db3` |
| Canary ARM64 | `345d1b7010acb5ae2bcb38bcb8d49a443867f7e5235d7e737b251ca5753d5354` |

| Tested 2.0.0 DLL | Bytes | SHA-256 |
| --- | ---: | --- |
| x64 `secur32.dll` | 242,176 | `0d0fe98e918541096d2fa15748b436ca24901a3b21cf9b7498ecd24506468c2c` |
| x86 `secur32.dll` | 247,808 | `641c0089f9c6ac67c190ceea6380c06f609389355d864bb4d74a7ec5de709cb4` |
| ARM64 `secur32.dll` | 172,544 | `c216f39bfc9778b19794b82bcef406018525af8ce12d02535cc5711406a3cb94` |

The matrix, source URLs, reports, executable hashes and failures are retained in
`_scratch/m6-1118/results.json` and `_scratch/m6-1118/browser-trace.log`.
Successful raw browser results are:

- Stable x64: `_scratch/m6s64i/results.json`.
- Stable x86: `_scratch/m6s32r2/158.0.8127.37/results.json`.
- Canary x64: `_scratch/m6c64i2/results.json`.
- Canary x86: `_scratch/m6c32i/results.json`.

Initial failures remain in `_scratch/m6s32r/` and `_scratch/m6c64i/`; native and
fixture logs use the `_scratch/m6-` prefix. Runtime commands:

```text
python scripts/test_autoscan_crx.py _scratch/m6-1118/stable-x64-runtime.json --arch x64 --work _scratch/m6-new-s64
python scripts/test_autoscan_runtime.py _scratch/m6-1118/stable-x86-runtime.json --arch x86 --work _scratch/m6-new-s32
python scripts/test_autoscan_crx.py _scratch/m6-1118/canary-x64-runtime.json --arch x64 --work _scratch/m6-new-c64
python scripts/test_autoscan_crx.py _scratch/m6-1118/canary-x86-runtime.json --arch x86 --work _scratch/m6-new-c32
```

## November 18, 2026: Chrome 158 x86 CRX discovery fix

The corrected x86 plan for Stable **158.0.8127.37** adds the reviewed CRX download
branch: **eight core decisions plus InstallVerifier and CRX download**. The caller
uses register `SHL`/`SUB`/`SAR` and a helper with 2,327 reachable instructions.
Recognition now models those register overwrites conservatively and walks every
returning helper path within a 4,096-node budget. Stack-derived arithmetic,
conflicting cleanup, overlapping writes and exhausted bounds still decline. See
the [source/proof review](../mv2-reversing.md#5-off-store-extensions-and-downloaded-crx-files).

New fixtures reproduced the old arithmetic/helper-budget failures before the
implementation changed. Native CTest passed **18/18 x86 and 20/20 x64**, including
larger-callee, cleanup-conflict, budget-exhaustion, stack-pointer, memory-operation
and stack-alias rejection checks. ARM64 cross-built. Six architecture regression
reports preserved every earlier decision and patch, adding only the reviewed
Stable x86 CRX branch. These earlier scanner reports are regression input, not an
independent core-address baseline. ARM64 analysis ran on x64. Portable Capstone/Z3,
Mach-O and CDP checks passed with `--fast`; the unchanged installer suite had
already passed its isolated run.

All three x86 browser copies passed seven-phase Downloads/native-confirmation
runs with the identical corrected DLL:

| Browser | Decisions | Instruction-memory checks | Renderer sandbox checks |
| --- | ---: | ---: | ---: |
| Stable 158.0.8127.37 x86 | 10 | 70 | 58 |
| Canary 160.0.8168.0 x86 | 9 | 63 | 59 |
| Canary 160.0.8166.2 x86 | 9 | 63 | 59 |

Together they passed **21 browser phases, 196 instruction-memory checks and 176
renderer sandbox checks**. Stock signed packages reproduced
`CRX_REQUIRED_PROOF_MISSING`; patched packages installed and MV2 enabled/blocked
requests. Tampered signatures and missing developer proofs stayed rejected.
MV3 controls, both restart types, removal and private registry cleanup passed.
Both source and copied browser executable/DLL hashes stayed unchanged. No new
startup failure occurred; the earlier intermittent failures remain unexplained.

The stock browser hashes are listed in the preceding matrix and November 17 CRX
record. Tested artifacts:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| x86 `secur32.dll` | 248,320 | `1caedd09e13bb8297a6b243d83f62beea301dd4090d3c21ee8417bb6a214cb9c` |
| Local x86 fix ZIP | 111,921 | `1697c5e9475baf7192135f80bda233cfa699067fc0fe5457354be638d3f8b931` |

The ZIP is `_scratch/x86-gate/mv2-patch-2.0.0-chrome158-x86-fix.zip`, containing
only `install.bat` and the tested DLL; its archived hash matches all three runs.
Evidence: `_scratch/x86-gate/results.json`,
`_scratch/x86-gate/reviewed-crx.json`,
`_scratch/x86-gate/scanner-regression.json` and
`_scratch/x86-gate/browser-trace.log`. Raw browser results are
`_scratch/g158crx/results.json`, `_scratch/g160crx/results.json` and
`_scratch/g166crx/results.json`.

```text
python scripts/test_autoscan_crx.py _scratch/m6-1118/stable-x86-runtime.json --arch x86 --work _scratch/g158-new
```

## November 18, 2026: x86 Stable, Beta, Dev and Canary

The working-tree 2.0.0 x86 build, based on `183a1af` with the Chrome 158 CRX
discovery fix above, passed the full seven-phase signed CRX/MV2 lifecycle on
all four current consumer channels. Google Update selected the versions below;
updater installer hashes, complete browser hashes, PE machine `0x14c` and binary
file versions were verified before testing. Stable and Canary reused matching
stock artifacts; Beta and Dev were downloaded and extracted into `_scratch/`.

| Channel | Version | Core + optional decisions | Browser phases | Instruction-memory checks | Renderer sandbox checks |
| --- | --- | ---: | ---: | ---: | ---: |
| Stable (Release) | 158.0.8127.37 | 8 + 2 | 7/7 | 70 | 59 |
| Beta | 159.0.8154.6 | 7 + 2 | 7/7 | 63 | 59 |
| Dev | 160.0.8157.0 | 7 + 2 | 7/7 | 63 | 61 |
| Canary | 160.0.8168.0 | 7 + 2 | 7/7 | 63 | 59 |

The additional Stable site was subsequently confirmed by independent source and
disassembly review: its policy-refresh caller contains an inlined MV2 predicate,
while the other three builds call an already recognized predicate. See the
[source and branch-outcome review](../mv2-reversing.md#1-the-source-predicate).
Evidence is `_scratch/x86-4ch/core-review/review.json`, `review.md`, the stock
disassemblies and `policy-call-comparison.json`; no PDB symbols were used.

Together these runs passed **28/28 browser phases, 259 instruction-memory checks
and 238 renderer sandbox checks**. Stock Chrome rejected the signed package with
`CRX_REQUIRED_PROOF_MISSING`; the patched browser installed it through Downloads
and native **Add extension** confirmation. MV2 enabled and blocked requests.
Tampered packages retained `CRX_SIGNATURE_VERIFICATION_FAILED`, and missing
developer proofs retained `CRX_REQUIRED_PROOF_MISSING`; neither control installed.
MV3 controls, cache reuse, empty-cache restarts, removal and private registry
cleanup passed. Source and copied `chrome.exe`/`chrome.dll` hashes stayed unchanged.

Native Release CTest passed **18/18 x86 tests**, including the real small-stack
`rundll32` helper. All browser runs were sequential and completed with clean child
process shutdown; no new startup failure occurred. The earlier intermittent
concurrent-startup failures remain unexplained. These are runtime checks of
recognized plans; independent core-address baselines were not evaluated.

| Stock x86 browser DLL | SHA-256 |
| --- | --- |
| Stable 158.0.8127.37 | `becbf5d2e36bd480736502489284d39955a44ae86aae7ba0e8e1cac0c0311baa` |
| Beta 159.0.8154.6 | `69fe764346b3c1f5a472b4fc6d1f43e6128a7d30b91fa6ccd64357beb18d8ce9` |
| Dev 160.0.8157.0 | `25ed9124deeadd60f2a92fb3d6b975906d6da8db463b0e85c028faa88d2ad2ed` |
| Canary 160.0.8168.0 | `bda93cb38cfc17a0df1012cea757cd0baa157258aa2d1820faa941a56d021db3` |

| Tested artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| x86 `secur32.dll` | 248,320 | `1caedd09e13bb8297a6b243d83f62beea301dd4090d3c21ee8417bb6a214cb9c` |
| x86 `mv2-scan.exe` | 219,648 | `2faf8c6f36e23329961bb7b8ac056aaab9e355c5ce745c57ecce643ea9dc675c` |

Evidence: `_scratch/x86-4ch/results.json`, `_scratch/x86-4ch/results.md`,
`_scratch/x86-4ch/native-x86.log`, updater responses, artifact manifests and
per-channel CRX logs. Raw browser results and scanner reports are in
`_scratch/x4s/`, `_scratch/x4b/`, `_scratch/x4d/` and `_scratch/x4c/`.
The tested DLL and scanner are preserved in `_scratch/x86-4ch/patcher/`.

Reproduce with matching x86 test helpers and fresh short work paths:

```text
python scripts/test_autoscan_crx.py _scratch/x86-4ch/stable-x86-runtime.json --arch x86 --dll _scratch/x86-4ch/patcher/secur32.dll --work _scratch/x4s-new
python scripts/test_autoscan_crx.py _scratch/x86-4ch/beta-x86-runtime.json --arch x86 --dll _scratch/x86-4ch/patcher/secur32.dll --work _scratch/x4b-new
python scripts/test_autoscan_crx.py _scratch/x86-4ch/dev-x86-runtime.json --arch x86 --dll _scratch/x86-4ch/patcher/secur32.dll --work _scratch/x4d-new
python scripts/test_autoscan_crx.py _scratch/x86-4ch/canary-x86-runtime.json --arch x86 --dll _scratch/x86-4ch/patcher/secur32.dll --work _scratch/x4c-new
```

## Remaining limits

`complete_enforcement_coverage_proven` remains **false**. New compiler layouts,
missing function bounds or unsupported instructions can escape recognition.
Native ARM64 browser behavior, browser updates, broader interactive browsing and
DRM remain unvalidated. Performance timings use one host, warm files and
headless/GPU-disabled browsers; controlled cold-disk and desktop-window
performance were not measured. A new scanner identity refills its cache on first
use.
