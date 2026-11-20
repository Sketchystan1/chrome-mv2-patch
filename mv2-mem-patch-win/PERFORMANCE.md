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

## Installer drive search (November 18, 2026)

The optional installer search scans ready fixed, removable and RAM drives in
parallel. NTFS reads MFT records and resolves paths only for exact `chrome.exe`
or `msedge.exe` matches. Unsupported or unavailable metadata uses one directory
traversal, excluding reparse points.

The disposable benchmark used 500 folders and 20,002 files, including one Chrome
and one Edge executable. Results are medians of three warm runs after one warmup
on this Windows host; fixture creation and PowerShell/C# startup are excluded.

| Operation | Median time |
| --- | ---: |
| Installer directory fallback | 135.5 ms |
| Native `where /r` with both filenames | 1,195.5 ms |
| PowerShell recursive file enumeration with name filtering | 1,986.9 ms |
| Filter 100,000 synthetic USN records | 14.7 ms |

The fallback was about 8.8 times faster than `where /r` on this fixture.
An elevated full-volume NTFS scan and cold-disk timings remain unmeasured.
The embedded search C# (UTF-8, LF, excluding the PowerShell here-string markers)
has SHA-256 `8e4f23a5b3625316bd92fb673254ae5d91b3c8b54188d3ba13b32985d2f60141`.
Reproduce the fixture timings with `python _scratch/install-search-bench.py`.

`python scripts/test_install.py` passed, covering record bounds and versions, native
file-ID/path lookup, case-insensitive names, parallel folder roots, Unicode
paths, junction cycles, repeated menu searches, quiet selection and empty
results, plus staged install and uninstall in a CJK path, using isolated browser
fixtures. DLL marker detection also passed against the built x64, x86 and ARM64
DLLs.

## November 19, 2026: native Windows ARM64 CI

The testing branch at commit `438cba4` added a six-channel Windows ARM64 matrix.
[GitHub Actions run 44507649748](https://github.com/Sketchystan1/chrome-mv2-patch/actions/runs/44507649748)
built on `windows-11-arm` and passed **17/17 native CTest tests** in 2.72 seconds.
The browser jobs downloaded complete consumer packages, verified their vendor
installer sizes and SHA-256 hashes, and checked both executable/DLL PE machines
and file versions before testing isolated copies.

| Browser/channel | Version | Core + optional decisions | Browser result |
| --- | --- | --- | --- |
| Chrome Stable ARM64 | 158.0.8127.37 | 7 + 2 | 7/7 CRX/MV2 phases passed. |
| Chrome Beta ARM64 | 159.0.8154.13 | 7 + 2 | 7/7 CRX/MV2 phases passed. |
| Chrome Canary ARM64 | 160.0.8171.0 | 7 + 2 | 7/7 CRX/MV2 phases passed. |
| Edge Stable ARM64 | 157.0.4341.60 | Declined | No browser launch. |
| Edge Beta ARM64 | 158.0.4370.26 | Declined | No browser launch. |
| Edge Canary ARM64 | 160.0.4412.0 | Declined | No browser launch. |

Chrome passed **21/21 browser phases, 189 instruction-memory checks and 176
renderer sandbox checks** with the identical 172,544-byte ARM64 DLL. Phases were
stock rejection, signed CRX installation/native confirmation, tampered-signature
rejection, missing-developer-proof rejection, cached restart, empty-cache restart
and removal. The runs also exercised MV2 enable/disable and request blocking,
MV3 controls, private registry cleanup and unchanged source/copied browser files.

All three Edge scans failed with `Edge installer recognition requires x64`.
Those jobs and the overall workflow correctly remained failures. No ARM64 Edge
runtime support or complete enforcement coverage is claimed. The corrected
upstream Detours source is used only by ARM64 browser-test helpers; the deployed
DLL's existing import enumerator and discovery/patch semantics were unchanged.

| Artifact | SHA-256 |
| --- | --- |
| Tested ARM64 `secur32.dll` | `b6ab6baed07fbb496235e5d1d894aa9d3c9e330b744b67f090286b5450359451` |
| Chrome Stable ARM64 `chrome.dll` | `b31377053940c78b29c3a6d9d73abd94b0fe2665f9f7488e369421c62e4a4e50` |
| Chrome Beta ARM64 `chrome.dll` | `a2c98cc95856c1660946ec8240d8aaefdec438ef95583b7624568b0904b12465` |
| Chrome Canary ARM64 `chrome.dll` | `6df68f641fba28df848c115fb68c59cf81502bd23d5399664cabe4f2b4a35024` |
| Edge Stable ARM64 `msedge.dll` | `6184594b61aa86a00074ada46c2fe2e2542188b773bacecaa43f4804c709c2a9` |
| Edge Beta ARM64 `msedge.dll` | `2a42b64d1b49083d99a2ba6375d2890e35f403c08e144511f93e206daa4b4105` |
| Edge Canary ARM64 `msedge.dll` | `7172a1dc343ffc7f22066f7b8d9cb70bac069dc6a7b9b2d0bd2f0516dfd79a2e` |

Each browser's Actions artifact contains `browser/source.json`,
`browser/matrix.json` and `scan.json`; Chrome artifacts also contain the CRX
phase results and logs. The native binaries are in `arm64-test-binaries`.
Evidence is downloaded locally beneath `_scratch/ci-run-44507649748/`.

```text
gh run view 44507649748 --log
gh run download 44507649748 --dir _scratch/ci-run-44507649748
```

Pushes to `master` test Stable against the then-current vendor release. Manual
dispatch can select a browser and channel; `browser=edge, channel=stable` reruns
Edge Stable alone. New versions require fresh validation.

## November 20, 2026: DLL-only validation attempt

The requested matrix is Chrome and Edge Stable (release), Beta and Canary on
local x64/x86 and remote native ARM64, with `secur32.dll` alone. Work started
from primary branch `master` at `62f0c62`; no production launcher or alternate
proxy was added. The ARM64 provider-result fix selects the already verified
fall-through for `TBZ` instead of always generating a branch. The new fixture
failed on the old scanner and passed after the one-line correction. The CRX
harness now rejects a `--dll` basename other than `secur32.dll` before creating
its workspace, matching the external-extension harness.

These are cached stock discovery results, not current-channel or runtime passes:

| Browser/architecture | Stable | Beta | Canary |
| --- | --- | --- | --- |
| Chrome x64 | 158.0.8127.37: ready | Stock unavailable | 160.0.8168.0: ready |
| Chrome x86 | 158.0.8127.37: ready | 159.0.8154.6: ready | 160.0.8168.0: ready |
| Chrome ARM64 | 158.0.8127.37: ready | Stock unavailable | 160.0.8171.0: ready |
| Edge x64 | 157.0.4341.60: ready | 158.0.4370.26: ready | 160.0.4412.0: ready |
| Edge x86 | 157.0.4341.60: ready | 158.0.4370.26: ready | 160.0.4412.0: ready |
| Edge ARM64 | 157.0.4341.60: ready | 158.0.4370.26: ready | 160.0.4412.0: ready |

All 16 available requested combinations passed discovery and stock PE/version
checks. A separate read-only scan of installed Chrome Canary 160.0.8172.0 x64
also passed. ARM64 analysis ran in the x64 diagnostic executable, not on ARM64
Windows. ARM64 Edge's source patches are now `1F2003D5` (`NOP`). Current vendor
metadata could not be queried, so channel freshness remains unverified.

The Release DLL built for all three architectures. Full local CTest passed
19/20 x64 and 17/18 x86; the failing cache tests reproduce a sandboxed
`CryptProtectData` error 2 on synthetic data. After the correction, ARM64
analysis/optional fixtures passed 222/86 checks on x64, and x86 optional fixtures
passed 225 checks. Portable image/fetch/runner tests and CRX CDP syntax passed;
the CRX CLI rejected `version.dll` with exit 2 before filesystem changes.

Both local Chrome Stable lifecycle attempts stopped at the required private
HKCU registry creation with `WinError 5`, before any browser phase. No isolation,
cache authentication or sandbox assertion was removed. Latest-browser downloads
and unsandboxed reruns were not executed because automatic approval review
returned an internal `content-blocked` router error, explicitly a review failure
rather than an unsafe-action determination. No fresh remote workflow was
dispatched. The requested 18-case runtime matrix remains incomplete.

Earlier Edge CI at `62f0c62` failed its patched-memory checks; the wrong ARM64
branch can explain application rejection. Successful Edge CI at `0e839f2`
injected `secur32.dll` using a deployed launcher and is excluded from DLL-only
validation. Its GitHub Actions run was deleted when cleaning results from the
retired `tests` branch. A prior stock Edge Canary x64 startup module capture had no
`secur32.dll` loaded; executable/ELF imports across all three architectures
contain no eager `secur32.dll` import, while `msedge.dll` delay-imports it.
Fresh dropped-DLL runtime/module checks are still needed to determine whether
the tested Edge startup path loads the proxy before its installer decisions;
the later SxS Canary checks are recorded below.

| Built artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| x64 `secur32.dll` | 244,224 | `81b68a49776d2b95522ce77067f5b0388f5a38d6ead22d28f058f3e106440660` |
| x86 `secur32.dll` | 260,096 | `60ae4d95f637fa02a1480e4839feb009dbc5a7be34831f23a31e0b01d326d753` |
| ARM64 `secur32.dll` | 178,176 | `4fd80cb54b58943ea0931b5dd7fab80633a62eee34bca014cd34c82d4d785700` |

Evidence: `_scratch/t19-x64-scan/results.json`,
`_scratch/t19-x86-evidence/results.json`,
`_scratch/t19-arm64/cached-scanner-results.json`, per-case scan reports,
`_scratch/t19-arm64-regression-red.log`,
`_scratch/t19-arm64-final-fixtures.log`, `_scratch/t19-x64-native.log`,
`_scratch/t19-x86-native.log`, `_scratch/t64cs1.log` and
`_scratch/t19-x86-chrome-stable-crx.log`. Structured reports contain exact browser
hashes and input paths; readiness is not an independent address baseline.

## November 20, 2026: ARM64 Canary AST exclusion

Access was restored after the initial sandbox failures. The cache tests then
passed, and the local native totals became 20/20 x64 and 18/18 x86. The isolated
CRX harness now waits up to 75 seconds only while decision bytes remain exactly
stock; unexpected bytes and failed/partial reads still fail immediately. Failed
phases retain their original error if UI inspection fails, and final module
diagnostics refresh the loaded security-DLL paths. Seven synthetic Windows memory
tests passed. Edge packing and launch use its compatibility-relaunch skip flag
to keep the original isolated process and synchronous packing results.

Initial native ARM64 [run 44616524962](https://github.com/Sketchystan1/chrome-mv2-patch/actions/runs/44616524962)
at `863fe3a` passed 17/17 native tests. Chrome Stable/Beta and Edge Stable passed
all seven browser phases each. Chrome Canary 160.0.8172.0 declined discovery;
Edge Beta 159.0.4402.7 and Canary 160.0.4413.0 failed patched-memory checks.
The initial local x64/x86 runs likewise passed all Chrome channels and Edge
Stable, while Edge Beta/Canary loaded only Windows security DLLs. Final rebuilt
artifact validation is recorded below when completed.

The rejected Canary DLL is SHA-256
`f13be3049d78329a540319bfac402c48c40d76e4718b44f9215eb00cc2eeed94`.
Its comparison at RVA `0x3a60938` belongs to V8 AST literal dispatch in a
163,616-byte function, not MV2 enforcement. The source-bound proof is in
`_scratch/t20-arm64-canary-source-proof.json` and the reversing notes. Generic
extraction filtering was rejected during two independent read-only reviews:
it could silently omit a genuine, unsupported predicate.

The narrower source-family exclusion keeps the 64 KiB program and other proof
budgets unchanged. It validates the literal origin/guard, the read-only switch
and its preserving loop, every backed executable section including raw padding,
and the absence of executable/table/metadata relocations. Failed proofs retain
the unresolved candidate. The exact stock DLL now produces a ready nine-decision
plan with no unresolved candidate. A warm read-only x64-host ARM64 CLI run took
7.418 seconds while another isolated browser test was running; this is not a
controlled performance benchmark or native ARM64 runtime evidence.

Final local Release builds passed 20/20 x64 and 18/18 x86 native tests. ARM64
analysis fixtures passed 222 module and 134 optional checks on x64. The ARM64
DLL cross-built successfully; native execution of that new build remains
required. The final local matrix uses fresh workspaces and these exact files:

| Built proxy | Bytes | SHA-256 |
| --- | ---: | --- |
| x64 `secur32.dll` | 244,736 | `740aca60041793a9a63dbd60dad2d69befe5233df5618403cecf1f1ac20144ec` |
| x86 `secur32.dll` | 260,096 | `82cc53faf231ef092377619b568dc340368ccceb32fb9833284f3db0c60fc30e` |
| ARM64 `secur32.dll` cross-build | 185,856 | `0384bba9877cdbdb20be41e60bd294b2354b2eba35dac8ed8ef2b0c6a1fc618b` |

Evidence: `_scratch/t20-final-native-x64.log`,
`_scratch/t20-final-native-x86.log`, `_scratch/t20-arm64-ast-final-tests.log`,
`_scratch/t20-arm64-canary-final-scan.json`, `_scratch/t20-final-local/`,
`_scratch/t20-arm64-results.json` and
`_scratch/t20-arm64-ci-44616524962/`. All browser runs use `secur32.dll` alone
as the deployed proxy; the private-registry shim is test-only. No launcher or
alternate deployment proxy was introduced.

## Final recorded DLL-only matrix (November 20, 2026)

The completed snapshot covers all 18 requested browser/channel/architecture
cells: **12 passed, six failed**. Each passing cell completed all seven signed
CRX/MV2 lifecycle phases, including MV3, signature and missing-proof controls,
cache reuse, cold discovery and removal. These 12 cells passed 84/84 phases,
616 instruction-memory checks and 768 renderer sandbox checks. All 18 cases,
including failures, preserved source/copied browser hashes and cleaned their
private registry subtree. No production launcher or alternate proxy was used.

| Browser / execution host | Stable (release) | Beta | Canary |
| --- | --- | --- | --- |
| Chrome local x64 | 158.0.8127.37: 7/7 | 159.0.8154.13: 7/7 | 160.0.8172.0: 7/7 |
| Chrome local x86 | 158.0.8127.37: 7/7 | 159.0.8154.13: 7/7 | 160.0.8172.0: 7/7 |
| Chrome native ARM64 CI | 158.0.8127.37: 7/7 | 159.0.8154.13: 7/7 | 160.0.8172.0: 7/7 |
| Edge local x64 | 157.0.4341.60: 7/7 | 159.0.4402.7: failed | 160.0.4413.0: failed |
| Edge local x86 | 157.0.4341.60: 7/7 | 159.0.4402.7: failed | 160.0.4413.0: failed |
| Edge native ARM64 CI | 157.0.4341.60: 7/7 | 159.0.4402.7: failed | 160.0.4413.0: failed |

All six failed Edge cells passed stock rejection, then retained stock decision
bytes after the full 75-second patched readiness wait. Final module snapshots
contained only Windows' system `Secur32.dll` and `SspiCli.dll`, not the local
production proxy. Their reports remained failures; signature/identity/readiness
assertions were not removed. These tested startup paths cannot be activated by
changing code inside a DLL that they do not load. The required DLL-only deployment
was preserved rather than substituting a launcher, another proxy or altered
browser files.

### Edge Beta and Canary ARM64 follow-up

The user reports that installed Edge SxS Canary 160.0.4415.0 x64 works with
uBlock Origin 1.76.4 enabled. Its installed `secur32.dll` matches the local x64
build (`b6f7113216434ddedce9a571913b2cfd8f979bad83ea2cb8c6ffc4e6846afd39`), and
the installed `msedge.dll` scan recognizes both gates
(`20975631e3dba6144523dc9ad9f30afc8030de375a940d775d9b83e64014d3f2`). A clean
copy did not reproduce that report. A local direct x64 attempt also ended before
gate reads when Edge's GPU process exited with access denied; it is inconclusive.
This does not invalidate the user's live observation. Artifacts:
`_scratch/edge-canary-4415-installed-scan.json` and
`_scratch/edge-canary-4415-root-lifecycle/results.json`.

Edge Stable ARM64 passed the full seven-phase lifecycle in run 44778695275
(`_scratch/arm64-master-44778695275/edge-stable/crx/results.json`). The latest
focused tests were Beta 159.0.4402.13 and Canary 160.0.4415.0 ARM64. Both verified
Edge Update packages extract only versioned `Chrome-bin/<version>/msedge.exe`,
not the installed top-level `Application/msedge.exe`; the direct DLL-only check
therefore reports `not_tested`. The CRX harness then passed its stock phase but
failed the patched-memory assertion with stock bytes `e0fe0736`; diagnostics
listed only Windows `SspiCli.dll` and `Secur32.dll`. Those CRX runs use the
test-only `registry-test.dll` to isolate extension registry reads, so they are
not proof of DLL-only loading. Machine-readable Beta and Canary reports are saved
under `_scratch/arm64-edge-beta-44826700857/` and
`_scratch/arm64-edge-canary-44826700537/`.

These ARM64 runs validate the native code and isolated extracted-copy behavior,
not an installed Beta/Canary launch. A real-layout test needs the top-level
Application executable and install context. Microsoft's offline installer is
available for Beta but not Canary; the current verified update payload is not
that MSI, and no supported unattended Canary install path was established. We
therefore did not guess installer switches, fall back to the versioned executable,
copy an authenticated user profile, or use injection as proof. DLL-only support
for installed Beta/Canary remains unresolved. Native ARM64 CTest passed 17/17 in
each latest focused run.

Local final native CTest passed 20/20 x64 and 18/18 x86. Native Windows ARM64
[run 44720250707](https://github.com/Sketchystan1/chrome-mv2-patch/actions/runs/44720250707)
at `ab88b67` passed 17/17 native tests and the four successful ARM64 browser
cells; its overall conclusion correctly stayed failure for Edge Beta/Canary.
Its identical 185,856-byte ARM64 proxy has SHA-256
`ad014c4cae8d33dff83783281da87b7f60f5ad02d5d86cd881db29121ac972f1`.
Local tested x64/x86 proxy hashes and sizes are the final-build entries above.
Source metadata files retain verified installer sizes, SHA-256 values and PE
architecture/version identities for every case.

Canary advanced while the final tests ran. Unpinned
[run 44716336096](https://github.com/Sketchystan1/chrome-mv2-patch/actions/runs/44716336096)
received Chrome 160.0.8172.1 ARM64, browser DLL SHA-256
`f759d9b2800a57d88f1ae6b753b6c11f2d1b68f3bc5297baccfd0d887da8741a`.
That build was correctly rejected: three genuine predicate layouts need further
instruction/side-effect support, and a fourth candidate belongs to FIDO
credential-protection validation. Those authentication decisions were not
patched or bypassed. This is a separate unsupported build, not a pass for the
recorded 160.0.8172.0 snapshot. Vendor metadata later reported 160.0.8173.0;
that version was not fetched or runtime-tested in this matrix.

The fetcher and workflow now support replaying recorded vendor metadata, so
reruns test the same immutable inputs while retaining all size/hash/PE/version
checks. Reproduce the native snapshot with:

```text
gh workflow run win-arm64-test.yml --ref master -f browser=all -f source_run=44616524962
python scripts/test_autoscan_runtime_memory.py
```

The combined machine-readable ledger is `_scratch/t20-final-matrix.json`.
Detailed final local records are `_scratch/t20-final-local/results.json` and
the corresponding `f20<arch><case>/` workspaces. Native records, original vendor
metadata, browser/DLL identities, scans and logs are beneath
`_scratch/t20-arm64-pinned-final-ci/`; its `summary.json` describes all six
ARM64 outcomes. Initial and failed exploratory attempts remain separately
recorded in the earlier directories. No independently reviewed complete core
address baseline or complete enforcement coverage is claimed.

## Remaining limits

`complete_enforcement_coverage_proven` remains **false**. New compiler layouts,
missing function bounds or unsupported instructions can escape recognition.
The recorded Edge Beta/Canary test copies did not activate the local proxy, while
the user reports their installed SxS Canary 160.0.4415.0 x64 works; the isolated
copy has not reproduced that result. Newer Canary builds, browser updates, broader
interactive browsing and DRM remain unvalidated or unsupported as recorded above.
Performance timings use one host, warm files and headless/GPU-disabled browsers;
controlled cold-disk and desktop-window performance were not measured. A new
scanner identity refills its cache on first use.
