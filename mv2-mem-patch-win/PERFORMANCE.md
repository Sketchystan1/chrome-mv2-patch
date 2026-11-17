# Windows automatic patcher performance

`secur32.dll` is the deployment DLL for x64, x86 and ARM64. The performance
experiments and historical identities below describe the November 14, 2026
implementation, before the 2.0.0 version and documentation cleanup. The final
section separately identifies the rebuilt 2.0.0 DLL tested against Chrome Canary
160 x86 on November 17. Results apply to their recorded artifacts.

## Current path

| Startup state | Work performed |
| --- | --- |
| Valid protected cache | Full stock-file BLAKE3 identity, cache authentication, complete loaded-code validation and transactional patching |
| Cache miss or rejected cache | The same checks, plus isolated helper discovery and a new protected plan |

The parent locks and maps the stock file read-only. Its DPAPI-protected cache is
bound to browser BLAKE3, scanner SHA-256 and protocol version. The helper runs only
on a cache miss, with a 30-second deadline. Patch pages transition
RX → RW → write → flush → RX; failed rollback terminates the process.

Selected improvements include `/O2`/LTCG, upstream SIMD hashing, adaptive hash
workers with a 16 MiB threshold, bounded shared reference searches, function-trim
reuse, combined allocation/readability validation and process-only initial-thread
capture. Full-file identity, ambiguity handling, bounds, loader-lock calibration,
loaded-code equality, protection and rollback remain required.

## Measured performance

The 160-route catalogue had 113 remaining experiments: **107 executed and six
skipped**. Outcomes were 30 component/design wins, 77 no-gain results and six
hardware/privilege skips. The final campaign selected only the x86 reference
filter (61) and validated contiguous runtime-table reads (65).

| Complete discovery endpoint | Before → after | Paired reduction | Confirmation |
| --- | --- | --- | --- |
| x86 reference filter; unbranded Chrome for Testing 157.0.8103.78 | 2,514.022 → 844.536 ms | 66.37% | 16/16 pairs faster; 34 identical reports |
| Runtime-table reads; Chrome 157.0.8103.79 x64 | 313.734 → 303.934 ms | 3.40% | 16/16 pairs faster; 34 identical reports |
| Runtime-table reads; Edge x64 | 281.711 → 260.428 ms | 7.60% | 16/16 pairs faster; 34 identical reports |

These are retained-stock-view `Analyze` measurements affecting cache misses.
The x86 image is authentic, unmodified and **unbranded**. Separate improvements
cannot be added together or presented as browser-start gains.

Twelve alternating cached Chrome launches per DLL all succeeded. Medians were
774.239 → 775.125 ms; paired median reduction was 1.14%, with 7/12 faster.
**No cached browser-start improvement was established.** The endpoint was browser
resume to owned DevTools RPC completion. All 234 instruction checks and 78
sandbox-renderer observations passed; all 24 cache hits preserved bytes and mtime.

## Experiments left unselected

| Experiment | Decision |
| --- | --- |
| 4/8 MiB hash thresholds | Kernel gains did not survive browser confirmation: paired -1.23% / -0.30%, 6/12 faster each. Keep 16 MiB. |
| Atom compiler tuning | Initial 8.43% screening gain fell to 2.16%, 7/12 faster. Compiler flags stay unchanged. |
| Instrumented PGO and function ordering | No consistent complete-browser gain; optimized PGO populations had worse tails or mixed pairs. |
| Fused hashing and code comparison | Repaired prototype passed safety checks but lost against current assembly by paired 4.96% on Chrome and 22.04% on Edge. |
| Combined discovery routes 65/60/130 | Slower than route 65 alone. |
| Acquire-state proxy read | Six browser pairs gave 9.16% paired reduction, only 4/6 faster. Nanosecond kernel savings do not establish startup attribution. |
| Persistent disk patch | Isolated design improved startup by 25.13%, 6/6 faster; its signature/update/restore contract differs from this runtime patcher. |
| Broker/helper protocol redesigns | Corrected prototypes passed 397 authentication, header, EOF and deadline checks; architecture changes remain experimental. |

AVX2, AVX-512, native Windows ARM64, two multi-node NUMA routes and privileged
SPGO sampling were unavailable and skipped at the user's request.

## Validation and historical identities

The November 14 DLL passed stock, patched, cached restart, cache-deleted restart and
restore with packed MV2 request blocking and MV3 controls: 45 instruction checks
and 39 renderer checks. Stock browser files stayed unchanged; isolated proxy and
private registry state were restored. Native CTest passed **20/20 x64 and 17/17
x86**; ARM64 cross-built. Confirmation also passed 943,106 reference/alignment/
collision assertions and 85,248 adversarial runtime-table/unwind/stride comparisons.

The earlier reviewed scanner matrix reproduced 166 core decisions across 21 x64
and two x86 images, 23 InstallVerifier gates and 20 CRX download gates; two ARM64
analysis reports matched. Edge 157.0.4341.46 passed developer-signed CRX3 installation,
enablement, restart and removal. Tampered packages and missing developer proofs
were rejected; shared store detection stayed unchanged. Ordinary Chrome/Edge
window startup passed on a private desktop, without a timed performance endpoint.

Earlier populations retain a 30-second patch-verification timeout, a WebSocket
observer timeout and failed PGO training whose cause cleanup masked. Initial
broker/helper and fused-comparison failures were repaired and preserved. Later
successful populations do not erase those failures or identify their causes.

`complete_enforcement_coverage_proven` remains **false**. Those experiments did
not validate native x86/ARM64 browser behavior, browser updates or DRM. Timings
use one host, warm files and headless/GPU-disabled browsers; controlled cold-disk
and desktop-window performance were not measured. A new scanner identity refills
its cache on first use.

| Deployment artifact from the recorded experiments | Bytes | SHA-256 |
| --- | ---: | --- |
| x64 `secur32.dll` | 243,200 | `3e5238381af1280bdce4fdfb31d85f9e45ac7535eecea21468cbf90c25366898` |
| x86 `secur32.dll` | 245,760 | `15f6d0cf296e15350081839e433a524d0c190993bce6cfd70d7d15c078c37ddd` |
| ARM64 `secur32.dll` | 172,544 | `b97d23862dc688e3a94bd3fb905cea381a05da00a32914023963a4974c9ef01a` |

## Detailed records

Commit `7f803bfd2900907f24b427c614067988ba91ce02` preserves the complete report,
160-route catalogue, 113-row execution ledger and historical artifact identities:

```sh
git show 7f803bf:mv2-mem-patch-win/PERFORMANCE.md
```

Sources, raw results, failed populations, research artifacts and test logs are
retained locally in the ignored `_scratch/performance-evidence-2026-11-14.zip`.
Archive paths preserve the original workspace layout; `ARCHIVE.json` lists hashes
and omitted temporary content. Key records are the campaign's `outcomes.json`,
`final-summary.json`, `final-selected/results.json`, `discovery/confirm61/results.json`,
`discovery/confirm65/results.json` and `final-checks/`, plus the final lifecycle
`_scratch/all-experiments-life/results.json`. Copied browsers, test profiles,
duplicate dependencies and regenerable build intermediates were removed.

## Chrome Canary 160 x86 regression validation

On November 17, 2026, the rebuilt 2.0.0 x86 DLL passed a full isolated lifecycle
test with branded Chrome Canary **160.0.8167.0**. The old x86 helper ran analysis
on `rundll32`'s 256 KiB stack and could overflow before returning a plan, leaving
Chrome running without MV2 patches. Analysis now runs on a joined worker with a
1 MiB stack reserve. Canary's diagnostic calls and high-byte register operations
also required recognizing a verified reload of the provider's extension argument
before its off-store flag check. The fix preserves those calls and diagnostic
branches; it patches only the existing verified-extension decision.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Stock Canary x86 `chrome.dll` | 272,000,664 | `496b63e201072bd4dccfe185dfd0ff50fbf0eb1f8c7c95b05109aa0c05472201` |
| Tested x86 `secur32.dll` | 247,296 | `8236f3f34596d012215242b51a30b1df2d43c3f888c5d36f9a598bd24421562d` |

The packed external MV2 control enabled, ran its background page and cancelled
requests. Disable/re-enable, protected-cache reuse and a restart after deleting
the private scan cache passed. The MV3 control ran in every phase; removing the
proxy restored MV2 deprecation and prevented enablement. All **40 instruction
checks** and **39 renderer sandbox checks** passed. Stock browser DLL hashes
remained unchanged, and the private external-extension registry subtree was
removed. The scanner recognized seven core decisions and the off-store verifier;
the optional CRX download decision was unrecognized.

Independent stock disassembly confirms the off-store branch at RVA `0x2f0953e`
selects its existing target `0x2f0958c`. Its other path can store the
`DISABLE_NOT_VERIFIED` reason `0x100` at `0x2f09581`. The extension pointer is
reloaded from `[ebp+8]` immediately before the creation-flag test; the preceding
`SETNE BH` and `TEST BL,BH` retain their diagnostic behavior.

Native CTest passed **18/18 x86** and **20/20 x64**, including the new cold/cached
helper regression through the real x86 `rundll32` host and rejection tests for
unsafe provider argument reloads. ARM64 cross-built successfully. The full
portable fixture and Windows installer suite also passed with Capstone and Z3
available. This test does not establish Chrome x86 CRX download installation,
native ARM64 behavior, browser updates, interactive browsing or DRM.

The retained local evidence is `_scratch/x86-160-recheck/results.json`, its
per-phase reports and `_scratch/x86-160-recheck.log`. Reproduce the browser check
after building the x86 test targets:

```text
python scripts/test_autoscan_runtime.py _scratch/canary160-x86-runtime-matrix.json --arch x86 --work _scratch/x86-160-new
```

The matrix names the stock, complete x86 browser copy; the new output directory
must not already exist. Earlier failed attempts remain in `_scratch/x86-old/`,
`_scratch/x86-thread/` and `_scratch/x86-160-final/`.

The first fixture-suite attempt failed an installer process-identity check; the
repeated full run passed. Both results are retained in
`_scratch/canary160-fixture-tests.log` and
`_scratch/canary160-fixture-recheck.log`. ARM64 build output is retained in
`_scratch/canary160-arm64-build.log`.

## Chrome Canary 160.0.8166.2 x86 CRX installation

On November 17, 2026, the corrected 2.0.0 x86 DLL passed signed off-store CRX3
installation on the user's exact branded **160.0.8166.2 (32-bit)** build. The
stock browser reproduced `CRX_REQUIRED_PROOF_MISSING` for the same signed
package. The scanner previously declined the framed constant-zero external
verifier and a security-cookie helper's terminal trap at its trimmed boundary.
Recognition now checks those bounded forms without changing verifier calls,
return cleanup, developer signatures, package integrity or user confirmation.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Stock Canary x86 `chrome.dll` | 272,436,376 | `87ef34817cfcb2c6fb3443aa94621b0f980102ae81a256c6666db297d4e148ba` |
| Tested x86 `secur32.dll` | 247,808 | `641c0089f9c6ac67c190ceea6380c06f609389355d864bb4d74a7ec5de709cb4` |
| Local `mv2-patch-2.0.0-canary160-crx-fix-win-x86.zip` | 114,932 | `486274bf032c031d7007661507084e97c88e3b4bd1a49d51d8bd68ab41cd4e29` |

The final seven-phase matrix used an isolated browser copy, private profiles,
download directories, registry subtree and Windows desktop. Chrome's real
Downloads Keep action opened the signed CRX; its native Add extension dialog
confirmed installation. The packed MV2 extension enabled, ran its background
page and blocked requests. Disable/re-enable, cache reuse, a restart after
deleting the private cache, and an MV3 background control passed. Removing the
proxy restored both the downloaded-CRX proof requirement and MV2 deprecation.
The scanner recognized seven core decisions, InstallVerifier and the CRX
download decision; all **63 instruction checks** and **59 renderer sandbox
checks** passed. The stock `chrome.exe` and `chrome.dll` hashes stayed unchanged,
and registry cleanup completed.

Tampering with the signed package produced `CRX_SIGNATURE_VERIFICATION_FAILED`;
removing its developer proofs produced `CRX_REQUIRED_PROOF_MISSING`. Neither
control installed. The ZIP contains only `install.bat` and the tested DLL; its
archived DLL hash matches the final runtime result. The prior ZIP named
`mv2-patch-2.0.0-canary160-fix-win-x86.zip` contains the earlier DLL and does not
include this CRX discovery fix.

Independent source/disassembly review identifies the CRX branch at RVA
`0x2c84d2a` (`74 0E` to `90 90`), the framed external verifier at `0x51f4f10`,
and the security-cookie terminal trap at `0x79737a5`. The installer's source
reason is `AllowedBecausePref` (2) at field offset `+0x12c`. These are evidence
for this stock hash, rather than scanner input or version-table entries.

Native tests passed **18/18 x86** and **20/20 x64**, including positive and
negative fixtures for the framed verifier, terminal trap and conflicting return
cleanup. ARM64 cross-built; native ARM64 execution remains unverified. Browser
updates, DRM and broader interactive browsing remain outside this test.
The complete portable fixture and Windows installer suite passed with Capstone
and Z3 available, including both CDP helpers' syntax checks. Its log is
`_scratch/canary160-crx-final-fixtures.log`.

Retained evidence is `_scratch/crx160final/results.json`, its per-phase logs,
`_scratch/crx160final.log`, `_scratch/canary160-crx-package.json` and
`_scratch/canary160-crx-final-native-x86.log`. The earlier complete run in
`_scratch/crx160q/` also passed. An earlier attempt in `_scratch/crx160full/`
failed its empty-cache memory check with stock bytes still present. It captured
no patcher trace, so the cause of that intermittent startup failure is not
established; both subsequent full runs passed with diagnostics. The separate
external-extension lifecycle passed in `_scratch/mv28166/results.json`.
Five additional consecutive empty-cache restarts passed with all nine decisions
applied, MV2 execution/request blocking, the MV3 control, unchanged browser
hashes and registry cleanup. Their evidence is
`_scratch/crx160cold/results.json` and `_scratch/crx160cold.log`.

Reproduce after building matching x86 test targets, using a new short work path:

```text
python scripts/test_autoscan_crx.py _scratch/canary160-8166-runtime-matrix.json --arch x86 --work _scratch/crx160-new
```
