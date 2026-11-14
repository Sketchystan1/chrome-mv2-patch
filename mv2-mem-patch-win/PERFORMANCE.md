# Windows automatic patcher performance

`secur32.dll` is the deployment DLL for x64, x86 and ARM64. This record summarizes
the current implementation and the completed November 14, 2026 experiments.

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

The current DLL passed stock, patched, cached restart, cache-deleted restart and
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

`complete_enforcement_coverage_proven` remains **false**. Native x86/ARM64 browser
behavior, browser updates and DRM remain unvalidated. Timings use one host, warm
files and headless/GPU-disabled browsers; controlled cold-disk and desktop-window
performance were not measured. A new scanner identity refills its cache on first use.

| Current deployment artifact | Bytes | SHA-256 |
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
