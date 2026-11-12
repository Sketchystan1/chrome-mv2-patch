With one identical complete DLL, disabling **parent-process thread notifications** lowered the headless browser API-response median from **1,134→1,079 ms**, roughly 5%, and cached Patch from **304→267 ms**, roughly 12%. Four cache-hit observations per setting and overlapping ranges limit the conclusion. Renderer settings stayed at defaults; the 8 MiB threshold did not improve median Patch time. The earlier separate-build comparison and the subsequent same-DLL controls are both retained below.

Research date: November 12, 2026. This continues [PERFORMANCE-FOLLOWUP.md](PERFORMANCE-FOLLOWUP.md). Production source, installed browsers, real profiles and previous research artifacts were unchanged. [PERFORMANCE-IO-STARTUP.json](PERFORMANCE-IO-STARTUP.json) records exact source/artifact identities and observations. New prototypes live under `_scratch/perf-stage3-*`.

## Complete browser comparison

| Complete DLL | Bytes | Launcher spawn→API response median | ResumeThread→API response median | Cached Patch median |
| --- | ---: | ---: | ---: | ---: |
| Current algorithm with common measurement fields | 219,136 | 1,157.419 ms | 1,072.391 ms | 304.217 ms |
| Current + working-set protection batch | 219,648 | 1,128.004 ms | 1,056.146 ms | 284.947 ms |
| Working-set batch + dynamic TLS + disabled notifications | 220,160 | 1,070.302 ms | 1,002.411 ms | 256.526 ms |

The combined candidate's medians were 7.5% lower before-spawn, 6.5% lower after-resume and 15.7% lower inside Patch. The extra dynamic bundle did not beat the page batch in every observation block. Separate DLL builds, compiler/layout effects, background load and cache conditions were not isolated; these results cannot assign the individual contributions of dynamic lookup and notification suppression.

The milestone is successful **Browser.getVersion and SystemInfo.getProcessInfo** WebSocket responses with the returned browser PID checked. The workload is headless with GPU disabled. A port file alone is insufficient; no first usable desktop window was measured. The observer starts before the launcher without a separate readiness handshake, so initialization, 20 ms polling, RPC and output IPC remain in the observation where applicable. QPC is recorded immediately after ResumeThread and again at response observation.

Fifteen browser launches comprised three excluded cache-fill warm-ups and twelve cache-hit measurements in forward/reverse blocks. Every launch received a fresh copy of the same frozen installed-profile seed and a variant-specific persistent cache. No other agent ran CPU benchmarks during the window; file caches were not purged and normal background activity continued. The WS variant's first retained cache hit had a 133 ms plan stage despite unchanged cache data; it was retained, not removed as an outlier.

Every browser called Patch **exactly once**, including after the functional controls. Repeated qualifying loader calls therefore were not a bottleneck in this workload. All measured launches reported direct-parent cacheHit=1 and unchanged cache bytes/mtime. Current used six decision-page VirtualQueries; both candidates used one working-set batch and zero fallback queries.

All **135 final decision instructions**, matching proxy path/hash, stock-file hashes and **15 functional lifecycles** passed. Controls included packed off-store MV2 enable/disable, background listener startup, real HTTP request cancellation, MV3 service-worker activity and renderer Win32k lockdown, without an off-store launch flag. The private UUID registry namespace was confirmed absent before creation and removed after all isolated jobs closed. Real extension registrations were not written; termination was restricted to owned kill-on-close jobs.

All three complete DLLs passed 23 forwarding/ordinal checks each (**69 total**). The complete dynamic DLL has a zero PE TLS directory, and actual DllMain DisableThreadLibraryCalls returned TRUE in native checks and every browser launch. Common timing fields are constant-initialized globals; no guarded dynamic function-local static was added. The larger probe DLLs' zero-TLS findings were independently checked on this complete proxy.

## What dynamic TLS changes, and its limit

The current hash adapter's small static thread_local budget causes DLL TLS work even in children/threads that never hash. The tested candidate uses a global POD InitOnce/index and scoped pointers to caller-owned stack Budget storage. Parent and callback storage remains live through joins. Initial allocation or installation failure falls back to serial hashing. Restoration failure retires all future lookups before stack storage expires, avoiding later dereference of a stale slot.

Five fresh-process native modes passed normal, initialization failure, installation failure, restoration failure and retirement-during-hash checks, including irregular/threshold digests, odd budgets, concurrent callers, nested pointers and LastError. A tiny full-kernel DLL first established zero static TLS and successful notification suppression; the full proxy subsequently passed the same structural and ABI checks.

The prototype retains one TLS index until process exit per module load. Repeated DLL unloading/reloading can accumulate slots; cleanup after quiescence was not added. Normal tested browser/helper loads keep the module for their process lifetime. EXE/static-library hash users initialize lazily at the first eligible join, rather than relying on proxy DllMain. Dynamic local statics such as a lazily calculated QPC scale can themselves reintroduce TLS, so the final PE directory must be inspected.

## Same-DLL controls: parent benefit, renderer settings stayed at defaults

One **228,352-byte DLL** then supplied all three cases, so machine code, DLL identity and scanner cache identity were identical. Bounded process-local environment settings selected notification policy and an immutable 16/8 MiB fork threshold before hashing. Native parsing preserved defaults for missing/malformed/oversized inputs; PE TLS stayed zero. Sixty-four flag/digest/boundary checks and 69 forwarding checks passed before fifteen more browser lifecycles.

| Same DLL, parent setting | Launcher spawn→API median | ResumeThread→API median | Cached Patch median |
| --- | ---: | ---: | ---: |
| Notifications enabled, 16 MiB fork threshold | 1,133.530 ms | 1,066.795 ms | 304.151 ms |
| Notifications disabled, 16 MiB | 1,079.381 ms | 1,022.417 ms | 267.032 ms |
| Notifications disabled, 8 MiB | 1,057.055 ms | 989.967 ms | 270.526 ms |

Parent notification suppression gave roughly **4.8% lower API-response and 12.2% lower cached-Patch medians** in this population. Four retained cached observations per case, overlapping ranges, background/cache state and observer overhead still limit the conclusion. One notifications-enabled run retained a 780 ms identity outlier. The 8 MiB case had a slightly lower API median but a **higher Patch median** than 16 MiB; it does not establish a cached-patcher improvement.

The important non-obvious result came from reading owned renderer modules: **all 105 snapshots retained flags zero**, representing default notifications-enabled/16 MiB settings. Parent flags correctly matched the requested controls, but renderer controls did not follow them. This is an observed propagation failure, not proof of its precise cause. The experiment therefore compares observed parent settings with default renderer settings; it cannot attribute aggregate child-loader savings. The earlier unconditional complete dynamic build is a different configuration and must remain separate.

All fifteen new lifecycles, 135 additional decision checks, direct cache hits, unchanged proxy/stock-file identities and private registry cleanup passed. Every browser again invoked Patch once. No production setting or sandbox policy changed. A possible future aggregate-child experiment would vary only a bounded read-only startup data block between copied DLLs and verify identical executable sections, rather than depend on environment propagation; it was not implemented here.

## Read buffers remove faults, but copies still cost time

The synchronous kernel uses the same exact read-only locked handle, one fresh VirtualAlloc buffer per observation and repeated fills within that single file. Actual successful read counts are accumulated until the hash window is full, retaining power-of-two alignment and the chosen parallelism. Every file byte contributes to the standard incremental BLAKE3 digest; every text byte is compared. Buffer allocation, first fill and cleanup are included. The mapping control likewise includes data-view creation and unmapping, with readiness and cleanup recorded separately.

| Read/hash/compare readiness | Chrome 153 | Chromium 157 | DCHECK Chrome 159 |
| --- | ---: | ---: | ---: |
| Mapping, whole-file hash with 8 MiB threshold | 224.528 ms | 217.766 ms | 398.227 ms |
| One 16 MiB buffer, 4 MiB threshold | 285.902 ms | 287.290 ms | 520.467 ms |
| One 32 MiB buffer, 8 MiB threshold | 295.588 ms | 291.223 ms | 515.537 ms |
| One 64 MiB buffer, 8 MiB threshold | 296.941 ms | 306.075 ms | 561.756 ms |
| Same 64 MiB buffer with SEQUENTIAL_SCAN | 298.382 ms | 302.576 ms | 558.106 ms |

The 16 MiB buffer roughly halved aggregate process page faults: 136,620→66,930, 140,784→68,932 and 248,480→121,580. Nevertheless, read/copy cost outweighed saved stock-view fault work. On the diagnostic image, synchronous reading took roughly 168–206 ms, hashing 91–97 ms and comparison 253–267 ms. Fewer faults alone is not proof of lower latency; aggregate counts do not separate disk and soft faults.

Sixty-seven checks covered successful fragmented reads, mismatches, bad handles/ranges/sizes, forced IO failure, buffer reuse and larger threshold/window digests. All real-image digests matched the independent diagnostic scanner and all stock SHA-256 values remained unchanged.

## Background reader: less waiting, still no readiness win over mapping

A second kernel allocates two fresh buffers and lets one thread-pool callback synchronously read the next window while the caller hashes/compares the current window. One reader owns the sequential file position at a time; every callback is joined before task/buffer reuse or release. Failure to allocate a work item falls back to synchronous reading. The standard hasher is never updated concurrently.

| Read/hash/compare readiness in the separate paired batch | Chrome 153 | Chromium 157 | DCHECK Chrome 159 |
| --- | ---: | ---: | ---: |
| Mapping / 8 MiB fork threshold | 227.069 ms | 220.281 ms | 407.919 ms |
| Synchronous 16 MiB buffer | 288.900 ms | 289.668 ms | 509.924 ms |
| Two 16 MiB buffers / background reader | 240.663 ms | 233.798 ms | 414.930 ms |
| Synchronous 32 MiB buffer | 296.255 ms | 289.793 ms | 510.929 ms |
| Two 32 MiB buffers / background reader | 236.159 ms | 239.029 ms | 418.188 ms |
| Two 64 MiB buffers / background reader | 258.932 ms | 263.915 ms | 430.413 ms |

The worker hid much synchronous read time, but did not consistently beat mapping at readiness. Two 32 MiB buffers completed through cleanup in 239/242/421 ms versus mapping 281/277/502 ms. That removes or shifts different work: the production patcher already defers mapping cleanup, so the through-cleanup result is not an equivalent blocked-startup improvement. Larger buffers added private committed memory and first-touch cost; lower process working set does not automatically mean lower system RAM use because file-cache pages remain elsewhere.

Each kernel case/image has eight retained observations plus a warm-up, with forward/reverse ordering and fresh input resources and loaded-image views. Sixty-three new checks covered worker/serial fallback, fragmented reads, first/next-read failure, mismatch and large-window digest parity. Every live input byte/digest and original-file SHA were checked. These kernels exclude plan/cache/application/rollback and require independently verified absence of text relocations; they are not deployable patch authorization paths.

Ordinary OVERLAPPED APIs are a different experiment: cached reads can complete inline, so simply queuing the next read may still perform copy work on the caller. A tiny asynchronous API probe submitted two reads before waiting, observed pending completion, retained an actual 17-byte short read near EOF, and observed EOF only at completion. All buffers/events/OVERLAPPED records must remain live through completion or confirmed cancellation. The explicit reader callback avoids assuming the IO API offloads copy work; it still competes for CPU and memory bandwidth.

## Merging validation walks stayed unselected

Merging the allocation and text-readability walks retained every allocation check and deferred unreadability reporting until allocation validation finished, preserving failure-reason priority. The native suite passed **585 checks**, including guard/noaccess/decommit, unreadable nontext regions, late allocation failure, original working-set fallbacks and rollback.

It removed one text query while retaining all thirteen allocation queries on the tested images. The paired saving was **0.04–0.07 ms serially**, or **4.2–8.2 ms after preflight** populated text PTEs. Whole-return improvements were inconsistent: diagnostic overlap even worsened 352→373 ms while application time fell. It is not an independent serial optimization worth adding; it remains an optional preflight cleanup requiring actual-browser evidence.

## Decision from this round

The useful production candidate remains the independent page-protection guard. Dynamic TLS plus successful notification suppression is now a complete-proxy/browser candidate with a documented lifetime limit; the same-DLL controls determine what can be attributed to notification policy. Read buffering, an IO worker and merged region walks remain unselected for the ordinary cached-startup path. Genuinely cold storage, other CPUs and desktop windows can produce different crossovers.

Primary sources: [VirtualQuery](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery), [working-set page protection](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-psapi_working_set_ex_block), [DisableThreadLibraryCalls](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-disablethreadlibrarycalls), [dynamic TLS](https://learn.microsoft.com/en-us/windows/win32/dlls/using-thread-local-storage-in-a-dynamic-link-library), [TlsGetValue and LastError](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsgetvalue), [ReadFile counts/lifetimes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile), [pending IO cancellation](https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations), [standard BLAKE3 incremental API](https://github.com/BLAKE3-team/BLAKE3/blob/f3149ec5bb5449af877ba20377a11008ff499fa2/c/README.md).

Skipped production deployment, general IO frameworks and repeated-DLL-reload TLS cleanup. Desktop window latency, native x86/ARM64, controlled cold boots and broad CPU/DRM validation remain unchecked; startup snapshots and timing uncertainty retain their existing limits.

## Implementation after research

The production code now uses the exact-RX working-set batch with original-query
fallback and scoped dynamic hash TLS. DLL detach frees the TLS slot after joined
calls, removing the prototype's repeated-reload limitation. Thread notifications
are disabled in every proxy process, without the research environment controls.
The 16 MiB fork threshold is retained. The x64 discovery loop additionally uses
complete raw runtime-table rejection before trimming; unsupported/limited scans
and all heuristic/other-architecture bounds keep the original path.

Native x64 tests passed 18/18 and x86 passed 14/14, including TLS failure/retirement,
concurrency and repeated unload, page-guard fallback/boundaries and lazy-trim
limits. All six rebuilt binaries have correct architecture, no static TLS or
writable executable sections and remain below 300,000 bytes. These implementation
checks do not turn the earlier headless medians into desktop latency guarantees.
All 23 native and two ARM64 analysis reports matched the full frozen diagnostics.
The final DLL passed three isolated browser lifecycles with 13 stock, upgrade,
patched, restart and restore phases, checking 125 instructions, cache reuse,
MV2/MV3 behavior, Win32k lockdown and private registry/original-file restoration.
