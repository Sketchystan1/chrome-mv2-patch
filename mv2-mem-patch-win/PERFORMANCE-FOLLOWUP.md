Further research found a small improvement independent of hash/preflight overlap: avoid repeatedly querying the same executable memory region for each patch page. The page-protection guard fell from **17–59 ms to 4–8 ms** with one cached region result, or to **0.009–0.018 ms** with a documented batch query. Complete serial patch medians were **3–13% lower** in these samples; the guard measurements and reduced API counts are stronger evidence than the noisy complete-path percentages.

Research dates: November 11–12, 2026. Production source, deployment DLLs, browser installations and cache protocol were unchanged. This continues [PERFORMANCE-FRONTIER.md](PERFORMANCE-FRONTIER.md). [PERFORMANCE-FOLLOWUP.json](PERFORMANCE-FOLLOWUP.json) preserves raw observations, source/artifact identities and validation. New disposable experiments live under `_scratch/perf-stage2-*`; previous experiments were retained.

[Further IO and actual-browser measurements](PERFORMANCE-IO-STARTUP.md) test read buffers, dynamic TLS, notification policy and the 8 MiB threshold, including same-DLL controls and direct renderer checks.

## The new bottleneck: repeated page-region queries

`ApplyPlan` already checks all loaded allocation regions and `.text` readability, compares all nondecision code with checked relocations, and verifies every instruction/site. Before writes, it calls `VirtualQuery` again for every unique changed page. These pages are sorted and mostly belong to one large RX region. Microsoft's API description explicitly says it scans subsequent matching pages to determine the returned region's extent. Repeated calls can therefore repeat a large tail scan even though only a few patch bytes change.

The native stage probe separated allocation/readability, relocation comparisons, page collection/querying, writable transition, instruction copy, flush, post-write verification and protection restoration. The unexpected cost belonged to the **page queries**, not instruction writes or flushing. In the overlap attribution pass, page queries cost about 20/29/62 ms, repeated allocation/readability about 11/15/21 ms, relocation gap checks less than one millisecond and instruction-cache flushing approximately 0.001 ms.

| Complete serial Patch return, median | Original | One-region reuse | Batched page protection |
| --- | ---: | ---: | ---: |
| Chrome 153.0.8010.37 x64 | 299.494 ms | 267.595 ms | 269.722 ms |
| Chromium 157.0.8103.39 x64 | 279.998 ms | 271.598 ms | 267.641 ms |
| DCHECK Chrome 159.0.8148.1 x64 | 523.837 ms | 477.610 ms | 455.861 ms |

| Page-protection guard alone | Original | One-region reuse | Batched page protection |
| --- | ---: | ---: | ---: |
| Chrome 153 | 17.3957 ms | 4.2975 ms | 0.0094 ms |
| Chromium 157 | 21.2029 ms | 4.7570 ms | 0.0091 ms |
| DCHECK Chrome 159 | 59.1065 ms | 7.5200 ms | 0.0175 ms |

All modes ran in **one identical DLL**, with eight retained observations per mode/image plus excluded warm-ups, in alternating forward/reverse order. Every observation creates fresh stock-file and relocated image views and runs the actual `Patch`, protected cache lookup, complete application checks and deferred cleanup. Chrome is mapped with `DONT_RESOLVE_DLL_REFERENCES` and is never initialized or executed. Every final patch byte and the unchanged stock-file SHA-256 were checked.

The original guard made six queries on each normal image and nine on the diagnostic image. Region reuse made one. The batch made one working-set query and **zero VirtualQuery fallbacks** on all retained real-image samples. Protection-loop savings were consistent. Complete-path timings also contain hash/fault/scheduling variation; some total differences exceed the isolated query saving. The normal Chrome image's complete median favored region reuse slightly even though the batch guard was faster.

**Smallest candidate:** retain the end of the last successful MBI result within the existing sorted-page loop. Every later page inside that exact range has the same returned protection. Query again at a boundary; retain exact `PAGE_EXECUTE_READ` and check returned base/size coverage and overflow. This stores one operation's evidence, with no persistent cache or early preflight token.

**Faster guard candidate:** supply at most 128 explicit changed-page addresses to `K32QueryWorkingSetEx`. Only `querySucceeded && Valid && Win32Protection == PAGE_EXECUTE_READ` passes that page's protection check. Every other result runs the original `VirtualQuery` check. Keep the entire protection value, including modifiers; use neither AllocationProtect nor Shared for acceptance. K32 linkage is in Kernel32 and does not raise the existing Windows 10 minimum.

The batch does **not** replace full-file hashing, allocation/readability validation, byte equality, relocation rules, branch/target/order checks, stock/patch state checks, W^X or rollback. A private COW page restored to RX is valid even with `Shared=false`. An RX page can be nonresident and return `Valid=false`, including after removing a guard; it must fall back rather than decline just for residency.

The native suite passed **414 checks**, including region boundaries, RX/RW mismatch before writes, two-page branches, already-applied/mixed state, malformed/straddling relocations, API failure, invalid-residency fallback, protection restoration and rollback. A separate tiny SEC_IMAGE API check confirmed exact protection agreement for resident RX/R/RW/executable-write-copy pages, including private COW pages. These are startup snapshots under the existing no-concurrent-writer contract, not general live-patching protection guarantees.

Sources: [VirtualQuery](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery), [QueryWorkingSetEx/K32](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-queryworkingsetex), [Valid and Win32Protection](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-psapi_working_set_ex_block), [memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants).

## Worker count must be judged with the complete path

The separate native sweep varied only the hash ceiling and overlap mode in one DLL. The process allowed eight logical workers. Each case/image has eight retained observations with fresh views, plus warm-ups. Digests were later checked against the independent diagnostic scanner for all tested ceilings; every final patch and original-file identity was checked.

| Complete Patch return | Serial, automatic | Overlap, 2 hash workers | Overlap, 4 | Overlap, 7 | Overlap, 8 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Chrome 153 | 254.431 ms | 232.779 ms | 214.083 ms | 224.876 ms | 213.423 ms |
| Chromium 157 | 260.593 ms | 247.025 ms | 229.558 ms | 246.322 ms | 235.329 ms |
| DCHECK Chrome 159 | 656.753 ms | 516.107 ms | 480.859 ms | 496.063 ms | 489.975 ms |

Four workers matched eight within roughly 3% on these inputs and used about 5–11% less CPU through cleanup. Reserving exactly one logical worker was not the best measured rule. A one-worker hash with a comparator was much slower. CPU availability is a capacity limit, not a latency optimum; this does not justify restoring a fixed four/eight-worker production ceiling or hard-coding this host's answer.

The wider overlap is still conditional. The independent stage-attribution batch measured serial/overlap 440→329 ms, 347→363 ms and 614→482 ms: **one image regressed**. In the later page-query batch, adding the batch guard to overlap improved two images but slightly regressed the first. Keep old results as measurements of their own populations; do not treat the earlier 11–15% result as a universal launch guarantee.

## Streaming has a parallelism cliff

The pinned BLAKE3 implementation consumes each update in file order using power-of-two subtrees aligned to the accumulated byte count. The current adapter only forks subtrees of at least 16 MiB. With ample CPU capacity, an aligned 4 MiB update is serial; 16/32/64 MiB updates expose at most 2/4/8 compression leaves. A 16 MiB-minus-one-byte call is entirely serial. An odd-size call or a small separately hashed header can reduce the alignment of later updates too.

These are source-derived scheduling ceilings, not promises of simultaneously running workers. The upstream standard incremental API keeps the correct chunk counters, flags and root reduction. Concurrently updating one hasher or concatenating independent chunk digests is incorrect.

The kernel experiment retained whole-file BLAKE3 and compared every text byte, hashing each chunk before comparing its overlapping text. Each sample uses a fresh locked stock-file view and fresh image view. All three images were independently checked to have no `.text` relocations, so **raw equality is sufficient only for this kernel experiment**. A runtime implementation still needs the complete relocation/plan transaction. Cache IO, application checks, patching and actual Chrome startup are excluded.

| Hash + full text equality, current 16 MiB fork threshold | Chrome 153 | Chromium 157 | DCHECK Chrome 159 |
| --- | ---: | ---: | ---: |
| One whole-file update, then comparison | 243.837 ms | 236.283 ms | 418.423 ms |
| 4 MiB windows | 460.737 ms | 479.399 ms | 802.325 ms |
| 16 MiB windows | 321.623 ms | 343.987 ms | 571.026 ms |
| 32 MiB windows | 256.090 ms | 274.282 ms | 467.267 ms |
| 64 MiB windows | 231.082 ms | 244.207 ms | 412.001 ms |
| 128 MiB windows | 229.251 ms | 246.607 ms | 409.393 ms |

Small-window locality alone did not compensate for lost parallelism. Large windows gave small, inconsistent gains. All digests matched the independently recorded whole-file identity; **222 bounded-range/chunk/mismatch self-checks passed**. CPU and aggregate page-fault observations are retained. Aggregate faults do not distinguish disk reads from soft mapping faults.

A second, separately preserved DLL varied the window and fork threshold together, keeping the same upstream digest implementation and automatic CPU budget. This tests whether restoring small-window parallelism makes locality worthwhile.

| Window / fork threshold | Chrome 153 | Chromium 157 | DCHECK Chrome 159 |
| --- | ---: | ---: | ---: |
| Whole file / 16 MiB | 262.804 ms | 223.503 ms | 403.832 ms |
| Whole file / 8 MiB | 226.700 ms | 215.533 ms | 391.477 ms |
| 4 MiB / 1 MiB | 264.114 ms | 233.867 ms | 421.812 ms |
| 16 MiB / 4 MiB | 252.412 ms | 219.355 ms | 424.479 ms |
| 32 MiB / 8 MiB | 241.774 ms | 222.565 ms | 417.045 ms |
| 64 MiB / 16 MiB | 238.947 ms | 229.295 ms | 427.404 ms |
| 128 MiB / 16 MiB | 241.448 ms | 233.983 ms | 410.875 ms |

Lowering the whole-file threshold to 8 MiB gave **3–14% lower kernel medians** across these three images. It is an additional candidate for complete-runtime measurement, not a shipped threshold choice. Jointly tuned chunking did not consistently beat that whole-file variant. All 189 observations, including warm-ups, retained exact file digest and full-text equality. Another **144 digest checks** passed at 1/4/8/16 MiB minus one byte, equal and plus one byte, including unaligned starts, budgets of three workers and concurrent callers.

The aggregate page-fault medians were effectively identical across window policies for each image. Chunking did not remove the need to touch all stock and live pages. A buffered ReadFile experiment could reuse already committed buffers and avoid fresh stock-view PTE faults, but adds copies and hasher-window bookkeeping; it remains unmeasured on both warm and cold storage.


Sources: [pinned update/subtree implementation](https://github.com/BLAKE3-team/BLAKE3/blob/f3149ec5bb5449af877ba20377a11008ff499fa2/c/blake3.c), [upstream C streaming advice](https://github.com/BLAKE3-team/BLAKE3/blob/f3149ec5bb5449af877ba20377a11008ff499fa2/c/README.md). Ordinary buffered/overlapped ReadFile on genuinely cold storage remains a distinct experiment; these mapped-view samples do not establish its result.

## More code is not yet justified for discovery

Two minimal changes after lazy trimming were tested: avoid constant initialization that `prefix` overwrites, and test numerical CFG edges before `isNoReturn` in shared `Program::follows`. All **90 full benchmark reports** matched, and their differential checks passed **489** and **819** assertions respectively. Neither showed consistent overall gains across the normal and diagnostic images. The diagnostic edge-first core improved, while normal images and unrelated stages slowed.

Background/cache drift and separate whole-program compiler/inlining/layout effects cannot be disentangled from these samples. Both remain unselected. The larger 16 KiB unique-predecessor index stayed an unbuilt draft. Do not add index maintenance on the strength of a theoretical operation count.

An unmeasured next option is to collect the two bounded anchors early and share one `.text` vector load between the core prescreen and reference filter. Preserve independent candidate ordering, per-target overflow, core/layout acceptance and all ambiguity. The CRX caller scan cannot join immediately because its target RVA is discovered later. Even the smaller actual single `.rdata` traversal needs a benchmark against the current optimized character searches.

## Additional checks changed the practical research plan

- **No supported prefault switch was found for these file views.** The SDK exposes SOFT_FAULT_PAGES, NONPAGED and 64K names, but a tiny read-only MapViewOfFile3/CreateFileMapping probe returned `ERROR_INVALID_PARAMETER (87)` for those combinations. Ordinary mapping succeeded with zero initially resident pages. This result applies to the tested ordinary file-backed views on this host, not all private allocation APIs or Windows versions.
- **SPGO is ready to evaluate without installation.** SPTAggregate/SPDConvert and the LBR/PMC providers are already present/configured in the installed MSVC/toolkit. Training a real release DLL and held-out launches is now a concrete option, but no SPGO speedup was measured here.
- **Merge two existing region walks before inventing an early token.** Allocation and text readability can potentially share one traversal, checking readability only where a returned region overlaps `.text`. Retain both predicates and error semantics. This is an unmeasured small follow-up; serial pre-comparison sweeps are already cheap, while post-preflight repeats cost more.
- **Mapped IO failures must be caught on the thread that reads.** A parent's handler does not catch `EXCEPTION_IN_PAGE_ERROR` inside a hash callback. Any future streaming/scheduling rewrite must join workers, restore budgets and decline incomplete identity before writes; explicit reads need correct short-read/cancellation lifetimes.
- **Earlier loader overlap requires stronger evidence.** A wrapper outside its own DllMain can still be called by an initializer holding the loader lock. LoadLibraryExW's hFile is reserved NULL, so a preopened file handle cannot force the supported loader to use that object. Prove the call site and file/module binding before moving work earlier.
- **Dynamic TLS remains unmeasured.** Compare static TLS, dynamic TLS with notifications enabled, and dynamic TLS with notifications disabled separately. Otherwise hash indirection cost and thread-loader savings are confounded.

Sources: [MapViewOfFile3](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3), [extended parameters](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-mem_extended_parameter), [SPGO](https://learn.microsoft.com/en-us/cpp/build/sample-profile-guided-optimization?view=msvc-170), [mapped-view failure handling](https://learn.microsoft.com/en-us/windows/win32/memory/reading-and-writing-from-a-file-view), [DLL startup rules](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices), [LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw).

The next production candidate is the independent page guard, with the one-region version the smallest and the batch version the strongest isolated guard result. Actual browser usable-window/extension readiness, p50/p95, peak memory, CPU and eventual cleanup must decide between them and any wider pipeline. Keep full identity, code validation, W^X, rollback and the 300,000-byte limit. No new dependency, tuning framework or persistent service was added.

Skipped production implementation/deployment and unselected-index builds. Actual browser, native x86/ARM64, controlled cold-storage and broader CPU/NUMA/ISA checks remain undone; snapshots retain the startup no-concurrent-writer assumption and complete-path gains vary with load.
