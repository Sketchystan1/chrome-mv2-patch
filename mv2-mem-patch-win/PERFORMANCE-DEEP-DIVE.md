Further research found another measurable improvement: a disposable native prototype reduced the **cached patch path from 381 ms to 253 ms**, about **34% less startup delay / 1.5× faster** on this host. The strongest new changes are balanced BLAKE3 work allocation and moving file-view cleanup after the patcher returns. A four-thread version reached **275 ms**, with a smaller CPU cost.

The 253 ms number measures when all verified instructions are installed and `Patch()` returns. Cleanup continues afterward. Counting through cleanup completion gives **381 → 307 ms**, a **19% reduction**. Both measurements matter: moving cleanup shortens the blocked startup path, but still consumes CPU and briefly retains the mapping. Actual Chrome launch must establish how much that helps the browser.

This is follow-up research against commit `8f56f5cc7f50573bc4b72157032cfc17194533fe`, dated November 11, 2026. Production runtime code and deployment DLLs were left unchanged. Prototypes, build scripts and logs are in `_scratch/perf-deep-dive-2026-11-11/`; reproducible inputs, artifact hashes and individual observations are recorded in [PERFORMANCE-DEEP-DIVE.json](PERFORMANCE-DEEP-DIVE.json). The [previous research](PERFORMANCE-RESEARCH.md) covers optimizations already implemented.

The balanced hash budgets, bounded deferred cleanup and one-entry trim cache have
since been implemented. The original eight-thread ceiling has since been removed;
hashing follows process affinity, eligible groups and default CPU sets. Core
placement belongs to the scheduler; see [threading research](PERFORMANCE-THREADING.md). CPU model
and host OS identifiers are omitted from reports. The implementation passed 8/8
x64 and 5/5 x86 tests, 23 complete frozen-report comparisons, two ARM64 analysis
comparisons and three isolated browser lifecycles. Current artifact identities and
validation are recorded in [AUTOSCAN-RESULTS.json](AUTOSCAN-RESULTS.json).

The default constraint for this study is the existing automatic discovery model and 300,000-byte limit. Complete patch prototypes keep whole-file BLAKE3, full loaded `.text` comparison with checked relocations, plan identity, branch direction, target and ordering checks, W^X transitions, post-write verification and rollback. More radical approaches are identified separately below.

**What was measured**

Measurements used four physical cores/eight logical processors and about 8 GiB visible RAM. AVX2 and AVX-512 were not exercised. Background applications remained running; available memory and scheduling varied. Neither the file cache nor the machine was reset.

The final experiment alternated the current implementation and both candidates in forward/reverse order, collecting **20 cache-hit observations per variant** after warm-up. Every observation mapped a fresh Chrome 153 image using `DONT_RESOLVE_DLL_REFERENCES`, checked all nine stock decisions, ran the native patch entry point, then checked all nine replacements. Chrome was never initialized or executed. Cache files used isolated directories. The original file's SHA-256 was checked afterward.

| Final alternating experiment | Current implementation, 4 threads | Balanced hashing + deferred cleanup, 4 threads | Balanced hashing + deferred cleanup, 8 threads |
| --- | ---: | ---: | ---: |
| Return from patcher | **380.968 ms** | **274.610 ms** | **253.079 ms** |
| Reduction in blocked patch time | — | **27.9%** | **33.6%** |
| Completion including cleanup | 381.036 ms | 333.000 ms | 307.209 ms |
| CPU time through cleanup | 562.500 ms | 601.562 ms | 750.000 ms |
| Identity stage | 176.651 ms | 120.459 ms | 94.320 ms |
| Cache/plan stage | 2.342 ms | 2.350 ms | 2.329 ms |
| Apply stage | 149.427 ms | 152.519 ms | 153.845 ms |

These are medians of separate columns; stage medians need not sum to the median total. CPU time adds work across threads. The eight-thread candidate used about **33% more CPU time** through cleanup; the four-thread candidate used about **7% more**. Cleanup completion uses a short polling loop, so that column includes observation overhead.

**1. Balance the hash tree before raising the thread cap**

The current [join hook](blake3_threads.cpp) uses a global count of available worker slots. A subtree that reaches the hook first can consume slots recursively. Another subtree then falls back to entirely serial compression, even though it represents a large share of the input. This explains why the earlier retained-map experiment found little difference between two and four threads.

The prototype gives each subtree a worker budget. A fork divides the budget between its children; the caller and callback restore their previous budgets afterward. The existing global worker limit and allocation-failure fallback remain. The underlying BLAKE3 compression, counters, flags and tree result are unchanged. The prototype uses a trivial `thread_local` value to carry the budget through upstream recursion.

| Retained mapping, balanced-budget experiment | Existing 4-thread hook | Balanced 4-thread hook | Balanced 8-thread hook |
| --- | ---: | ---: | ---: |
| 301.7 MB Chrome 153 hash | 98.3 ms | 67.6 ms | 55.35 ms |
| 535.5 MB DCHECK Chrome 159 hash | 171.5 ms | 128.3 ms | 92.9 ms |

The complete patch experiment also confirmed a gain before deferred cleanup: **378 → 316 ms** with four threads and **378 → 304 ms** with eight. This is the first implementation choice to take forward. More workers alone reached about 324–326 ms, while balanced four-thread work was faster with fewer workers.

A fixed fork threshold is less reliable. Four threads with a 128 MiB threshold reduced the 301.7 MB retained-map hash from 97.6 to 72.5 ms. On the 535.5 MB image the same setting only improved 180.9 to 172.1 ms; a 256 MiB threshold worsened it to 243.9 ms. BLAKE3 processes different-sized subtrees as input length changes. A threshold tuned for one file does not balance every subtree of another file.

Checks covered empty input, 1 KiB chunk boundaries, the 16 MiB parallel boundary, an irregular 32 MiB input, odd three-thread budgets and concurrent hashes. All digests matched the existing implementation. Native proxy/TLS behavior on every deployment architecture still needs validation.

Sources: [upstream tree implementation](https://github.com/BLAKE3-team/BLAKE3/blob/f3149ec5bb5449af877ba20377a11008ff499fa2/c/blake3.c), [threaded API and identical-result contract](https://github.com/BLAKE3-team/BLAKE3/blob/f3149ec5bb5449af877ba20377a11008ff499fa2/c/README.md).

**2. Include cleanup in the timing, then move eligible cleanup off the blocked path**

The runtime's [completion timestamp](autoscan_runtime.cpp) occurs before `View::~View()` calls `UnmapViewOfFile`. In the instrumented experiment, the difference between the reported internal total and return from the patcher was consistently about **49–50 ms**. A separate `OutputDebugStringA` probe took about **0.007 ms**, so logging did not explain that gap on this host.

Unmapping removes working-set entries and updates physical-page share counts. That can be significant for a fully touched 300 MB mapping. The cleanup prototype queues this operation only after verification and patching have finished. The callback owns the view until it unmaps it. A bounded slot prevents overwriting pending ownership; a busy slot or failed submission retains synchronous cleanup. A counted module reference is released with `FreeLibraryWhenCallbackReturns`, keeping callback code loaded until it returns. No caller's stack storage escapes.

The paired cleanup experiment reduced return time from **351 → 280 ms** at four threads and **325 → 248 ms** at eight. The final alternating experiment above is the stronger combined comparison. Every queued unmap completed, with zero recorded unmap failures; the forced busy-slot case patched correctly and used synchronous cleanup.

This moves work, rather than removing it. A real launch might contend with the worker for memory-management locks or CPU. Test Chrome's first usable window, memory peak and subsequent page faults before choosing this as the release behavior. Queue-allocation failure and DLL-unload races also need dedicated integration checks.

Sources: [unmap behavior](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile), [callback submission](https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-trysubmitthreadpoolcallback), [module reference counting](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw), [release after callback return](https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-freelibrarywhencallbackreturns).

**3. Cache one exact function range during discovery**

[Boundaries::trim](boundaries.hpp) decodes the entire function to remove padding without mistaking immediate bytes for `90`/`CC` instructions. `find()` can repeat that work for several candidates in the same function. A one-entry cache keyed by the exact **untrimmed begin/end pair**, scoped to one immutable `PeImage`, avoids that repeated decode. It does not infer a boundary from containment or reuse another image's result.

Six disposable scanner variants ran five analyses per mapping in forward/reverse order over three images. First-touch observations are retained but excluded from the table: **eight warm observations per variant per image**. All **180 complete reports** matched the current scanner after removing diagnostic hash fields, including decisions, fields, counts, optional outcomes and unresolved candidates.

| Warm analysis only | Current | One-entry trim cache | One-entry cache + SIMD mask draining |
| --- | ---: | ---: | ---: |
| Chrome 153.0.8010.37 x64 | 602.8 ms | 494.1 ms (**18.0% less**) | 465.1 ms |
| Chromium 157.0.8103.39 x64 | 579.1 ms | 514.4 ms (**11.2% less**) | 475.0 ms |
| Chrome 159.0.8148.1 DCHECK x64 | 1,130.0 ms | 872.8 ms (**22.8% less**) | 814.8 ms |

For Chrome 153, bytes passed through trimming fell from **17.5 MB to 5.7 MB**. For DCHECK Chrome they fell from **47.6 MB to 15.8 MB**. A 16-entry cache saved only a few additional trim calls and did not consistently beat the single entry. Start with one entry.

This helps first discovery and cache misses. It has no direct benefit when a protected plan is already cached. x86 and ARM64 still require their own parity and runtime checks; leaf and x86 recovery must continue to run normally before caching the exact trim input.

**4. Drain SIMD masks, but keep the measured payoff in proportion**

The current RIP-relative reference search finds the first matching operand byte in a vector, then starts another overlapping vector search. The prototype processes every set bit in that vector before moving to the next block. Each surviving candidate still gets the same opcode, displacement, instruction-length and reference checks.

Mask draining alone improved total discovery by only **1–2%** here. The combined cache/draining variant was 18–28% faster, but most of the demonstrated standalone gain belongs to trimming. Treat draining as a secondary improvement, and check real inputs and tails. It should preserve candidate ordering and overflow behavior.

Changing `PeImage::code()` to translate `.text` directly, bypassing its general section lookup, did not improve these measurements. A hand-written SSE2 equality loop was also slower than UCRT `memcmp`: **57.3 versus 45.5 ms** on retained text. These experiments do not justify extra code.

Sources: [packed-pair implementation](https://github.com/BurntSushi/memchr/blob/master/src/arch/generic/packedpair.rs), [why excessive prefilter candidates can slow a search](https://github.com/BurntSushi/memchr/blob/master/src/memmem/searcher.rs).

**5. Overlap whole-file identity and loaded-code validation**

This is the largest remaining architectural opportunity after the small changes. The final eight-thread prototype still spends about **94 ms identifying the file**, then **154 ms applying the plan**, mostly including loaded-code verification. Those stages currently run in sequence.

The difficulty is that the cache filename depends on the content digest. Use metadata only to locate a *candidate* protected plan, then run hashing and preflight validation concurrently. The file stays locked. The candidate becomes usable only after the full digest matches its recorded identity, the scanner identity matches, and every validation check succeeds. A stale hint causes normal discovery. No instruction may be changed before that join.

```text
bounded protected candidate lookup using a file/path hint
            /                                   \
  full-file BLAKE3                  complete loaded-code preflight
            \                                   /
     join; verify digest, scanner identity and preflight
                 then perform the existing write/flush/restore checks
```

The disposable pipeline benchmark overlapped **hashing and stock `.text` equality** on retained mappings. Four-thread hashing plus one comparison worker improved **188.5 → 112.3 ms**. Eight-thread hashing plus two comparison workers reached **77.8 ms**. This establishes that overlap can help; it omits plan IO, full PE/relocation/application checks and fresh-view page faults, so it is **not a complete patcher timing**.

With the current eight-thread stage medians, perfect overlap would put the main identity/validation portion near the larger stage, about 154 ms, plus other work. That is an ideal scheduling estimate, not a promised 155 ms patcher. Shared bandwidth, page-fault locks and extra workers can erode the gain.

A more involved version fuses comparison with the hash's input traversal. Chrome 153 has 301.7 MB of file data and 256.8 MB of text. Separate hashing and two-sided comparison read about **815.3 MB** logically. Reusing stock bytes from cache can reduce DRAM traffic toward **558.5 MB**, about 31% less. It does not reduce the whole-file disk input requirement. Preserve BLAKE3's official API/tree result and the complete relocation/patch exception rules.

**Remaining catalogue: improvements that fit the current model**

“Unmeasured” means a reasoned opportunity, not an established gain. Cache misses include a changed Chrome binary, a changed scanner and a missing/corrupt plan.

| Approach | Where it helps | Finding / next experiment |
| --- | --- | --- |
| Balanced subtree budgets | Every full hash | Measured; prioritize before adding workers. |
| Up to eight hashing threads | Every full hash | Fastest measured on this host; more CPU. Respect process CPU availability and keep serial fallback. |
| Size-aware fork threshold | Every full hash | Measured threshold sensitivity; avoid a single file-size assumption. |
| Cache processor availability once per hash | Scheduling overhead | Small potential saving over querying at each fork; must respect affinity/groups. Unmeasured. |
| Reuse work objects or submit a fixed set of coarse tasks | Hash scheduling | Could reduce allocation/submission overhead and enforce balanced work. Measure against the simpler budget hook. |
| Avoid unnecessary `CallbackMayRunLong` adjustments | Hash scheduling | Could reduce pool bookkeeping; must still prevent starvation while joins wait. Unmeasured. |
| Defer file-view unmapping | Every successful patch | Measured blocked-path improvement; retain ownership, fallback and eventual completion. |
| Defer diagnostic output | Debugger-heavy launches | Useful only if output blocks. Local output was effectively negligible. |
| Measure resource destruction explicitly | All benchmarks | Necessary: current runtime stage totals omit a material cleanup cost. |
| Read a candidate plan before full hashing | Cache hits | Enables overlap without treating metadata as content identity. Requires bounded/authenticated lookup. |
| Split preflight validation from commit | Cache hits | Enables concurrent hash/validation. Keep the final write, flush, restoration and rollback sequence. |
| Fuse hash and comparison by chunks | Cache hits | Potential stock-data cache reuse. Relocations, legal patch bytes and mismatch handling make this more complex. |
| Collect bounded mismatches before a plan is known | Cache hits | Another way to overlap without early writes. Compare every byte; unexpected/overflowing differences fall back or decline. Unmeasured. |
| Parallel `memcmp` over disjoint spans | Code validation | Four comparison workers improved retained equality 45.5 → 36.0 ms. Combining many compare/hash workers was often slower than one compare worker. |
| Cache one exact trim result | Discovery | Measured 11–23% analysis improvement; small change. |
| Cache a validated runtime-function table entry | Discovery | Can avoid repeated binary searches for nearby candidates. Restrict to proven table ranges; do not memoize heuristic leaf bounds by containment. |
| Reuse an already complete `Program` for the same range | Optional discovery | Core already does this in places. Optional recognizers can rebuild a range. Preserve `noReturns`, decode failure and complete-state semantics. |
| Build predecessor lists once per decoded program | Provenance analysis | Several queries scan all nodes repeatedly. A bounded reverse-edge index can reduce repeated work, but first profile how much remains hot. |
| Cache immutable provenance/constant query results | Optional discovery | Potential repeated-query saving. Key by program generation, PC, register and query parameters; failures and limits must remain meaningful. |
| Clear only the bounded instruction-occupancy range | Program decoding | Could avoid zeroing 64 KiB for a small function. Do not remove initialization from generic `FixedList` storage. Likely modest. |
| Generation marks instead of repeated occupancy clearing | Program decoding | Adds wraparound/state complexity; consider only if clearing proves hot. |
| Scan references for both optional literals together | Optional discovery | Both scan the same large `.text`. A small batched target set can share filtering/decoding. Preserve per-target hit limits and ambiguity. Strong unmeasured candidate. |
| Search both names in one `.rdata` pass | Optional discovery | Avoids duplicate traversal; two fixed names do not need a large pattern engine. |
| Use rare literal bytes or packed pairs | Literal search | Could reduce full string comparisons. Keep complete name/NUL checks. The current first-character search is already cheap. |
| Drain all vector-mask candidates | Reference search | Measured modest gain; avoid repeated overlapping loads. |
| AVX2/AVX-512 scanner filters with dispatch | Discovery | Could widen the current 16-byte filter. This host cannot validate them; preserve CPU/OS checks and SSE fallback. |
| ARM64 NEON opcode/reference filters | ARM64 discovery | Fixed-width instructions suit vector masks. Requires native ARM64 measurements and scalar parity. |
| Adaptive prefilter effectiveness | Discovery | Stop spending on filters that produce too many candidates. Must keep a semantically equivalent complete search; use measured candidate density. |
| Parallel core chunks | Discovery | Each worker needs its own program/solver state and exact candidate ownership. Merge counts, unresolved issues and layout evidence without suppressing ambiguity. |
| Run CRX discovery concurrently with core discovery | Cache misses | CRX analysis is largely independent. Avoid shared mutable program/trim-cache state; failed core plans still decline. |
| Parallel optional analyses after core layout is known | Cache misses | Possible wall-time reduction, with additional `.text` bandwidth and worker storage. Measure the merged full report. |
| Walk text relocations once across all decision gaps | Mostly x86 apply | x86 has millions of real code relocations. Keep malformed/straddling/unsupported relocation handling and a fallback for unsupported ordering. |
| Validate monotonic relocation blocks, then index ranges | Apply | Can avoid revisiting block headers. Do not assume all input tables are sorted. x64's existing block skip already removes most entry work. |
| Compare relocated words in batches | Mostly x86 apply | Could reduce millions of tiny comparisons. Preserve width, wraparound and non-relocated-byte comparisons. |
| Coalesce adjacent changed protection pages | Commit | Could reduce system calls, but only across pages with compatible original protection and complete rollback ownership. Few current sites limit payoff. |
| Flush only changed instruction ranges/pages | Mostly ARM64 commit | The API accepts a range. Retain flushes after writes and rollback; native cache-coherency tests are required. |
| Cache system page size | Commit | Tiny saving; not a reason to add a framework. |
| Cache the scanner's content identity within a process | Repeated calls | Small saving; normal startup patches once. Do not substitute a timestamp for the scanner hash. |
| Stable semantic scanner cache version | Scanner updates | Could preserve plans across logging/proxy-only changes. Must cover every change that affects recognition, application or protocol; a missing version bump risks stale plans. |
| Protected negative-result cache | Unsupported images | Repeated deterministic declines currently rescan. Cache only verified deterministic failures bound to full image/scanner identity; never persist transient IO errors or timeouts as permanent failure. |
| One discovery per image during simultaneous launches | Concurrent cache misses | A bounded single-flight mechanism can avoid duplicate helpers. Recheck cache after waiting; keep timeouts and failure recovery. |
| Prepare the plan during installation | First launch | Moves full scan/cache creation before startup, using the final DLL identity and correct user DPAPI scope. |
| Prepare the next plan after a Chrome update | First launch after update | Requires reliable update detection and exact-file locking; unknown versions still use the helper fallback. |
| Start read-only work before the intercepted load finishes | Initial launch | Could overlap with the loader. Resolve the exact file, work outside `DllMain`, and join before Chrome can execute patched routines. May compete with loader IO. |
| Reply before durable cache persistence finishes | Cache misses | Can overlap optional persistence with parent validation only if the exit/reply contract is redesigned. Moving a write alone does not hide it while the parent waits for process exit. |
| MSVC PGO on the actual DLL | CPU-bound discovery | Prior scanner experiments gave modest gains. Train full runtime/scanner workloads, not only a hash or one Chrome layout. |
| MSVC SPGO on release binaries | CPU-bound discovery | Uses sampled hardware profiles for layout/inlining. Validate tool/hardware support and representative data; published generic speedups are not this patcher's measured result. |
| Target-specific compiler scheduling (`/favor`) | CPU-bound discovery | Hardware-specific experiment; the blend default supports varied machines. Measure rather than imposing one vendor's tuning. |
| Keep cold error paths away from hot decode loops | CPU-bound discovery | Let PGO establish the hot/cold layout first. Manual duplication may increase instruction-cache pressure and DLL size. |

Sources for this catalogue: [multi-pattern/prefilter design](https://github.com/BurntSushi/aho-corasick/blob/master/DESIGN.md), [CPU Sets](https://learn.microsoft.com/en-us/windows/win32/procthread/cpu-sets), [SPGO](https://learn.microsoft.com/en-us/cpp/build/sample-profile-guided-optimization?view=msvc-170), [MSVC scheduling options](https://learn.microsoft.com/en-us/cpp/build/reference/favor-optimize-for-architecture-specifics?view=msvc-170), [instruction flush ranges](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache).

**Storage and hardware options: test on the workload that can benefit**

| Approach | Practical assessment |
| --- | --- |
| Whole-range `PrefetchVirtualMemory` | Prior fresh-map, disk-warm experiments regressed from about 179–180 to 201–202 ms. A genuinely disk-cold case can differ. The hint preloads physical memory, not the process working set. |
| Prefetch a short distance ahead | Smaller outstanding ranges might improve cold IO without loading the entire image at once. Include hint cost and peak memory in the measurement. |
| Buffered `ReadFile` into reusable aligned buffers | Can change page-fault/copy costs and make sequential-read hints useful. Include buffer allocation, copying, hashing, validation and disposal. |
| Overlapped double-buffered reads | Could hide disk latency behind hashing. Streaming update sizes affect BLAKE3 parallelism; keep exact digest parity and read-error handling. |
| Unbuffered IO | Needs size/offset/buffer alignment and tail handling; bypassing a useful cache can hurt. Does not eliminate loaded-code validation. |
| Add `FILE_FLAG_SEQUENTIAL_SCAN` to the current mapping path | No demonstrated win. Microsoft's cache-hint explanation applies to `ReadFile` and distinguishes memory-mapped access; it is not a substitute for a mapped-IO experiment on current Windows. |
| Touch one byte per page before hashing | Can move fault cost earlier but does not remove it. A separate warm-up must be counted unless deliberately done outside startup. |
| Keep a file mapping across operations | Can avoid repeated setup/PTE population in a long-lived process. Normal startup creates a new process; retaining a large view changes memory and file lifetime. |
| Windowed mappings | Bound working-set pressure but add map/unmap calls and complicate PE/relocation access and parallel hashing. Unmeasured. |
| Large pages | Ordinary file/image mappings cannot simply enable `SEC_LARGE_PAGES`; documented support is for pagefile-backed mappings. Copying into large pages adds privileges, RAM and copy cost. |
| `VirtualLock` | Keeps pages resident but does not make the initial IO free, and can fail under memory limits. Do not lock hundreds of MB by default. |
| NUMA placement and local workers | Useful on multi-socket systems if remote reads dominate; first-touch/shared file pages complicate placement. Unmeasured on this single-socket host. |
| Prefer available performance cores on hybrid CPUs | Can reduce a slow subtree tail. Respect process CPU restrictions and test P/E-core and SMT combinations. No hybrid hardware was used here. |
| SMT versus physical-core worker counts | Eight hashing threads helped these measurements. Transfer neither the cap nor speedup directly to other CPUs. |
| AVX-512 versus AVX2/SSE kernels | BLAKE3 already dispatches upstream backends. Frequency effects vary by CPU and instruction mix; wider code needs whole-path measurements on supporting hardware. |
| GPU hashing/comparison | A warm GPU might offer high throughput, but initialization, transfers, reduction, fallback and runtime dependencies must fit the startup/DLL budget. No measured win here. |
| DirectStorage | Designed for high-throughput game storage, including many small reads. For one mapped DLL, setup and integration may exceed savings; it does not replace content/loaded-code checks. |
| Lower memory priority for disposable scan pages | Could reduce later cache pressure but can worsen the immediate scan under load. Measure browser launch plus subsequent work, not only scanner throughput. |
| Foreground/thread-local scheduling adjustments | Might help under contention, but cannot fix redundant work. Avoid realtime priority and global machine-policy changes. |
| WPR/WPA traces | Next diagnostic step for actual launches: separate hard faults, waits, CPU, loader IO and cleanup contention. QPC alone cannot attribute soft versus hard faults. |

Sources: [prefetch semantics](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-prefetchvirtualmemory), [cache-hint scope](https://devblogs.microsoft.com/oldnewthing/20120120-00/?p=8493), [mapping/large-page rules](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw), [DirectStorage](https://learn.microsoft.com/en-us/windows/win32/dstorage/dstorage-portal), [WPR/WPA](https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/support-tools-xperf-wpa-wpr). [Cloudflare's AVX experiment](https://blog.cloudflare.com/on-the-dangers-of-intels-frequency-scaling/) is historical evidence, not a universal rule for newer CPUs.

**The fastest architectures need stronger proofs or changed constraints**

| Approach | Possible saving | Required condition / limitation |
| --- | --- | --- |
| Reuse a digest while an exact file remains continuously immutable | Avoid repeated full hashes | A trusted owner must hold the exact file object/lock, bind consumers to it and invalidate before writers proceed. A persistent filename record is insufficient. |
| Share a verified digest between simultaneously running browser processes | Avoid duplicate identity work | Requires authenticated ownership, exact file identity, race-safe lifetime and a fallback when the producer is gone. Helps simultaneous profiles more than a clean restart. |
| A persistent broker retaining verified files/plans | Move identity/discovery outside launches | Adds a process, protocol, update coordination and memory lifetime. It can be fast, but is a deployment change rather than a small DLL optimization. |
| File ID + size + timestamp cache | Very cheap lookup | Suitable as a hint. Timestamps are mutable and have delayed-update guarantees; these fields do not establish content equality. |
| NTFS USN/change-journal reuse | Skip unchanged content work | Needs journal continuity, file identity, writer coordination, mapping-write treatment, replacement/reparse handling and permission/filesystem fallbacks. A single last-USN comparison is not a general proof. |
| Read/RH oplock invalidation | Cache file content efficiently | Some break notifications are advisory and do not wait for acknowledgement before writes. Reuse requires a complete race-safe protocol, not just an event handler. |
| Compare only private/COW loaded pages | Avoid most text reads | `MEM_IMAGE` does not mean unmodified. Even the Shared bit needs resident-page handling and proof that the mapped image corresponds to the exact verified file object. There is no drop-in byte-equality proof here. |
| Compare against a second `SEC_IMAGE_NO_EXECUTE` view | Potential loader-layout reuse | Needs file-object, relocation and page-sharing analysis. This mapping attribute does not authenticate equality of the existing loaded image to the stock file. |
| Trust an updater's digest/change map | Avoid duplicate hashing or update work | Must authenticate the producer, hash scope, exact extracted file and all write/replacement steps. A package digest is not automatically a `chrome.dll` digest. |
| Merkle/chunk digest cache across updates | Rehash only changed chunks | Needs a trustworthy change map or uninterrupted immutability. Without it, discovering which chunks changed still requires reading the input. |
| Signed precomputed plans from a release service | Eliminate first local discovery | Requires an authenticated producer and offline/helper fallback. It changes the plan trust/deployment model and resembles a generated plan distribution system. |
| Hash only `.text` | Reduce hash input | Changes identity coverage; `.rdata` and other file contents influenced discovery. Not the current whole-file contract. |
| Use Authenticode/WDAC identity instead of flat-file identity | Potential reuse of platform checks | Authenticode omits checksum/certificate-related data and has different coverage/trust semantics. Signature verification may also add chain/revocation work. |
| Use xxHash/CRC instead of BLAKE3 | Faster non-cryptographic identity | Changes the adversarial collision model. CRC/xxHash can be preliminary hints, not substitutes for the current cryptographic identity. |
| Skip full loaded-text comparison and check sites only | Remove most apply work | Gives up detection of unrelated loaded-code changes; it is a materially weaker validation contract. |
| Accept old RVAs/nearby matches after an update | Faster local discovery | Can miss new/ambiguous enforcement bodies elsewhere. If the full digest is identical, the existing cached plan already supplies the addresses. |
| Patch the browser file once per version | Almost no repeated patch work | Changes the signed disk image, update/restore behavior and potentially DRM or platform trust. This project currently leaves that file unchanged. |
| Replace Chrome with a build that retains MV2 | Remove the patcher | Changes the browser/deployment goal. Useful only if that is an acceptable product choice. |
| Kernel/global image-cache modification | Potential global reuse | Requires a driver and a different trust/deployment model; adds signing, maintenance and process-isolation concerns. No implementation is proposed. |

Sources: [timestamp guarantees](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times), [journal continuity](https://learn.microsoft.com/en-us/windows/win32/fileio/using-the-change-journal-identifier), [accumulated journal records](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journal-records), [oplock details](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock), [COW reporting](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery), [working-set query](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-queryworkingsetex), [Authenticode coverage](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#appendix-a-calculating-authenticode-pe-image-hash), [xxHash's stated model](https://github.com/Cyan4973/xxHash/blob/dev/README.md).

**Approaches that already have an answer**

| Approach | Decision |
| --- | --- |
| Rewrite the scanner in Rust/C/assembly | It is already native C++; upstream assembly handles the hottest hash kernels. Solve scheduling and repeated work first. |
| Switch to Clang without profiling | Previous full-report experiments were close to MSVC. No demonstrated overall deployment advantage. |
| LLVM BOLT on this Windows DLL | Upstream BOLT accepts x86-64/AArch64 ELF, not this PE DLL. MSVC PGO/SPGO are applicable routes. |
| Hand-write replacement cryptographic compression | Existing vetted assembly is fast; the new gains required no crypto rewrite. |
| Add a general pattern/solver dependency | Two literals and bounded predicates do not justify a large engine or abandoning the 300 KB limit. |
| More complicated SIMD branch masks by default | Previous experiments increased normal-image CPU time. This follow-up also shows tiny standalone gains for mask draining. |
| Hand-written SSE2 equality instead of UCRT | Measured slower. |
| Direct `.text` translation as a speed change | Measured no improvement. |
| Increase the trim cache to 16 entries | Little additional reused work; inconsistent improvement. One entry solves the main repeated decode. |
| Remove the helper's 25 ms wait | It is a timeout that wakes on process exit, not a fixed delay. Cached plans already bypass helper launch. |
| Move cache write after the reply without changing the wait contract | Parent still waits for successful helper exit. The persistence work remains on that path. |
| Optimize DPAPI/short SHA checks first | Final cache/plan medians were about 2.3 ms: less than 1% of the current path. Keep authentication and persistence guarantees. |
| Disable antivirus or change global power settings | No implementation gain demonstrated; those machine-policy changes are outside this study. |

Source: [BOLT input requirements](https://github.com/llvm/llvm-project/blob/main/bolt/README.md). Other decisions are supported by the recorded experiments and [previous research](PERFORMANCE-RESEARCH.md).

**Order of work and the code each change must reach**

| Priority | Change | Integration and checks |
| --- | --- | --- |
| 1 | Balanced BLAKE3 budgets; select measured worker cap | `blake3_threads.cpp`, hash callers and `hash_test.cpp`; cross-build x86/x64/ARM64, concurrent/odd-budget/threshold vectors, actual proxy TLS/ABI and size checks. |
| 2 | Report cleanup time and evaluate deferred cleanup | `autoscan_runtime.cpp` ownership/trace path; callback completion, busy/submission-failure fallback, module unload, repeated startup and actual browser memory/launch tests. |
| 3 | One-entry exact trim cache | `boundaries.hpp`, core/optional users and module/scanner tests; preserve immediate-padding, leaf, x86 recovery, malformed unwind and full matrix reports. |
| 4 | Batch optional reference scans | `references()`, `installVerifier()` and `crxDownload()` in `autoscan.cpp`; retain per-literal caps, ambiguity, ordering and complete matrix parity. |
| 5 | Candidate-plan lookup + hash/preflight overlap | `StockImage`, `Patch`, `ApplyPlan`, cache lookup/protocol and runtime tests. Same metadata with changed non-text bytes must never authorize the old plan; join before any write. |
| 6 | PGO/SPGO and wider ISA experiments | `CMakeLists.txt`, architecture-specific objects, build/release validation; profile representative images and full browser lifecycles, retaining dispatch/fallbacks and the size limit. |
| 7 | Negative caching or update-time preparation | Cache/helper and installer/update integration; distinguish deterministic declines from transient failures and preserve user DPAPI scope. |
| 8 | x86 relocation pass / ARM64 flush ranges | `autoscan_apply.cpp` and native memory tests; real relocations, boundary crossings, W^X, rollback, architecture-specific coherency and full image parity. |

The smallest useful implementation is priorities 1–3. The fastest measured version here uses eight hashing threads plus deferred cleanup. The next substantial experiment is complete hash/preflight overlap; batched reference scanning is the most promising bounded discovery follow-up. Actual browser tracing should determine whether deferred cleanup reduces time to a usable window or shifts contention into later startup.

Skipped: deployment to installed browsers, another language/crypto rewrite and the
unmeasured catalogue variants. Cold boots, AVX2/AVX-512 hardware and native ARM64
remain unchecked; eight hashing threads add CPU demand, and deferred cleanup
briefly retains the mapping.
