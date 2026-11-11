The Windows auto-patcher now uses native SIMD searches, parallel BLAKE3 hashing, relocation filtering and a persistent protected plan cache. The measured cached patch path fell from **2,139 ms to 379 ms**, about **5.5× faster**, on this host. A language rewrite did not offer the best return: the patcher already runs as native C++, and its hottest hash kernels now use the upstream assembly implementations.

Research and local release validation were completed on November 11, 2026, against source commit `aba80822c36286a2aaf8df6762849483cb8870aa` plus the working changes. The user increased the exclusive DLL/scanner size limit from 150,000 to **300,000 bytes**. Exact artifact hashes, raw measurements, source identity and validation results are in [PERFORMANCE-RESEARCH.json](PERFORMANCE-RESEARCH.json) and [AUTOSCAN-RESULTS.json](AUTOSCAN-RESULTS.json).

**What the measurements establish.** These are patcher timings, not a claim that Chrome's complete launch is 5.5× faster. The measurements used four physical cores/eight logical processors and roughly 8 GiB RAM. Background applications stayed running. File-cache state and CPU scheduling varied; neither the Windows file cache nor the machine was reset. Reported medians describe these samples, not a portable latency guarantee or a controlled cold-boot result.

| Operation | Baseline | Selected approach | Evidence |
| --- | ---: | ---: | --- |
| Complete cached native patch path, Chrome 153 | 2,139 ms | 379 ms | 15 cache-hit observations per implementation; every decision checked after application |
| Full 301.7 MB content hash, retained mapping | BLAKE3 serial 187 ms | Windows parallel BLAKE3 101 ms | 20 observations per implementation; digest matches independent Rust and official vectors |
| Full-file hash provider experiment | Windows SHA-256 1,682–1,744 ms | Upstream BLAKE3 assembly 183–185 ms | Alternating providers over one mapping; three assembly samples |
| Parent cache read | Existing helper cache reuse required process launch | Typically 2–5 ms in browser traces | Protected plan read in the parent after content hashing |

The complete native patch experiment uses research-only exports around the production entry points and maps/relocates Chrome without initializing or executing it. Each observation creates a fresh loaded-image mapping, uses an isolated cache directory, checks every final patch byte and confirms the stock file's SHA-256 is unchanged. The baseline is the frozen source rebuilt with the same MSVC compiler. The 379 ms pool median and the baseline median were collected in separate alternating experiments; raw observations and ordering are retained. The first discovery/cache-write observation for each implementation is excluded from the cache-hit median. This is stronger than timing a hash or scanner alone, but actual browser launch involves more work.

**Discovery improved across normal and diagnostic layouts.** Disposable scanners execute five analyses over each retained mapping. Variants ran in forward and reverse order, producing ten observations per variant per image. All 150 reports from the five main variants matched the frozen scanner exactly, including addresses, patch bytes, inferred fields, candidate counts and optional outcomes.

| Image | `/O1 /Os /Oi` analysis median | `/O2` with selected filters | Reduction |
| --- | ---: | ---: | ---: |
| Chrome 153.0.8010.37 x64 | 1,735 ms | 663 ms | 62% |
| Chromium 157.0.8103.39 x64 | 1,767 ms | 618 ms | 65% |
| Chrome 159.0.8148.1 DCHECK x64 | 2,934 ms | 1,286 ms | 56% |

These analysis measurements exclude hashing. The diagnostic CLI still computes truthful SHA-256 plus BLAKE3, while the runtime computes only BLAKE3 for the large browser image. Repeated diagnostic CLI calls therefore do not measure runtime plan-cache hits and should not be used as a browser-startup benchmark.

**The selected changes are small and cover the complete path.**

1. Compile C++ and the common BLAKE3 code with `/O2`, retaining whole-program optimization and dead-code elimination. The larger size allowance permits all four x64 assembly variants. x86 intrinsic objects retain their separate ISA settings and stay out of cross-file inlining; ARM64 uses NEON. The default build requires no training profiles.
2. Screen core candidate bytes in 16-byte SSE2 groups on x86/x64. Screen x64 RIP-relative operand bytes similarly. Literal searches find the first character quickly, then compare the complete bounded name, including its NUL. Direct-call searches use `memchr` and a checked raw displacement before decoding. Every surviving candidate still passes the existing decoder, function-boundary, provenance and predicate checks; ambiguity detection remains.
3. Hash the whole locked stock file with the pinned BLAKE3 implementation. A Windows thread-pool adapter supplies its existing parallel join hook, with at most three extra workers for subtrees of at least 16 MiB. It joins callbacks before caller storage expires and falls back to serial work if allocation fails. There is no oneTBB runtime dependency and no new cryptographic compression implementation.
4. Skip relocation entries in blocks that cannot overlap the current comparison span. Block headers are still validated. Widened arithmetic includes a relocation crossing the page boundary, and the existing relocation adjustment and full loaded-code comparison remain. The Chrome 153 x64 image has 973,325 nonpadding relocation entries and none in `.text`; the former code revisited those entries for each patch gap. x86 still checks its millions of actual code relocations.
5. Read a protected cached plan in the parent before starting a helper. On a miss, keep the existing isolated helper and its 30-second deadline. Discovery stays outside the browser and all work stays outside `DllMain`.
6. Replace same-logon memory protection with user-scoped persistent DPAPI. Protected input is bounded to 4 KiB; the decrypted size, checksum, browser BLAKE3, scanner SHA-256 and protocol are checked. Writes retain flushes and atomic replacement. API-owned buffers are freed. Missing/corrupt/incompatible cache data causes discovery.

The private protocol is now 5, still 1,532 bytes with at most 64 sites. SHA-256 remains available and correctly named in diagnostic output, scanner identity and small cache checksums; runtime browser identity is explicitly named `blake3`. Changing the DLL changes its scanner hash and prevents reuse of old plans. No filename/version/timestamp shortcut replaces content hashing. Full loaded `.text`, patch direction, stock instructions, targets, ordering, protection restoration, mixed-state detection and rollback checks remain enforced.

**Language, assembly and compiler experiments.**

| Candidate | Result | Decision |
| --- | --- | --- |
| MSVC `/O1`, `/O1 /Oi`, `/O2` | `/O2` plus bounded filters won on the normal layouts; code growth fits 300 KB | Ship `/O2` |
| Clang 22.1.3 with ThinLTO | Analysis medians 681/641/1,281 ms versus MSVC 663/618/1,286 ms | Keep the existing MSVC build |
| MSVC PGO | Three representative training images; all reports matched. Further alternating samples improved 617→590 ms and 1,165→1,101 ms, while shrinking the experimental EXE | Keep as an optional first-use optimization; no PGO DLL was released or browser-validated |
| Rust BLAKE3 | Serial median 242 ms; 2/4/8-thread medians 131/77/62 ms; all whole-file digests matched C | Demonstrates parallelism, not a reason to rewrite the scanner; research EXE alone is 285,184 bytes |
| Upstream x64 assembly | 183–185 ms in the provider comparison, versus portable C 908–935 ms | Ship vetted upstream assembly with runtime dispatch |
| All-C SIMD backend under size flags | Experimental DLL grew to 193,024 bytes versus 175,616 with all assembly | No size advantage; keep assembly |
| Windows `CreateThread` adapter | Native cached patch median 388 ms in its paired pool comparison | Thread pool simplified completion handling and gave a small gain |
| Windows thread pool | Paired cached median 379 ms; retained-map hash median 101 ms | Ship this adapter |
| More complex SIMD opcode/branch masks | Identical reports, but normal-image CPU medians rose from 656 ms to 727–734 ms | Drop them; extra vector work outweighed filtering |
| OpenSSL SHA-256 | Roughly 1,000–1,083 ms versus CNG 1,682–1,744 ms in the provider comparison | Useful evidence, but a slower runtime identity path and unnecessary deployment dependency |
| SHA-512 / BLAKE2b-256 | Roughly 1,035–1,043 ms / 1,967–1,991 ms | BLAKE3 was faster here |

The earlier 150 KB limit prevented the all-assembly deployment DLL from passing its size check. The final release builds are **215,040 bytes x64**, **228,352 bytes x86** and **153,600 bytes ARM64**. All include the selected runtime path. There is no handwritten replacement solver or assembly patcher.

**Non-obvious approaches and remaining opportunities.**

| Approach | Finding and practical limit |
| --- | --- |
| Prefetch mapped bytes | Tested fresh mappings in alternating order, with hint time included. No-hint medians were 179–180 ms; `PrefetchVirtualMemory` raised them to 201–202 ms. Do not enable it by default. A genuinely cold disk workload still needs its own experiment. |
| Eight hashing threads / SMT | Rust's eight-thread result beat four threads on this machine, but the native adapter's four-thread cap keeps resource use bounded. Retune the actual full startup path on newer CPUs rather than transferring a hash-only result. |
| Faster AVX2/AVX-512 candidate screening | Hash dispatch already includes these upstream backends. Wider scanner filters need measurements on supporting hardware; this host executes SSE paths. |
| Hashing only `.text` or changed metadata | Saves input work by changing identity coverage. The implementation continues to hash the full stock file and validate all loaded code. |
| File IDs, timestamps or NTFS USNs | Metadata is not content identity. A sound USN cache needs journal continuity, writer coordination, replacement/reparse handling and filesystem fallbacks. File timestamps can lag writes; this was not substituted for hashing. |
| ReadFile buffers / unbuffered IO | Different copy, page-fault and alignment costs; no demonstrated win over the current mapping. Unbuffered reads and sequential-read flags are not a substitute for measuring mapped IO. |
| Large pages / VirtualLock | Privilege, alignment and memory-pressure costs; no measured startup benefit on the 8 GiB host. |
| Parallel optional analyses | Could overlap discovery stages, but needs separate mutable `Program` storage and a checked merge. It only helps cache misses and competes for memory bandwidth. |
| Overlap hashing with discovery | Content identity determines whether discovery is needed. Starting both speculatively spends CPU on valid cache hits and changes the helper protocol. |
| Batch literal-reference indexing | Could avoid repeated text scans, but the selected screening already removes much of their cost. Add an index only with a measured remaining bottleneck. |
| Cache decoded/trimmed function ranges | Must preserve x86 recovery and leaf-range behavior, immutable input assumptions and thread safety. A cache keyed merely by containment can change boundary evidence. |
| Single-pass relocation processing | More useful on x86, where real text relocations remain. The bounded block skip gives the simpler x64 improvement without assuming global sorting. |
| Flush only changed instruction pages | Potentially valuable on ARM64. Native cache-coherency and rollback tests are needed before changing the current flush behavior. |
| Remove the 25 ms helper wait | It is a timeout, not a mandatory delay: process exit wakes it immediately. Cache hits now bypass helper creation entirely. |
| Reply before cache persistence | The parent still waits for successful helper exit, so moving a write after the reply does not automatically hide its latency. |
| GPU hashing | Kernel/runtime startup and transfer costs must be included; no deployment or transfer win was demonstrated for a roughly 100 ms native CPU hash. |
| Disable antivirus, change global power settings or raise global priority | Not part of the patcher implementation or these measurements. Improve the code and IO path without changing the user's machine policy. |
| WPR/WPA and SPGO | Useful follow-ups for separating remaining hard faults, scheduling and sampled CPU work on target hardware. QPC stage traces already distinguish identity, plan retrieval and application. |

The remaining lower bound includes reading the file and validating loaded code. A newly mapped input can spend much longer faulting pages than hashing resident bytes: individual research first observations exceeded 1.6–2.1 seconds. In actual browser lifecycle traces, cached patch totals were 341 ms for the reviewed Canary, 491 ms for Chromium and 1,056 ms for the 535.5 MB DCHECK image. Those are individual functional-validation observations under background load, not performance acceptance medians.

**Release validation.** x64 native tests passed 7/7; x86 passed 4/4. Checks include 70 aligned/unaligned official BLAKE3 vectors, concurrent hashes at the parallel boundary, SHA-256 diagnostic vectors, SSE candidate/tail cases, malformed and straddling relocations, cache authentication/size/corruption, mixed patch state, rollback and native proxy ABI. The reviewed matrix of 21 x64 and two x86 files passed with **166 core decisions, 23 InstallVerifier decisions and 20 CRX download decisions**. The different DCHECK download layout still safely skips its optional gate. x86 reports and both ARM64 analysis reports matched the frozen source exactly after removing the new BLAKE3 field; the previous results record had omitted x86's recognized provider gates.

Three isolated browser lifecycles passed stock/patched/restart/restore controls, plus the Canary upgrade from an older DLL. They cover MV2 request blocking, MV3 operation, renderer Win32k lockdown, complete memory decisions, unchanged stock files and private-registry cleanup. Two CRX lifecycles passed valid download confirmation, native drag-and-drop, tampered-signature rejection, missing-proof rejection and restoration. Installed browser files were never replaced; reviewed Canary 159 was recovered from a hash-verified preserved copy after the real installation updated to 160.

ARM64 cross-compilation and the actual ARM64 hash/module/optional executables under Wine/QEMU passed. The ARM64 DLL exports were inspected, but Wine's version-DLL loader prevented the native proxy ABI check. Native Windows ARM64 browser execution is still required before treating that target as runtime-validated. All six final DLL/scanner binaries passed architecture, size, import and non-RWX-section inspection. The local release bundle contains the three DLLs and both dependency licenses; its extracted bytes are checked against the final hashes.

Primary sources: [MSVC optimization options](https://learn.microsoft.com/en-us/cpp/build/reference/o1-o2-minimize-size-maximize-speed?view=msvc-170), [PGO](https://learn.microsoft.com/en-us/cpp/build/profile-guided-optimizations?view=msvc-170), [MSVC ISA selection](https://learn.microsoft.com/en-us/cpp/build/reference/arch-x64?view=msvc-170), [pinned BLAKE3 C documentation](https://github.com/BLAKE3-team/BLAKE3/blob/f3149ec5bb5449af877ba20377a11008ff499fa2/c/README.md), [BLAKE3 design](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf), [persistent DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata), [DPAPI decryption and integrity](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata), [thread-pool completion](https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-waitforthreadpoolworkcallbacks), [prefetch semantics](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-prefetchvirtualmemory), [DLL startup rules](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices), [file timestamps](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times), [USN journal continuity](https://learn.microsoft.com/en-us/windows/win32/fileio/using-the-change-journal-identifier), [instruction-cache flushing](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache) and [QPC timing](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps).

Skipped: a language/solver rewrite, custom cryptographic assembly, wider unmeasured scanner SIMD and speculative indexes. Native ARM64 browser behavior, reboot/logon persistence on this host, controlled cold-boot latency and AVX2/AVX-512 hardware performance remain untested; parallel hashing briefly uses additional CPU workers.
