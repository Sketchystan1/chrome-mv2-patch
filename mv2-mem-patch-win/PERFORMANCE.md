# Windows automatic patcher performance

`secur32.dll` is the only deployment DLL. It uses the existing native scanner,
full-file BLAKE3 identity, protected plan cache and complete loaded-code validation.
The best supported improvements already in that path are `/O2`/LTCG, upstream SIMD
hashing, balanced adaptive hash workers, parent cache reads, bounded search filters,
shared reference searches, exact function-trim reuse, lazy x64 trimming, batched
page-protection checks, dynamic hash TLS, deferred view cleanup and process-only
initial-thread capture during dynamic DLL loading. Further November 13 changes
add exact x86/x64 CMP-start filtering, ordered SIMD reference-mask draining,
relocation-block cursor reuse and two-way large-gap code comparison. November 14
adds active-range occupancy clearing, a rarer gallery-literal anchor, x86
absolute-reference filtering and direct reads from validated runtime-table spans.

This is the single record for the former performance Markdown/JSON reports and the
scanner, carrier and Edge result files. It retains measured summaries, validation,
distinct optimization proposals, limitations and primary sources. Repetitive raw
per-run samples and obsolete absolute scratch paths are preserved in Git history;
the provenance table below identifies their exact records. Research from November
11–12, 2026 used the historical `version.dll` carrier. Those measurements do not
establish identical timings for the current `secur32.dll`, and separate percentage
improvements must not be added together.

## Final November 14 experiment campaign

All 113 remaining routes from the 160-route catalogue now have an execution
outcome: 107 executed and six skipped at the user's request. The skips are AVX2,
AVX-512, native Windows ARM64, two multi-node NUMA routes and privileged SPGO
sampling. No pending, running or unresolved prototype disposition remains. The
30 `measured-win` labels describe component or design measurements; each row's
scope and final selection determine what that result supports. Only routes 61
and 65 were added to the frozen starting source in this campaign. The preceding
x64 reference filter and merged allocation/readability walk remain included.

| Selected route and complete discovery endpoint | Before → after | Paired reduction | Confirmation |
| --- | --- | --- | --- |
| 61: x86 absolute-reference upper-word SIMD filter; unbranded Chrome for Testing 157.0.8103.78 | 2,514.022 → 844.536 ms | 66.37% | 16/16 pairs faster; 34 identical reports |
| 65: validated contiguous runtime-table reads; Chrome 157.0.8103.79 x64 | 313.734 → 303.934 ms | 3.40% | 16/16 pairs faster; 34 identical reports |
| 65: validated contiguous runtime-table reads; Edge x64 | 281.711 → 260.428 ms | 7.60% | 16/16 pairs faster; 34 identical reports |

These `Analyze` measurements retain the stock view and affect discovery on cache
misses. They do not establish cold-disk or browser-start improvements. The x86
population uses an authentic, unmodified **unbranded** browser DLL. The filter
retains exact matching, order, vector/tail bounds and scalar fallback for more
than 17 queries. Table reads retain full-span validation, per-read bounds,
unwind/chaining validation, ambiguity handling and original fallback paths.
Confirmation included 943,106 reference/alignment/collision assertions and
85,248 adversarial runtime-table/unwind/stride comparisons. Production tests
also exercise the eighteenth-query fallback and rejected table-span reads.

The final x64 DLL was compared with the frozen starting `728f30ed...` DLL using
12 alternating cached Chrome launches per build, after excluded cache-fill
launches. Every observation succeeded. Browser resume to owned DevTools RPC
completion had medians 774.239 → 775.125 ms; paired median reduction was 1.14%,
with 7/12 pairs faster. This establishes no cached-start improvement. All 234
instruction checks and 78 sandbox-renderer observations passed, and all 24 cache
hits preserved cache bytes and mtime. Raw observations, including excluded
warmups, remain in `final-selected/results.json` beneath the campaign directory.

The final DLL passed stock, patched, cached restart, cache-deleted restart and
restore with packed MV2 request cancellation and MV3 controls. All 45 instruction
and 39 renderer checks passed. Browser files stayed unchanged, private registry
keys were removed and isolated proxy state was restored. Native CTest passed
20/20 x64 and 17/17 x86 cases; ARM64 cross-built. The exact current CTest logs are
archived in `final-checks/`. Native ARM64 execution was skipped as requested.

Confirmation changed several initial screening decisions:

- The 4/8 MiB hash thresholds improved kernels, but their 12-pair browser
  confirmations gave paired reductions of -1.23% / -0.30%, with 6/12 faster
  each. The existing 16 MiB threshold stays selected.
- Atom compiler tuning's initial 8.43% screening gain fell to 2.16% and 7/12
  faster in confirmation. Compiler flags stay unchanged; the exact variant's ISA
  audit and future `/favor:ATOM` ISA limitation remain recorded.
- Corrected fused hash/comparison route 104 passed 123 safety assertions,
  three deterministic late-fault cases and 70 vectors, but lost against current
  assembly by paired 4.96% on Chrome and 22.04% on Edge. Its initial assembly
  fault populations and repaired C-baseline wins remain preserved.
- The 65/60/130 discovery combination was slower than 65 alone. Routes 60 and
  130 remain unselected despite their isolated component wins.
- Acquire-state proxy route 148 had six clean browser pairs, a 9.16% paired
  reduction and only 4/6 faster. Its two regressions and nanosecond kernel scope
  leave startup attribution unproven; the production proxy stays unchanged.
- Persistent disk-patch route 128 improved its isolated browser design by
  25.13%, with 6/6 pairs faster and all nine sites/checksum/full-file differences
  verified. Its signature, browser-update and restore contract differs from the
  runtime patcher, so that design remains a prototype.
- Corrected broker/helper protocol prototypes passed 397 focused authentication,
  header, EOF and deadline checks. The original failed-review populations remain
  preserved; these architecture experiments were not added to deployment.

| Current deployment artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| x64 `secur32.dll` | 243,200 | `3e5238381af1280bdce4fdfb31d85f9e45ac7535eecea21468cbf90c25366898` |
| x86 `secur32.dll` | 245,760 | `15f6d0cf296e15350081839e433a524d0c190993bce6cfd70d7d15c078c37ddd` |
| ARM64 `secur32.dll` | 172,544 | `b97d23862dc688e3a94bd3fb905cea381a05da00a32914023963a4974c9ef01a` |

The frozen starting source, variant sources, raw populations, repairs and final
checks are retained in `_scratch/all-experiments-2026-11-14/`. Its
`final-summary.json` binds current source/DLL hashes to the validation outcomes;
`outcomes.json` and the execution ledger below account for every experiment ID.
The final lifecycle evidence is `_scratch/all-experiments-life/results.json`.
Final timings are single-host, warm-file and headless/GPU-disabled. Controlled
cold-disk and desktop-window timings were not run. A new scanner DLL identity
intentionally refills its protected cache on first use. Full-file identity,
authenticated plans, complete loaded-code checks, protection and rollback remain
required in every deployed build.

## Current path and where time remains

| Startup state | Avoided work | Required work |
| --- | --- | --- |
| Valid protected plan | Helper creation, discovery, decoding and solving | Whole stock-file identity, cache authentication, loaded-code validation and patch transaction |
| Stock file cached in RAM | Most backing-store reads | Fresh-view soft faults, hashing, code comparison and cleanup |
| Retained, fully touched mapping | Most mapping faults | CPU, cache and memory-bandwidth work; this is a microbenchmark state |
| Empty/incompatible cache | None of the discovery work | Helper creation and analysis, then the same parent checks |

The runtime locks the exact stock file, maps it read-only, hashes every byte,
reads the DPAPI-protected plan in the parent, and launches the isolated helper only
on a miss. The helper deadline is 30 seconds. Its 25 ms process wait is a timeout
that wakes on exit, not an unconditional sleep. Small plan/cache checks typically
cost 2–5 ms; hashing and full loaded `.text` validation dominate cached starts.

The x64 carrier forwards 98 system exports, including 91 system forwarders, through
assembly tail jumps. Children only forward. The initial browser thread triggers
the scan through a temporary main-DLL QPC import hook, with a `ChromeMain` lookup
hook for earlier loading. Scanning is deferred while the calibrated loader lock
is held. No polling thread is used. A changed Windows/browser startup model needs
new ordering and lock-calibration validation.

The cache is bound to the browser BLAKE3 and scanner SHA-256, protocol 5 and a
1,532-byte response containing at most 64 sites. Protected input is limited to
4 KiB. Corruption, identity changes and IO failure cause discovery. No filename,
timestamp, file ID, USN or page-sharing shortcut authorizes a patch. Site/branch,
stock-byte, target/order, allocation, relocation, full-code and rollback checks
remain compulsory. Pages transition RX→RW→write→flush→RX; rollback failure stops
the process. This is a startup operation before the patched code executes.

## November 14 further acceleration pass

Two selected changes reduce work without changing identities, IPC, discovery
semantics or patch authorization: an x64 SIMD opcode/ModRM reference filter,
and `.text` readability validation inside the existing allocation-region walk.
The latter removes the duplicate walk. Comparator work-object reuse was tested
and rejected; no new worker pool or dependency was added.

| Confirmation endpoint | Chrome before → after | Edge before → after | Evidence |
| --- | --- | --- | --- |
| Complete `Analyze`, retained stock view | 350.565 → 325.933 ms | 327.483 → 304.785 ms | 16 alternating pairs/image; paired reductions 6.29% / 6.22%; 14/16 faster on each |
| Four reference-search calls | 440.468 → 365.244 ms | 458.027 → 345.418 ms | Eight pairs/image, all faster; paired reductions 18.96% / 23.86% |
| Complete `ApplyPlan`, retained stock/live views | 40.082 → 35.810 ms | 40.273 → 36.291 ms | 24 pairs/image; paired reductions 11.64% / 9.91%; 21/24 and 24/24 faster |

All 136 discovery reports across initial and confirmation populations matched
exactly. The four-mode comparison campaign passed 400 complete transactions and
2,200 final instruction checks. Newly loaded live-image validation was largely
unchanged and noisy; those runs retained the stock mapping and are not cold-disk
measurements. The discovery filter affects cache misses only. Percentages from
different kernels cannot be added together or presented as browser-start gains.

The final normal x64 DLL (`728f30ed...`) was also compared with the original
`6cc736b7...` using the same isolated Chrome 157 copy and frozen profile seed,
alternating 12 cached launches per build after excluded cache-fill launches.
The endpoint was browser resume to owned DevTools RPC completion. Baseline had
11 successful observations and one WebSocket-observer timeout; candidate had
12 successes and no failures. Successful medians were 781.236 and 785.690 ms;
the 11 successful paired observations showed only 0.14% median reduction, with
6/11 faster. The failed baseline observation remains in the population and is
not discarded or assigned a fabricated latency. This establishes no cached
usable-browser speedup and does not identify the timeout's cause. All 225
instruction and 75 sandbox-renderer checks on successful launches passed;
cache hits preserved bytes/mtime, and proxy/job/registry ownership was cleaned.

The final DLL passed the packed-MV2 stock, patched, cached restart, cache-deleted
restart and restore lifecycle: all 45 instruction and 39 renderer checks passed,
MV2 request blocking and MV3 operation worked, original files stayed unchanged,
and registry/proxy state was restored. Full native checks passed 20/20 x64 and
17/17 x86 cases. ARM64 cross-built; native ARM64 execution remains untested.
Tests cover accepted/rejected nondecision code-page protections, both code
boundaries, allocation-query failure precedence, every supported reference
opcode/register field, invalid prefixes and vector/tail bounds. The signature
audit passed 29 tables/181 sites with no failures or warnings.

| Final normal artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| x64 `secur32.dll` | 243,200 | `728f30edd6f9d52e429afd22a0a45ba4806ce3b484474e205f83057a9a22196b` |
| x86 `secur32.dll` | 244,224 | `c0abfc8c7fbd032b52909c9672a6074d5cd1f67f45f1bcf167b2550c8670686f` |
| ARM64 `secur32.dll` | 172,544 | `dd667ba5f98db35f40da60992f332913588ec8648160ce463949e2f3f8f29e33` |

Evidence is in `_scratch/discovery-fast-pass/results.json` and
`results-first.json`, `_scratch/comparison-speed-100/results.json`,
`_scratch/speed100-2026-11-14/final-browser/results.json` (including the failed
observation), and `_scratch/speed100-life/results.json`. Browser observations are
headless/GPU-disabled on one four-core/eight-thread host. Controlled cold-disk,
desktop-window, native ARM64 and AVX2/AVX-512 measurements remain unavailable.
The new scanner identity intentionally refills its protected cache on first use.

### Release-DLL instrumented PGO experiment: unselected

A frozen-HEAD release-DLL experiment built a 301,056-byte research-only
instrumented DLL (`3bf6f332...`), collected four actual Chrome launches including
one miss and three cache hits, and relinked a 221,696-byte optimized DLL
(`caf408ca733b8628afdc8ef4b1f85d4aea306ccafb8d9fef1a431206eb32b4b7`).
The optimized DLL has no profiling-runtime import and passed all 98 native
export/forwarding checks. An initial training attempt failed before profile
collection; cleanup masked its underlying exception, and that failed/unknown
outcome remains preserved. The single corrected retry passed 36 instruction
checks and 12 sandbox observations. Training timings are not performance data.

Twelve alternating cached launches per DLL all succeeded. Original `6cc736b7...`
had median 803.146 ms and sample p95 887.990 ms; optimized had median 785.260 ms
and p95 1,026.354 ms. Paired median reduction was 1.62%, with 9/12 pairs faster.
All 234 instruction checks, 78 sandbox observations, 24 unchanged cache hits,
stock-file identity and owned job/proxy/registry cleanup passed. This small
population has a worse candidate tail and does not establish a durable cached
startup gain. Its profile is for frozen HEAD, without this pass's two source
changes, so PGO remains unselected and its percentages cannot be combined with
the selected kernels. No production build option or dependency was added.

Sources, PGD/PGCs, imports, failed training and complete observations remain in
`_scratch/speed100-2026-11-14/pgo*`, including `pgo-browser/results.json`.
Training and timing were Chrome-only, x64, warm-file and headless/GPU-disabled
on this host. Edge, native ARM64, controlled cold disk and production PGO across
all architectures were not validated.

## November 14 additional optimization pass

This pass assessed the 30 concrete routes below. Selected changes retain full
identity, complete discovery, ambiguity handling and transactional patch checks.
Potential routes are not claims of measured gains, and separate percentages must
not be added together.

| # | Acceleration route | Decision and evidence |
| --- | --- | --- |
| 1 | Clear only the active instruction-occupancy range | Selected: retain the same 64 KiB bound and byte-ownership checks; avoid clearing unused bytes. |
| 2 | Use one-call CNG SHA-256 | Unselected: warmed kernels improved, but the three-change browser candidate regressed; retain the existing caller-owned object and API. |
| 3 | Choose a rarer literal-search anchor byte | Selected for the gallery switch: search `-` at offset four; retain every full string, NUL, bounds and ambiguity check. Provider search stays unchanged. |
| 4 | Overlap stock hashing with loaded-code equality | Rejected in this pass: complete browser readiness regressed about 4%. |
| 5 | Cache the last authoritative runtime-table range | Rejected: Chrome improved about 2.8% paired, Edge regressed about 6.9%. |
| 6 | Replace locked TLS retirement reads with acquire loads | Primitive improved, complete hashing inconclusive; unselected. |
| 7 | Reuse comparison work across large gaps | Conditional: measure complete startup against work-item lifetime complexity. |
| 8 | Reuse the current operation's CPU budget across comparison gaps | Conditional: avoid repeated topology calls; likely a small saving. |
| 9 | Tune comparator concurrency | Conditional: retained-map wins do not establish fresh-view or browser wins. |
| 10 | Train the actual release DLL with instrumented PGO | Conditional: earlier scanner-only PGO gains do not establish DLL gains. |
| 11 | Train the actual release DLL with SPGO | Conditional: this token lacks the sampling privilege; no samples collected. |
| 12 | Use measured hot/cold function ordering and CPU scheduling options | Conditional: profile before changing `/ORDER` or `/favor`. |
| 13 | Read entries directly from a once-validated runtime-table span | Conditional: preserve entry, unwind and chained-record validation. |
| 14 | Memoize exact constant queries within one Program | Conditional: include PC/register/depth/generation and unknown/limit results. |
| 15 | Memoize exact pointer and argument provenance | Conditional: preserve predecessor ambiguity and register effects. |
| 16 | Memoize exact callee return summaries | Conditional: bind to immutable code and all input assumptions. |
| 17 | Find both optional anchor names in one physical `.rdata` pass | Conditional: compare with native `memchr` before adding a multi-pattern engine. |
| 18 | Share core/reference SIMD loads | Conditional: preserve independent order, capacity and ambiguity handling. |
| 19 | Filter x86 absolute references by byte pairs | Conditional: requires native distributions and bounded-window parity tests. |
| 20 | Filter ARM64 references/calls with NEON | Conditional: native ARM64 performance hardware is unavailable. |
| 21 | Widen scanner masks to AVX2/AVX-512 | Conditional: dispatch and match-density checks; this CPU supports neither ISA. |
| 22 | Run independent miss-path recognizers concurrently | Conditional: separate mutable solver state and deterministic merge are required. |
| 23 | Merge sorted relocations and patch-site gaps in one traversal | Conditional: mainly dense x86 relocations; preserve malformed-table rejection. |
| 24 | Normalize relocated words into bounded contiguous comparison runs | Conditional: copying must outweigh the cost of many tiny comparisons. |
| 25 | Fuse equality with coarse BLAKE3 subtree reads | Conditional: retain the exact cryptographic tree and relocation/site checks. |
| 26 | Tune hash threshold and physical/logical CPU budgets | Conditional: complete-path hardware measurements; the earlier 8 MiB browser trial lost. |
| 27 | Resolve `TlsGetValue2` opportunistically | Conditional: older Windows fallback and measured TLS cost required. |
| 28 | Apply rolling prefetch to genuinely cold views | Conditional: whole-view warm prefetch previously lost; count hint/fault costs. |
| 29 | Cache deterministic unsupported-image results | Conditional: authenticate full image/scanner identities; never cache transient failures. |
| 30 | Prepare plans at install/update time or single-flight concurrent misses | Conditional: exact final identities, DPAPI scope, abandoned-owner recovery and bounded waits. |

The short-range decode kernel used 10 alternating pairs, each containing 10,000
64-byte decode calls. Median time fell from 36.869 to 2.197 ms, about 94%, with
every pair faster. Complete `Analyze` comparisons showed only about 1.9% paired
improvement on Chrome and Edge, with substantial noise. All 104 full discovery
reports across the tested variants matched exactly. New tests cover changing
range lengths, branches into immediates, the last byte at the 64 KiB limit and
oversized-range rejection. These are cache-miss savings, not cached-start gains.

One-call SHA-256 used 12 alternating pairs per input. Median scanner-DLL hashing
fell from 1.437 to 1.405 ms (10/12 pairs faster), and 1,536-byte plan hashing from
10.063 to 9.620 microseconds (9/12 faster). The 128-byte key and empty input were
slightly slower. Empty/abc/key/plan vectors, the exact 310,481,560-byte Chrome
file, and inaccessible oversized-input rejection passed. Whole-browser identity
continues to use the unchanged parallel BLAKE3 implementation.

The gallery-only literal filter was confirmed with 16 alternating pairs per
browser. Median complete `Analyze` time was 350.065 to 339.712 ms on Chrome and
310.090 to 303.929 ms on Edge; paired reductions were 1.97% and 2.16%, with 15/16
and 12/16 pairs faster. Name collection alone fell from 136.234 to 79.279 ms per
ten calls on Chrome and 192.240 to 115.781 ms on Edge, all eight pairs per image
faster. All 220 complete reports in the initial/confirmation populations matched.
The provider-only alternative regressed and was rejected. New tests cover name
starts at section boundaries, preceding/following bytes and truncated literals.

The discarded overlap prototype used a joined comparator, an exact private
one-use proof, worker-local access/in-page fault handling and all original
relocation/site checks. It passed 21 x64 and 18 x86 test cases and all architecture
builds, but 12 alternating cached browser pairs measured 836.171 ms baseline
versus 869.089 ms candidate median readiness; p95 was 949.971 versus 1,129.410 ms.
Only 3/12 candidate pairs were faster. All 234 final memory decisions and 78
renderer sandbox observations passed; the 24 measured cache hits preserved
contents/mtime and the stock image stayed unchanged. Correctness alone did not
justify selecting the slower implementation.

TLS acquire-load guard reads fell from 25.892 to 18.373 ns. Over 24 retained-map
hash pairs the candidate was faster in only 10, with large overlapping ranges;
this is insufficient evidence for changing the production scheduler or TLS guard.

Raw samples, exact artifact hashes, discarded overlap sources and the paired
browser harness are in `_scratch/autopatch-speed-2026-11-14/`; discovery kernels
and parity reports are in `_scratch/discovery-speed-2026-11-14/`, and the TLS
experiment is in `_scratch/hash-speed-2026-11-14/`. Measurements are warm-file,
headless, GPU-disabled observations on one four-core/eight-thread host. They do
not establish controlled cold-disk, native ARM64, AVX2/AVX-512 or desktop-window
latency. The final two-change build passed all 20 x64 and 17 x86 CTest cases and
cross-built ARM64, including the new SHA, decode-range and literal-boundary tests.
All three DLLs remain below the 300,000-byte limit. The final source retains
only active-range clearing and the gallery anchor; both the one-call SHA and
overlap experiments were removed.

| Final artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| x64 `secur32.dll` | 242,688 | `6cc736b7b4800ff121bdca5d3705b694e7ba12be482043add0362deefb7899e0` |
| x86 `secur32.dll` | 244,224 | `e5ff358d7c5241e9d495d6c6a82baa2f2e69562e7ed2a0c9cd51f3fc15a734c1` |
| ARM64 `secur32.dll` | 172,544 | `047326359842eb69dbea70e731491165b9b4ef9090283a50ff2d635f0d184eb2` |

The three-change candidate (`1b6ac926...`, including one-call SHA) passed a packed
MV2 lifecycle, but the subsequent 12-pair cached browser comparison measured
871.264 ms baseline versus 986.768 ms candidate median readiness (13.3% slower).
The warmed SHA saving was only about 32 microseconds and did not justify that
whole-path result, so the SHA change was removed. Rebuilding HEAD verified that
the saved baseline used the same compiler and equivalent code: all function
bounds/opcodes matched, with only global-data address displacements changing.
A four-way control then encountered a baseline-independent startup timeout before
completion. An earlier attempt also stalled during the original DLL's excluded
warm-up. Neither incomplete run is presented as a completed performance population.
Final cached-start improvement is unproven; the selected gains are discovery
work reductions. Logs, discarded artifacts and completed samples remain in the
scratch campaign, including `browser-final-retry/results.json`.

The final `6cc736b7...` DLL separately passed the packed-MV2 stock, patched,
cached restart, cache-deleted restart and removal/restoration lifecycle. All 45
memory decisions and 39 renderer sandbox checks passed, including MV2 request
blocking, continued MV3 operation, cache reuse and unchanged original files.
The phase starts (1.003/2.449/0.602/1.203/0.411 seconds) validate behavior and
restoration, not a paired performance gain. The result is recorded in
`_scratch/ap-life-14-final/results.json`; final native checks are in
`_scratch/autopatch-speed-2026-11-14/native-checks-two.log`.

### Follow-up: old versus final DLL until patches are verified

Twelve cached launches per DLL used the same isolated Chrome copy and frozen
profile seed, alternating the launch order, with one excluded cache-fill launch
per DLL. The endpoint was browser `ResumeThread` to two stable observations of
all nine patched instructions with exact execute/read page protection. It
includes loader/trigger and 2 ms polling overhead; it is not exact `Patch()`
return, eventual view cleanup or usable-browser readiness.

| Cached launch result | Before (`d42b07e6...`) | Final (`6cc736b7...`) |
| --- | ---: | ---: |
| Launches | 12 | 12 |
| Median to verified patches | 432.421 ms | 441.303 ms |
| Median of successful verifications | 432.421 ms | 440.119 ms |
| p95 | 1,188.105 ms | At least 30 seconds |
| Verification timeouts | 0 | 1 |

The final median was 8.882 ms (2.1%) slower in this population. One final-build
launch failed to reach the verified state within 30 seconds; it was retained as
a censored timeout rather than discarded. This does not establish a cached-start
speedup or the timeout's cause. The selected discovery kernels improve, but that
gain does not extend to this cached-start endpoint. Successful cache hits preserved
contents/mtime, original browser files stayed unchanged, and owned jobs, proxy
files and registry state were restored. Full observations and exact identities
are in `_scratch/autopatch-speed-2026-11-14/patch-timing/results.json`.

## November 13 implementation and checks

The carrier now uses DllMain's non-null process-start `lpvReserved` value to take
the current initial-thread ID directly. Dynamic DLL loading keeps the existing
thread-enumeration fallback. This removes a whole-system thread snapshot from the
static process-start attach path without adding a worker or changing scan ordering.
Native tests exercise static-startup and dynamic-load paths from the primary
thread and a worker. It is a small startup-path optimization; no complete-browser
percentage gain is established.

This static-attach change and the following first-pass measurements were committed
with the cleanup in `92dcb45`. Dynamic loading was subsequently improved by the
process-only snapshot work recorded in the continuation below.

Twenty-call primitive averages were 55.993780 ms for the x64 enumeration fallback
versus 0.000010 ms for the static-attach shortcut, and 92.116235 versus 0.000035 ms
on x86. These are isolated calls under background IO, with the shortcut near the
measurement floor. The reviewed Chrome.exe has no direct secur32 import; a carrier
loaded dynamically still uses enumeration. These numbers do not establish a
56/92 ms Chrome launch improvement or prove static attachment for that browser.

The ARM64 core-candidate loop uses an exact raw CMP-immediate mask for values 2/3
before invoking the full decoder for branch and predicate recognition. It retains
both supported widths and excludes shifted/SP comparisons, matching the original
decoder. This avoids lifting every instruction word. Boundary, ambiguity and
full structural recognition remain. Differential coverage checks 5,568 instruction
words plus 64 filler words in 22 batches against `LiftArm64`.

| ARM64 prescreen, synthetic retained-map analysis on x64 | Original full-decode loop | Raw CMP prescreen |
| --- | ---: | ---: |
| Median | 102.35845 ms | 6.65225 ms |
| p95 | 108.9126 ms | 7.1226 ms |
| Minimum | 98.8555 ms | 6.4602 ms |
| Retained observations | 16 | 16 |

The filter-heavy fixture is a 32 MiB NOP-filled ARM64 PE with valid free/member
predicates. ABBA ordering used nine analyses/process, excluding the first from
timing, and all 36 complete reports matched exactly. The median fell 93.5% for
this deliberately synthetic workload. Hashing, IO and browser startup are
excluded; mapping is retained, background load is uncontrolled, and other build
CPU work was quiet. This does not establish real ARM64/hardware or cached-startup
speed. The old stock ARM64 research images are absent from this workspace.

```json
{
  "arm64_prescreen_2026_11_13": {
    "fixture_bytes": 33556480,
    "text_bytes": 33554432,
    "fixture_sha256": "2baedf8e6c1943243b917a5852775b47942d36c195f2fd702d3cf92920aa67a7",
    "baseline_scanner_sha256": "b01268b8d3484cb59b0764a20c5140710448e72744d52b3e00c761df578b59ff",
    "candidate_scanner_sha256": "3f7e6aa2445e405c7eb14ed0b165cb713761a554ccffd39b9c465545a67d8164",
    "baseline_autoscan_cpp_sha256": "95c45704f488a1d7dd267868121726b3966957a031b9e865e519665888234357",
    "candidate_autoscan_cpp_sha256": "7472c18ea040e5b2d982f763f4cd56ac46fd7e8f0fa9c8112a8749028ddc6af7",
    "reports_identical": 36,
    "retained_observations_per_variant": 16,
    "raw_scratch_directory": "_scratch/secur32-speed-2026-11-13",
    "real_browser_or_native_arm64_benchmark": false
  }
}
```

The cleaned build produces only `secur32.dll`: x64 241,152 bytes, x86 243,200 bytes
and ARM64 171,008 bytes, all below the exclusive 300,000-byte limit. Native x64
tests passed 19/19, including two ARM64 host-analysis tests, and x86 passed 16/16.
All ARM64 targets compiled; native execution was not available. Windows installer
fixtures passed 166 assertions, 12 elevation assertions and six build-script
success/failure cases. The signature audit passed 29 tables/181 sites with no
failures or warnings; those tables remain for Unix and Windows legacy restore.
WSL fixtures passed 72 ELF and 30 Mach-O assertions after correcting the harness's
host-path conversion. Fast Windows checks also passed. The initial full runner's
WSL `/c` versus `/mnt/c` mismatch was a harness/environment issue.
Optional Python scanner tests need Capstone/Z3 and were skipped because those
packages are absent; the shipped native scanner uses neither dependency.

| Rebuilt deployment DLL | Bytes | SHA-256 |
| --- | ---: | --- |
| x64 secur32.dll | 241,152 | `88cea526929d27ee70e221816df0ccde930cc9cb476b6d4bbb2cf788d88f339c` |
| x86 secur32.dll | 243,200 | `9163f539f95a4f5076b25192ef6d508db4bb515de867b8c4cb097ca06986bdc3` |
| ARM64 secur32.dll | 171,008 | `6e4fcf7533c4da3a3b819e3aa2dfc85498e83b803a1e212b156818f0cbed871f` |

The rebuilt x64 DLL passed an isolated Chrome 157.0.8103.79 lifecycle with stock,
patched, cached restart, cache-deleted restart and restore phases. All 45 memory
instruction checks, MV2 webRequestBlocking HTTP cancellation, MV3 behavior and
renderer Win32k checks passed. Stock `chrome.dll` SHA-256 remained
`db7ebeb22a6f731d85af882d314fecbab770eac22744dca033811d4c61cbd087`, and the private
test registry was removed. Raw results are in
`_scratch/secur32-final-runtime/results.json`. Phase startup observations were
0.822/1.614/1.216/2.266/0.616 seconds respectively; each is one functional run with
port-file polling, not an A/B performance population or desktop-window timing.

The published-release installer and release workflow now use
`secur32.dll-v<version>.zip` and the DLL beside the browser executable. A release
archive must be published before that new asset URL is usable. Existing branded
project `version.dll` carriers are removed during migration; unrelated files are
left alone. These checks do not include deployment to installed browsers or a
paired real-browser latency experiment.

## November 13 continuation after `92dcb45`

### Process-only initial-thread capture

Dynamic DLL loading now first captures the current process's threads with
`PssCaptureSnapshot(PSS_CAPTURE_THREADS)`, instead of enumerating every thread in
the system with ToolHelp. It selects the earliest creation time and releases the
snapshot and walk marker before returning. No thread contexts, process clone or
suspension are requested. Capture/walk/cleanup errors, partial results, foreign
process entries, zero creation times or an ambiguous earliest time retain the
original ToolHelp path. The existing process-start static shortcut is retained.
These Kernel32 APIs fit the existing Windows 10 minimum and add no dependency.

| Live workers in the measured process | x64 ToolHelp | x64 process snapshot | x86 ToolHelp | x86 process snapshot |
| --- | ---: | ---: | ---: | ---: |
| 0 | 55.6144 ms | 0.1886 ms | 76.7621 ms | 0.2041 ms |
| 8 | 55.4757 ms | 0.2329 ms | 54.0025 ms | 0.2573 ms |
| 32 | 52.1564 ms | 0.3539 ms | 54.3950 ms | 0.4194 ms |

Each case used twelve alternating observations per implementation with live
waiting workers. Preliminary samples collected during compiler activity were
discarded before this quiet paired pass. Actual DLL DllMain probes from primary
and worker LoadLibrary calls, with 0/8/32 live workers, identified the correct
initial thread. Every captured creation time matched `GetThreadTimes`; the
corresponding probe timings were 0.1661–0.4639 ms for PSS versus 53.2221–71.2034 ms
for ToolHelp. Permanent fault-injection checks cover complete/failed/partial
captures, marker/walk/cleanup failure, foreign IDs, zero times, ties, empty results
and a tie followed by an earlier valid thread. These are isolated initial-thread
operations, not whole-browser startup speedups. Frozen probes, commands and raw
measurements are in ignored `_scratch/secur32-thread-pss/{x64,x86}/bench-final.txt`
and its adjacent sources.

The production builds passed x64 19/19 and x86 16/16 native tests; all ARM64
targets compiled, with no native ARM64 execution. Final PSS-build identities:

| Deployment DLL | Bytes | SHA-256 |
| --- | ---: | --- |
| x64 secur32.dll | 241,152 | `a9d50f5c667d300c56765b13f7e67ec075118ca983817a40e339190b026884ea` |
| x86 secur32.dll | 243,712 | `6135661fd96d3dba23bc3cb010039b0428643f2bc4b085afa89d18b3a28e8d47` |
| ARM64 secur32.dll | 172,032 | `3f45988da087d22e5eec17540253968e5135e3618f78e2a360354813990ef7ee` |

### First actual-browser PSS comparison

The first headless Chrome comparison did not establish a startup gain:

| Cached launch endpoint, twelve samples per mode | Before PSS | PSS build |
| --- | ---: | ---: |
| Median | 943.8135 ms | 966.46895 ms |
| Observed range | About 850–1,067 ms | About 815–1,256 ms |

This population's candidate median was 2.40% slower. Each mode warmed a separate
profile seed, so profile differences and overlapping timing ranges confound
attribution. A common frozen profile seed is required to assess the change more
cleanly; the faster isolated PSS primitive does not prove a 50 ms Chrome saving.

The interval begins at native QPC immediately before ResumeThread and ends when
the observer receives successful `Browser.getVersion` and
`SystemInfo.getProcessInfo` RPC responses with the browser PID checked. The
observer signals readiness before launch and polls the port every 10 ms; this is
an API-response endpoint, not usable desktop-window or extension readiness.
All 26 successful launches including warm-ups checked 234 final instructions,
unchanged cache bytes/mtime, renderer Win32k lockdown, original-file hashes and
private-registry cleanup. Raw observations are retained under ignored
`_scratch/pss-browser/results.json`.

A subsequent diagnostic launch confirmed the PSS path in actual Chrome
157.0.8103.79: `secur32.dll` loaded dynamically on a worker, captured and walked
all 20 live threads, and selected the process's initial thread. Capture, marker,
walk and cleanup succeeded; enumeration ended normally with
`ERROR_NO_MORE_ITEMS` (259), with no zero creation times or minimum-time ties.
ToolHelp was not called, and the complete PSS operation took 0.308 ms. All nine
final instructions, three renderer-policy checks, stock-file identity and private
registry cleanup passed. This proves one real-browser fast-path execution, not
the path or latency distribution of every launch. Diagnostic details are in
ignored `_scratch/secur32-thread-diagnostic/diagnostic.json`.

### Common-frozen-profile browser controls

The stronger comparison copied the same frozen before-profile seed fresh for
both modes on every launch. Each mode kept its own protected plan cache, filled
by one excluded warm-up per mode. Twelve cached observations per mode used
alternating AB/BA order within pairs:

| Same-profile headless API endpoint | Before PSS | PSS build |
| --- | ---: | ---: |
| Median | 944.55225 ms | 864.69755 ms |
| Minimum | 861.0249 ms | 826.2211 ms |
| p95 / maximum with twelve samples | 1,094.6614 ms | 998.8778 ms |

The candidate median was **8.45% lower**, and eleven of twelve pairs were faster.
This is the measured whole-launch endpoint improvement for this population;
it is not the sum of prior optimizations or a guarantee for other machines,
profiles, browsers or desktop windows. The initial separate-seed population's
2.40% slower result remains above as evidence of the confounding and variability.

Timing starts at native QPC immediately before ResumeThread and ends when the
already-ready Node observer receives both successful browser-version/process-info
RPC responses and forwards completion through stdout IPC. The browser PID is
checked. Ten-millisecond port polling, observer/RPC/IPC overhead and ordinary
background activity remain included. This is a warm cached, headless,
GPU-disabled workload; genuinely cold disk and desktop-window latency were not
measured. It does not isolate every compiler-layout or scheduler contribution.

All 26 launches including warm-ups passed 234 final-instruction checks, with
three sandboxed renderers checked per launch. Cache contents and mtime stayed
unchanged on measured hits; stock-file identity and private-registry cleanup
passed. The common seed corrects the first comparison's known profile difference.
Raw results remain in ignored `_scratch/pss-browser/common-seed/results.json`.

The final production PSS DLL then passed a separate packed-MV2 functional
lifecycle on Chrome 157.0.8103.79: stock, patched, cached restart,
cache-deleted restart and restore. All 45 instruction checks, MV2 enable/disable,
background HTTP request cancellation, MV3 behavior and renderer Win32k checks
passed. Original disk hashes stayed unchanged and the private test registry was
removed. Single startup observations were 2.606/3.835/0.815/1.203/0.402 seconds
respectively; these validate behavior and restoration, not a performance
comparison. Raw results remain in ignored `_scratch/secur32-pss-runtime/results.json`.

### Unique-predecessor index: rejected after controls

The previously unbuilt 16 KiB predecessor-index idea was tested after `92dcb45`.
The prototype constructs one bounded index per decoded Program, including Edge
cold-block merges. Unique targets use the indexed predecessor; joins, external
PCs and changed graph counts retain the original ordered traversal. It passed
212,847 differential assertions with a 512 KiB stack and 144 complete report
comparisons across the two experiments. The index was not selected for production.

| Analyze-only retained-map experiment | Chrome 157.0.8103.79 | Edge 157.0.4341.46 |
| --- | ---: | ---: |
| Separate frozen builds, baseline→index median | 421.02405→361.7079 ms | 344.4493→341.6245 ms |
| Initial apparent reduction | 14.09% | 0.82% |
| Same executable, index off→on median | 357.61665→357.19415 ms | 323.81135→313.42605 ms |
| Reduction after controls | 0.12%, neutral | 3.21%, with substantial block drift |

ABBA ordering used nine analyses/process with the first excluded, leaving sixteen
observations per variant/image. Both controlled cases used the exact same
executable and input; an immutable process flag alone skipped index construction.
The initial Chrome gain did not survive the stronger controls. Background/cache
load and block drift were uncontrolled, so the small Edge result does not justify
extra stack storage and index maintenance. Hashing, IO, browser launch and patch
application are excluded; valid cached plans already bypass this discovery work.
Compilers finished before the controlled pass, but brief correctness probes near
its start may have overlapped initial work; exact overlap is unknown. Excluding
the first observation does not make the population a controlled quiet run.

The Chrome/Edge input hashes were respectively
`db7ebeb22a6f731d85af882d314fecbab770eac22744dca033811d4c61cbd087` and
`cb4951a5e61986871b698cdb5e74f7dbf27577dd5eaffe157ef8a57dd499672d`.
The control executable SHA-256 was
`0a3f3c905d9c427b5d89165083249f9d4d19539116220efd068541c0ec456ad3`.
Frozen commands, sources, differential checks and raw observations are retained
under ignored `_scratch/secur32-graph-2026-11-13/`; no new tracked report file was
added.

### Release-DLL SPGO: attempted, no samples collected

A complete x64 `secur32.dll` from frozen commit `92dcb45` was rebuilt with MSVC
14.52, `/Zi /DEBUG /spgo`. The training DLL was 244,736 bytes and its SPD metadata
file was 1,413,156 bytes. It contained no collected samples.

The documented LBR setup using `BranchInstructionRetired` failed counter
configuration. Timer sampling then failed at `xperf -setProfInt` with status
`0xd0000061` (`STATUS_PRIVILEGE_NOT_HELD`). The execution token was checked and
has no `SeSystemProfilePrivilege`. This establishes a profiling-permission limit
for the current token, not lack of SPGO/LBR hardware support. No browser training
started, no profile samples were generated, and no profiling logger remained
active. No SPGO optimization was selected, and no elevation was requested.

SPGO remains a future release-DLL experiment with a suitable execution token.
Classic instrumented MSVC PGO (`/GENPROFILE`, training, `/USEPROFILE`) is a separate
route that does not require system sampling permission, but its profiling runtime
and altered training layout must stay outside deployment. Historical scanner PGO
showed modest discovery gains; neither approach removes compulsory file reads,
mapping faults or loaded-code validation, and upstream assembly is not optimized
by the C++ profile. A permanent build configuration still needs a complete-path
win on representative held-out browser starts.

## Further November 13 scan and validation improvements

Discovery now checks an exact set of possible first bytes before decoding a
32-bit CMP-immediate candidate. The complete decoder and predicate checks still
run on survivors. The x64 reference collector drains each 16-byte SIMD mask in
address order, preserving hit limits and ambiguity handling. A smaller occupancy
buffer initialization was tested and removed because paired measurements showed
no useful gain.

Relocation block headers are validated once. A cursor skips only complete blocks
whose maximum relocation span precedes the next decision gap; sorted tables can
also stop at the next gap boundary. Unsorted tables retain the original traversal.
Individual relocation widths, ordering, overlap and decision-boundary checks are
unchanged, including zero-delta relocations.

After hashing, code gaps of at least 16 MiB use one thread-pool callback for half
the bytes and the calling thread for the other half. Each worker is joined even
on mismatch before returning or patching. One available CPU or worker allocation
failure uses serial `memcmp`. Relocation words and decision instructions retain
their original small comparisons. This adds no dependency or static DLL TLS.

| Controlled component measurement | Before median | After median | Reduction |
| --- | ---: | ---: | ---: |
| Chrome 157 discovery, retained mapping | 369.72745 ms | 349.4661 ms | 5.48% |
| Edge 157 discovery, retained mapping | 323.2322 ms | 307.16195 ms | 4.97% |
| Chrome 157 text comparison, fresh stock-file view | 135.4431 ms | 76.3543 ms | 43.63% |
| Edge 157 text comparison, fresh stock-file view | 160.1893 ms | 117.5187 ms | 26.64% |

Discovery uses one executable and one retained mapping per image, with sixteen
pairs alternating order on each call after two excluded warm-ups. Both browsers
were faster in fourteen of sixteen pairs; paired median reductions were 6.26%
and 4.91%. All 68 complete reports matched exactly. Earlier separate-process ABBA
controls suggested 7.14%/6.15%, but component runs contradicted those gains under
background drift. The final per-call controls supersede those estimates; the
earlier raw observations are retained. The comparison kernel uses one executable,
alternating pair order and nine retained pairs per image. Its live buffer is
already resident; the stock file is cached in RAM but remapped for each call.
These are component measurements, not complete browser launch improvements or
cold-disk results. Raw observations and frozen sources remain under ignored
`_scratch/autopatch-speed-2026-11-13/`.

Native tests pass 20/20 on x64 and 17/17 on x86; all ARM64 targets compile.
Added checks compare the scanner filters and relocation traversal against their
original behavior and exercise comparator split boundaries, mismatches, one-CPU
operation, allocation failure and callback joins. Native ARM64 execution is
unavailable.

The complete x64 `ApplyPlan` comparison used the same executable, one prehashed
retained stock mapping and an isolated relocated Chrome image. Twenty-four
observations per mode rotated order on each call after excluded warm-ups:

| Full validation and patch transaction | Median |
| --- | ---: |
| Original traversal and serial comparison | 44.95320 ms |
| Relocation cursor only | 43.99140 ms |
| Cursor and two-way comparison | 38.88675 ms |

The combined median was 13.50% lower and all 24 observations beat the original;
675 final-decision assertions passed. Hashing, fresh mapping faults and browser
launch are excluded. The first original warm-up took 255.7 ms and is not part of
the retained population.

Separate x86 synthetic 32 MiB text fixtures used 24 alternating pairs and direct
serial comparison to isolate the relocation cursor. With 8,192 relocation blocks,
nine decisions improved 6.87735→6.64180 ms (3.43%) and 64 decisions improved
9.06280→7.35885 ms (18.80%). A 58,192-block/nine-decision scaling fixture improved
8.41330→6.95880 ms (17.28%). All 4,100 final-decision assertions passed. These are
synthetic retained-image results, not native x86 browser startup measurements.

The final production DLL also passed a common-frozen-profile cached Chrome
157.0.8103.79 browser comparison, alternating AB/BA order across twelve pairs:

| Cached headless API-response endpoint | Before | Final DLL |
| --- | ---: | ---: |
| Median | 962.85775 ms | 807.37965 ms |
| p95 / maximum with twelve samples | 1,150.9568 ms | 1,019.37 ms |

The median fell 16.15%; eleven of twelve pairs were faster. Timing begins at QPC
immediately before `ResumeThread` and ends after the ready observer receives both
browser-version and process-info RPC responses with the browser PID checked.
Ten-millisecond port polling and observer/RPC/IPC overhead remain included. This
is a warm cached, headless, GPU-disabled workload on one host, with ordinary
background activity; it does not measure cold storage or usable desktop windows.
The component percentages above must not be added to this launch improvement.

All 26 launches including two excluded warm-ups passed 234 final-instruction and
78 renderer sandbox checks. All 24 measured cache hits preserved cache contents
and mtime. The stock-file SHA-256 remained
`db7ebeb22a6f731d85af882d314fecbab770eac22744dca033811d4c61cbd087` and the private
test registry was removed. The baseline was the frozen current PSS DLL
`a9d50f5c667d300c56765b13f7e67ec075118ca983817a40e339190b026884ea`;
the final DLL identity is below. Raw results are in
`_scratch/autopatch-speed-2026-11-13/browser/results.json`.

The same final DLL passed a separate packed-MV2 lifecycle: stock, patched, cached
restart, cache-deleted restart and removal/restoration. All 45 instruction and
39 renderer policy checks passed, together with MV2 enable/disable, background
HTTP cancellation and MV3 behavior. The cached restart reused the protected plan;
deleting it caused successful rediscovery. Stock disk bytes stayed unchanged and
the private registry was removed. Results are in `_scratch/ap-life-13/results.json`
and `_scratch/autopatch-speed-2026-11-13/validation_summary.json`. These functional
phase starts are not a paired performance population.

| Final deployment DLL | Bytes | SHA-256 |
| --- | ---: | --- |
| x64 secur32.dll | 242,688 | `d42b07e6a1af4094e83f512e579b5c0818a910985d51487190aee616437aeb08` |
| x86 secur32.dll | 244,224 | `d1e2d4e9d03e8574855dcd15c80b95f6ed47ff930230ca8fa0baa16e2c127a98` |
| ARM64 secur32.dll | 172,544 | `e5664925904bbc90a499549c84cf2d2f56ce2cb7f65711a2f40ee01050fd362e` |

## Measured improvements already selected

All numbers below are medians unless explicitly described as individual traces.
MB denotes decimal file bytes; MiB denotes binary thresholds/buffers.

| Experiment | Before | After | Scope and population |
| --- | ---: | ---: | --- |
| Initial complete cached native Patch, Chrome 153 | 2,139 ms | 379 ms | 15 cache hits per implementation; fresh relocated image, all final decisions checked |
| Runtime identity provider, 301.7 MB | CNG SHA-256 1,682–1,744 ms | BLAKE3 assembly 183–185 ms | Provider comparison over one mapping; three assembly samples |
| Parallel BLAKE3, 301.7 MB | Serial 187 ms | Native pool 101 ms | 20 samples/provider, retained mapping; digest parity |
| Balanced hash budgets, 301.7 MB | Existing 4-thread 98.3 ms | Balanced 4-thread 67.6 ms; 8-thread 55.35 ms | Retained mapping; historical worker ceilings |
| Balanced hash budgets, 535.5 MB | Existing 4-thread 171.5 ms | Balanced 4-thread 128.3 ms; 8-thread 92.9 ms | Retained mapping; historical worker ceilings |
| Balanced hashing before deferred cleanup | 378 ms | 316 ms / 304 ms | Complete cached native Patch with 4 / 8 workers |
| Balanced hashing + deferred cleanup | 380.968 ms | 274.610 ms / 253.079 ms | 20 hits/variant, Chrome 153, 4 / 8 workers; return from Patch |
| Same experiment through cleanup | 381.036 ms | 333.000 ms / 307.209 ms | Cleanup still consumes CPU and briefly retains the mapping |
| Same experiment total CPU through cleanup | 562.500 ms | 601.562 ms / 750.000 ms | Roughly 7% / 33% more CPU than baseline |
| Native pool versus PPL, 301.7 MB | Native 58.648 ms | PPL 62.321 ms | 20 samples/provider; no consistent PPL advantage |
| Native pool versus PPL, 535.5 MB | Native 108.721 ms | PPL 104.563 ms | PPL used more CPU for both inputs |

Balanced budgets split work between subtrees before adding workers. Availability
follows process affinity, eligible processor groups and default CPU-set counts;
there is no fixed four/eight-worker application ceiling. A 16 MiB fork threshold
limits useful work. The Windows scheduler places threads. Serial fallback and
joins protect caller storage on API/TLS failure. Simulated large-topology checks
prove sizing policy, not performance on matching many-core hardware.

Deferred cleanup uses one fixed ownership slot and a counted DLL reference until
the callback returns. Busy slots and submission/reference failure fall back to
synchronous unmapping. Earlier internal timing missed roughly 49–50 ms of view
destruction; a measured debug-output call cost only about 0.007 ms. Return time and
eventual cleanup must both be reported.

### Discovery: cache misses only

| Image | Original `/O1 /Os /Oi` | `/O2` + bounded filters | One-entry trim experiment: current→cache | Shared references: current→batch | Lazy x64 trim: current→lazy |
| --- | ---: | ---: | ---: | ---: | ---: |
| Chrome 153.0.8010.37 | 1,735 ms | 663 ms | 602.8→494.1 ms | 605.510→517.195 ms | 460.596→379.696 ms |
| Chromium 157.0.8103.39 | 1,767 ms | 618 ms | 579.1→514.4 ms | 557.269→477.631 ms | 471.846→409.247 ms |
| DCHECK Chrome 159.0.8148.1 | 2,934 ms | 1,286 ms | 1,130.0→872.8 ms | 972.342→757.618 ms | 788.095→549.472 ms |

Each column comes from its own paired experiment; it is not a sequence of timings
collected under identical conditions. Hashing is excluded. Trim bytes fell from
17.5→5.7 MB and 47.6→15.8 MB on the first/third image. A 16-entry trim cache added
little reuse and no consistent gain. Exact untrimmed begin/end pairs are cached
within one immutable image; containment alone is insufficient.

Shared references retain independent 64-hit limits, absent/ambiguous-name rules,
candidate ordering and complete/incomplete outcomes. Overflow of one target must
not hide another. The original experiment passed 60 benchmark-report and 105
reviewed-matrix comparisons plus 64 adversarial fixtures. The implementation
collects anchor names once and shares `.text` reference traversal.

Lazy trimming is restricted to authoritative x64 runtime-function bounds.
Preliminary prescreen counts were 6,192/6,427/11,262 versus seven core Program builds
per image. Only complete rejection can skip trimming; decode uncertainty and
capacity exhaustion retain the original trimmed path. Leaf, x86 and ARM64 recovery
remain. The experiment passed 225 boundary/capacity/decode checks and full report
parity; the other register-query experiments did not establish consistent gains.

The filter/compiler experiment matched 150 complete reports; trim variants matched
180. One-entry cache plus SIMD mask draining measured 465.1/475.0/814.8 ms, but
draining alone saved only about 1–2%, so most demonstrated gain belonged to trimming.

### Page checks and real headless browser observations

Repeated `VirtualQuery` on changed pages re-scanned a large RX-region tail.
One-region reuse helped, but a bounded `K32QueryWorkingSetEx` batch was the fastest
isolated guard. Only a successful query with Valid and exact RX protection passes;
every other result uses the original `VirtualQuery`. Residency/Shared bits are
never substitutes for byte equality or identity. At most 128 pages are queried.

| Image | Serial Patch: original→region→batch | Page guard: original→region→batch | Original / batch query count |
| --- | ---: | ---: | ---: |
| Chrome 153 | 299.494→267.595→269.722 ms | 17.3957→4.2975→0.0094 ms | 6 / 1 batch, no fallback |
| Chromium 157 | 279.998→271.598→267.641 ms | 21.2029→4.7570→0.0091 ms | 6 / 1 batch, no fallback |
| DCHECK Chrome 159 | 523.837→477.610→455.861 ms | 59.1065→7.5200→0.0175 ms | 9 / 1 batch, no fallback |

These used one identical DLL, eight retained samples/mode/image, fresh views and
full actual Patch checks without executing Chrome. The native guard experiment
passed 414 checks, including RX/RW/COW, invalid residency/API fallback, boundaries,
already-applied/mixed states, relocation failures, restoration and rollback.

| Complete headless browser comparison | DLL bytes | Spawn→API response | ResumeThread→API response | Cached Patch |
| --- | ---: | ---: | ---: | ---: |
| Baseline algorithm + common timing fields | 219,136 | 1,157.419 ms | 1,072.391 ms | 304.217 ms |
| Working-set page batch | 219,648 | 1,128.004 ms | 1,056.146 ms | 284.947 ms |
| Batch + dynamic TLS + disabled thread notifications | 220,160 | 1,070.302 ms | 1,002.411 ms | 256.526 ms |

Fifteen launches included three excluded cache-fill runs and four retained hits per
case. Separate builds confound layout and individual contributions. All 135 final
instructions, 69 forwarding checks, stock-file identities and 15 functional
lifecycles passed. Every browser invoked Patch once. The observed endpoint was
successful `Browser.getVersion` and `SystemInfo.getProcessInfo` RPCs with the
browser PID checked, headless/GPU-disabled; no usable desktop-window latency was
measured. Observer startup, 20 ms polling and RPC/output overhead remain.

The subsequent control used one 228,352-byte DLL for all settings:

| Parent setting in the same DLL | Spawn→API response | ResumeThread→API response | Cached Patch |
| --- | ---: | ---: | ---: |
| Notifications enabled, 16 MiB fork | 1,133.530 ms | 1,066.795 ms | 304.151 ms |
| Notifications disabled, 16 MiB | 1,079.381 ms | 1,022.417 ms | 267.032 ms |
| Notifications disabled, 8 MiB | 1,057.055 ms | 989.967 ms | 270.526 ms |

Parent notification suppression lowered these medians about 4.8% for the API
endpoint and 12.2% for Patch. Four retained hits/case and overlapping ranges limit
the conclusion; a 780 ms identity outlier was retained. All 105 renderer snapshots
kept default notifications-enabled/16 MiB flags, so this does not establish an
aggregate child-loader contribution. The 8 MiB threshold raised median Patch time
relative to 16 MiB and remains unselected.

Dynamic TLS removes static DLL TLS so `DisableThreadLibraryCalls` can succeed.
Scoped pointers reference joined caller-owned budgets; restoration failure retires
future lookups before storage expires. Production DLL detach frees the index after
quiescence, resolving the prototype's repeated-reload limit. The final PE TLS
directory must stay zero; guarded function-local statics can reintroduce TLS.

## Experiments that remain conditional

### Hash/code-validation overlap

The smallest tested pipeline hashes the whole locked stock file while a worker
compares all loaded stock `.text`, then joins before plan application. It needs no
metadata-keyed candidate cache. A mismatch falls back to the original plan-aware
validation, preserving already-patched images and mixed-state rejection. Whole
comparison does not establish relocation/site-gap validity: even a zero-delta
relocation can straddle a future decision boundary. Every original gap/header,
width/order/cursor check must remain. Proofs must be private and bound to exact
pointers, sizes, text range and one immutable startup operation.

| Image | Serial Patch→overlap | Serial→overlap through cleanup |
| --- | ---: | ---: |
| Chrome 153 | 306.520→260.219 ms | 374.036→323.034 ms |
| Chromium 157 | 278.856→243.641 ms | 344.009→307.586 ms |
| DCHECK Chrome 159 | 514.117→456.909 ms | 624.922→574.408 ms |

There were 16 retained observations/mode/image and 102 successful observations
including warm-ups, all patch bytes and stock hashes checked. CPU through cleanup
rose about 5/6/11%. Concurrent readers compete for faults/bandwidth. The corrected
prototype passed 350 native checks including the zero-delta straddling-relocation
case; its initial tail-padding fixture was outside the production text range and
was corrected before the retained pass.

Later separate attribution runs measured 440→329, 347→363 and 614→482 ms: one
image regressed. Later overlap worker sweeps measured:

| Image | Serial automatic | Overlap 2 hash workers | Overlap 4 | Overlap 7 | Overlap 8 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Chrome 153 | 254.431 ms | 232.779 ms | 214.083 ms | 224.876 ms | 213.423 ms |
| Chromium 157 | 260.593 ms | 247.025 ms | 229.558 ms | 246.322 ms | 235.329 ms |
| DCHECK Chrome 159 | 656.753 ms | 516.107 ms | 480.859 ms | 496.063 ms | 489.975 ms |

Four workers approached eight within roughly 3% while using 5–11% less CPU in that
population. N−1 was not the best rule. This is evidence for actual-browser paired
testing, not a reason for another hard-coded worker ceiling. Submission failure
must stay serial, callbacks must join, mapped IO errors must be caught on the
reading thread, and dense x86 relocations need separate evaluation. A helper miss
extends the validation-to-write interval; repeat validation if immutable code
cannot be guaranteed across it.

Retained-map hash/equality kernels measured 188.5→112.3 ms with four hash workers
and one comparator, and 77.8 ms with eight plus two comparators. They omit the full
authorization transaction and fresh-view faults. For file bytes F and text bytes
T, separate hashing/equality reads logically F+2T; nearby fusion could approach
F+T. Cold stock-file IO still has a lower bound F/storage-throughput. Ideal H/V
overlap is max(H,V)+other work, rather than H+V+other work; shared bandwidth and
fault/scheduling locks explain the smaller measured gain.

### Streaming and explicit read buffers

BLAKE3 updates are ordered, counter-aware power-of-two subtree operations. With a
16 MiB fork threshold, a 4 MiB update is serial; 16/32/64 MiB windows expose at most
2/4/8 compression leaves. A 16 MiB-minus-one update is serial, and an odd header
can misalign later subtrees. Do not update one hasher concurrently or concatenate
independent chunk digests.

| Hash + text equality kernel | Chrome 153 | Chromium 157 | DCHECK Chrome 159 |
| --- | ---: | ---: | ---: |
| Whole file, 16 MiB fork | 243.837 ms | 236.283 ms | 418.423 ms |
| 4 MiB windows | 460.737 ms | 479.399 ms | 802.325 ms |
| 16 MiB windows | 321.623 ms | 343.987 ms | 571.026 ms |
| 32 MiB windows | 256.090 ms | 274.282 ms | 467.267 ms |
| 64 MiB windows | 231.082 ms | 244.207 ms | 412.001 ms |
| 128 MiB windows | 229.251 ms | 246.607 ms | 409.393 ms |

The separate window/threshold sweep found whole-file/8 MiB medians
226.700/215.533/391.477 ms versus whole-file/16 MiB 262.804/223.503/403.832 ms.
Jointly tuned 4/1, 16/4, 32/8, 64/16 and 128/16 MiB policies did not consistently
beat whole-file/8 MiB. All 189 observations retained exact digests/equality;
222 bounded-range and 144 threshold/concurrency checks passed. These kernels
require independently proven absence of text relocations and exclude plan/patch
transactions. Actual-browser controls above did not select the 8 MiB threshold.

| Fresh-input read/hash/compare readiness | Chrome 153 | Chromium 157 | DCHECK Chrome 159 |
| --- | ---: | ---: | ---: |
| Mapping, whole-file/8 MiB fork | 224.528 ms | 217.766 ms | 398.227 ms |
| Synchronous 16 MiB buffer/4 MiB fork | 285.902 ms | 287.290 ms | 520.467 ms |
| Synchronous 32 MiB buffer/8 MiB fork | 295.588 ms | 291.223 ms | 515.537 ms |
| Synchronous 64 MiB buffer/8 MiB fork | 296.941 ms | 306.075 ms | 561.756 ms |
| Same 64 MiB + sequential-read flag | 298.382 ms | 302.576 ms | 558.106 ms |

The 16 MiB buffer roughly halved aggregate faults (136,620→66,930,
140,784→68,932, 248,480→121,580), but copies outweighed that saving. Aggregate fault
counts cannot distinguish disk versus soft faults. Sixty-seven checks covered
fragmented reads, errors/ranges/buffer reuse and digest parity.

| Separate paired background-reader kernel | Chrome 153 | Chromium 157 | DCHECK Chrome 159 |
| --- | ---: | ---: | ---: |
| Mapping/8 MiB fork | 227.069 ms | 220.281 ms | 407.919 ms |
| Synchronous 16 MiB | 288.900 ms | 289.668 ms | 509.924 ms |
| Two 16 MiB buffers, one reader callback | 240.663 ms | 233.798 ms | 414.930 ms |
| Synchronous 32 MiB | 296.255 ms | 289.793 ms | 510.929 ms |
| Two 32 MiB buffers | 236.159 ms | 239.029 ms | 418.188 ms |
| Two 64 MiB buffers | 258.932 ms | 263.915 ms | 430.413 ms |

The worker hides reads but did not consistently beat mapping at readiness. Two
32 MiB buffers completed through cleanup at 239/242/421 ms versus mapping
281/277/502 ms; production already defers mapping cleanup, so this is not an
equivalent blocked-startup win. Each kernel case/image has eight retained samples
plus warm-up; 63 worker/short-read/error/fallback/digest checks passed. Extra private
commit and first-touch cost count even if process working set appears smaller.

Ordinary OVERLAPPED reads can copy/complete inline. A separate API probe observed
pending completions, an actual 17-byte short read near EOF and EOF at completion.
Buffers, events and OVERLAPPED structures must live through completion or confirmed
cancellation. Microsoft does not guarantee coherence between mapped views and
ReadFile/WriteFile; keep the exact input immutable and hash/compare the same bytes.

### Other measured alternatives

| Alternative | Result | Current decision |
| --- | --- | --- |
| Clang 22.1.3 ThinLTO | Analysis 681/641/1,281 ms versus MSVC 663/618/1,286 ms | Keep MSVC |
| MSVC PGO | Paired analysis 617→590 and 1,165→1,101 ms; reports matched and EXE shrank | Train/test the real release DLL before selecting |
| Rust BLAKE3 | Serial 242 ms; 2/4/8 workers 131/77/62 ms, digests matched; research EXE 285,184 bytes | Scheduling evidence, no scanner rewrite |
| Portable C / all-C SIMD hashing | Portable 908–935 ms versus assembly 183–185 ms; all-C experimental DLL 193,024 versus assembly 175,616 bytes | Keep vetted assembly/dispatch |
| OpenSSL SHA-256 | About 1,000–1,083 ms versus CNG 1,682–1,744 ms | Slower than BLAKE3; no deployment dependency |
| SHA-512 / BLAKE2b-256 | About 1,035–1,043 / 1,967–1,991 ms | Keep BLAKE3 |
| CreateThread versus native pool | Complete cached medians 388 versus 379 ms | Pool has simpler joined lifetimes |
| Complex SIMD branch masks | Normal-image CPU 656→727–734 ms with identical reports | Rejected |
| Custom SSE2 equality | Retained text 57.3 ms versus UCRT memcmp 45.5 ms | Rejected |
| Four-way retained equality | 45.5→36.0 ms | Conditional; too many hash/compare workers often lost |
| Whole-view prefetch | Fresh-map medians 179–180→201–202 ms including hint cost | Rejected for this warm-file population; cold disk untested |
| Direct `.text` translation | No measured improvement | Rejected |
| Larger exact trim cache | Little additional reuse; no consistent gain | Keep one entry |
| Decoder register-query guard | Prefix-only small gains/regression; shared follow-up 514.231→668.632, 450.645→477.443, 1,136.643→982.795 ms | No consistent gain; APX may add R16–R31 |
| Skip overwritten constant fill / test CFG edge before isNoReturn | 90 full reports and 489/819 checks passed; no consistent end-to-end gain | Unselected |
| Merge allocation/readability region walks | 585 checks passed; removed one text query while retaining 13 allocation checks | 0.04–0.07 ms serial saving; whole returns inconsistent |
| Merged region walks after preflight | 4.2–8.2 ms application saving; diagnostic whole-return 352→373 ms | Unselected without complete-browser benefit |
| File-view prefault switches | SOFT_FAULT_PAGES/NONPAGED/64K combinations returned ERROR_INVALID_PARAMETER 87; ordinary view succeeded with zero resident pages | No supported drop-in switch found on this host |
| SPGO readiness | Toolchain/provider setup exists; November 13 training-DLL build passed, but sampling was blocked by the current token's missing SeSystemProfilePrivilege | No samples or speedup measured; see continuation |

## Remaining optimization catalogue

These are research routes, not promises or a claim that every possible future
technique has been exhausted. Profile the residual cost and choose the smallest
experiment whose complete path improves. November 14's paired browser trial
rejected the overlap implementation; actual release-DLL PGO/SPGO remains the
largest unselected compiler route. Cache-miss optimization must be assessed
separately from cached browser starts.

### Discovery and validation algorithms

| Technique | Potential and condition |
| --- | --- |
| Reverse predecessor edges once per Program | Repeated checks reached about 1.55M/1.70M/14.93M. The 16 KiB unique-predecessor prototype was later tested and rejected: its initial Chrome gain disappeared under same-executable controls; see the November 13 continuation. |
| Exact constant/provenance/call-summary memoization | Count repeated immutable-image/callee/PC/register/depth keys first; cache unknown/limit outcomes correctly and invalidate per Program generation. |
| Reuse complete optional Programs | Only 4–7 builds/stage and little same-range reuse were observed; retain noReturns/unsupported-decode semantics. |
| Cache authoritative runtime-table entry | November 14's prototype regressed Edge and was rejected; never memoize heuristic leaf boundaries by containment. |
| Partial occupancy clearing or generation marks | Partial clearing selected on November 14; retain the 64 KiB bound and instruction-byte ownership. Generation marks remain unselected. |
| One actual `.rdata` traversal for both names | Current name collection is once/name, not necessarily one physical traversal; compare with optimized memchr first. |
| Rare-byte/packed-pair literal filters | Reduce full comparisons only if measured density warrants it; retain full name/NUL and string-boundary checks. |
| Core/reference shared SIMD vector load | Collect bounded anchors early; retain independent candidate ordering/overflow. Later-discovered CRX caller targets cannot immediately join. |
| SIMD mask draining | Small standalone result already measured; retain ordered bits and tails rather than duplicate overlapping loads. |
| AVX2/AVX-512 scanner masks | CPU/OS dispatch, supporting hardware and full-report parity required; denser matches can erase wider-vector benefit. |
| x86 absolute-reference byte/pair screening | Bound unaligned four-byte windows and test real x86 distributions, tails and decode parity. |
| ARM64 NEON/raw CMP/BL screening | Fixed-width masks can reject before Lift; preserve every supported encoding and signed target checks, with native measurements. |
| Adaptive filter density | Must remain a complete semantically equivalent search when a filter is bypassed. |
| Parallel core/optional/CRX analysis | Misses only; each worker needs separate mutable Program/solver/trim state, bounded stack and deterministic ambiguity/unresolved merge. |
| Solver-state deduplication/dead-value pruning | Merge only truly equivalent PC/register/flags/constraints; PC-only merging is unsound and substantially more complex. |
| One sorted relocation/site merge | Mostly x86, with millions of text relocations; validate ordering and retain malformed/straddling/unsupported fallback. |
| Local relocated-word/page normalization | Could replace tiny x86 comparisons with large runs; copy traffic, wraparound and cross-page/site boundaries count. |
| Relocation block indexing | Current x64 block skip already saves most work; validate global ordering before using an index. |
| Coalesce changed protection pages | Compatible protection and complete rollback ownership required; few current sites limit payoff. |
| Narrow instruction-cache flushes | Preserve write/rollback flushes; current measured flush was about 0.001 ms, and ARM64 needs real coherency testing. |
| Deduplicate repeated successful Patch calls | Every measured browser called once; future memoization needs module lifetime/address-reuse/concurrency proof, not an eternal HMODULE flag. |
| Cache scanner identity/page size within a process | Tiny repeated-call opportunities, not reasons for a new cache framework. |

Do not end a prefilter early after finding enough constants: the original full
traversal might later exceed a bound and decline. Necessary byte summaries can
reject, but surviving candidates still need the complete original CFG check.
Old RVAs can prioritize work, never replace the rest-of-image ambiguity search.

### IO, memory and scheduling

| Technique | Potential and condition |
| --- | --- |
| Whole-hash/full-stock-code overlap | November 14's complete-browser trial regressed and was rejected; any future variant still needs private proofs, gap relocation checks, fallback and joins. |
| Fuse equality at coarse hash subtrees | Reuse stock cache lines without duplicate comparisons or changed upstream counters/flags/tree; real relocations make this nontrivial. |
| Rolling prefetch/live-text prefetch | Distinct from rejected whole-view hint; include hint time, hard faults and memory pressure. Prefetch does not populate all process PTEs. |
| Buffered/overlapped double-buffer reads | Tested reader kernels did not beat warm mapping consistently; genuinely cold disk can differ. Exact short-read/error/cancellation lifetimes required. |
| Unbuffered IO | Alignment/tail handling and bypassed useful cache can cost more than saved copies. |
| Sequential-read hints | No buffered-kernel win here; documented ReadFile hints do not establish a mapped-IO benefit. |
| Windowed mappings | Can bound x86 address-space pressure/peak working set, but adds mapping calls and complicates random-access discovery. |
| Retained mapping/prefault touch workers | Removes or shifts some PTE work only if lifetime/startup cost is counted; clean browser starts have new address spaces. |
| CPU budget/threshold tuning | Availability is a capacity bound, not a latency optimum; test complete path on input size and actual hardware. |
| Reusable coarse work items/private pool | Measure creation/queue/join overhead first; retain bounded storage, recursive deadlock-safe fallback and module lifetime. |
| CallbackMayRunLong changes | Pool starvation/lifetime rules matter; avoid removing it for a guessed bookkeeping saving. |
| Opportunistic TlsGetValue2 | Could avoid LastError side effects on Windows 11 24H2+; benchmark optional resolution and retain older-Windows fallback. |
| Thread-local QoS/performance-core preference | Test foreground startup, hybrid cores, SMT, scheduler/default policy and restore state on reused workers. Avoid global priority/power changes. |
| NUMA placement | Shared cached file pages do not move just because a mapping has a preferred node; copying/local workers need amortization. |
| AVX-512 versus AVX2 through next startup phase | Existing hash dispatch already handles ISA choice; frequency/power effects vary by CPU. Measure browser readiness and CPU/energy. |
| Low-memory concurrency | More workers can amplify faults/evictions; add a heuristic only after a measured crossover. |
| Large pages/VirtualLock | Normal file views are not drop-in large-page allocations; privileges, copy/commit/initial IO and pressure count. No demonstrated win. |
| Lower disposable-page memory priority | Hashing immediately reuses stock text, so early eviction can slow startup; process-wide policy affects Chrome too. |
| Deferred-unmap timing/priority | Faster Patch return may move contention into browser initialization; measure eventual cleanup and cap retained ownership. |
| Offer/DiscardVirtualMemory | Not replacements for unmapping the read-only owned view; writable/reclaim/content/lifetime semantics differ. |
| Windows IO rings/DirectStorage | Setup/support/runtime costs are unlikely to pay for one DLL without measured submission/storage bottlenecks; fallback needed. |
| GPU hashing/comparison | Include initialization, transfers/reduction/dependencies/fallback and 300 KB deployment budget; no win demonstrated. |

Mapped-file `EXCEPTION_IN_PAGE_ERROR` must be handled by the thread that touches
the view; a parent's handler does not catch a worker's fault. Moving work earlier
than a loader wrapper's return also needs call-site proof: a wrapper outside its
own DllMain may still run under another initializer's loader lock. Reserved
LoadLibraryExW hFile cannot bind loading to a preopened handle.

### Binary layout, caching and deployment designs

| Technique | Potential and condition |
| --- | --- |
| Release-DLL MSVC PGO/SPGO | Highest-value compiler experiment: train cached/missed starts and representative normal/diagnostic held-out images; does not optimize upstream assembly or compulsory IO. |
| `/favor`, `/ORDER`, hot/cold function layout | Use measured profiles; blend and dead-code/LTCG defaults already work. Static-function limits and code-size/i-cache effects count. |
| Delay-load bcrypt or lazy export resolution | Inspect loader/ETW cost first; do not delay DllMain dependencies or introduce unproven forwarding/loader/concurrency changes. |
| Stable semantic scanner-cache version | Avoids cache churn after carrier/log-only edits but requires covering every recognition/application/protocol change; missed bumps are unsafe. Full scanner hash remains. |
| Protected deterministic negative cache | Bound to full browser/scanner identity; never persist timeout, IO or resource failure as unsupported code. |
| Single-flight helper on simultaneous misses | Bound waits, recheck cache, recover abandoned owner and preserve deadlines. |
| Install/update-time plan preparation | Hides discovery on first launch using final DLL identity, exact immutable browser file and correct user DPAPI scope; launch still hashes/validates. |
| Reply before durable cache/helper exit | Current parent requires successful helper exit; moving WriteCache alone hides nothing. Completion/lifetime contract must change first. |
| Continuously locked verified file owner/broker | Could share identity across processes while exact-file immutability is proved; adds authenticated IPC, lifetime/update/replacement and resident-process costs. |
| Authenticated chunk/Merkle tree/change map | Reuse unchanged subtrees only under trustworthy producer and uninterrupted immutability/change coverage; otherwise discovering changes still reads all bytes. |
| Signed distributed precomputed plans | Removes known-image local discovery but adds distribution/signing/maintenance and fallback; local digest/code validation remains. |
| OS/driver-enforced immutable file/page evidence | Changes installation/privilege/signing/trust model well beyond a drop-in DLL; no deployment gain measured. |
| Patch browser disk once or use an MV2 browser build | Removes repeated patch work by changing signed files/update/restore/DRM or browser product; a separate deployment design. |

Metadata-only file ID/size/timestamps/USNs are hints, not content equality. A sound
journal cache needs continuity, writer coordination, replacement/reparse and
filesystem/permission fallbacks. Some read/RH oplock breaks let writes proceed
without acknowledgment, so notification alone is insufficient. MEM_IMAGE and
Shared/COW bits do not bind loaded bytes to the exact verified file. A second
SEC_IMAGE_NO_EXECUTE view does not authenticate an existing image. Authenticode
has different coverage and potentially chain/revocation costs. Text-only hashes,
site-only comparison and CRC/xxHash identity weaken the existing contract.

A language/solver rewrite, custom cryptographic assembly, general pattern library,
LLVM BOLT (ELF input, not this PE DLL), antivirus disablement and global power
changes have no evidence that justifies replacing this implementation.

The official documentation was checked again on November 13, 2026. Current SPGO
supports MSVC toolset 14.51+ on x64/x86/ARM64 and uses `/spgo`, xperf collection,
SPTAggregate, SPDConvert and `/spdin`. This host has toolset 14.52 and xperf, making
real release-DLL training a concrete next experiment. Microsoft's generic 5–15%
description is not a measured patcher improvement. Prefetch can partially fail
under memory pressure and does not populate process working-set PTEs. Async IO
can lose on fast storage because completion/signaling costs outweigh overlap.
Forwarded-export delay binding is unsupported; lazy `secur32.dll` forwarding is
not justified without an observed startup bottleneck and full ABI validation.

## Validation and historical identities

November 12's scanner implementation passed 18 x64 and 14 x86 tests, reproduced
166 reviewed core decisions, 23 InstallVerifier gates and 20 CRX download gates
across 21 x64 and two x86 images, and matched two ARM64 analysis reports. The DCHECK
159.0.8148.1 optional download layout safely declined. Three isolated lifecycles
on Chromium 157.0.8103.39, DCHECK 159.0.8148.1 and official Canary 159.0.8153.0
covered stock/upgrade/patched/restart/restore, MV2 request blocking, MV3 operation,
Win32k lockdown, cache reuse and original-file/private-registry restoration.

November 13's final recorded carrier/Edge build passed 20 x64 and 16 x86 tests and
all architecture cross-builds. The same x64 `secur32.dll` passed Chrome
157.0.8103.79 packed-MV2 stock/patched/restart/empty-cache-restart/restore controls,
with all nine memory decisions checked and original files unchanged. Edge
157.0.4341.46 passed Downloads CRX3 installation, confirmation, enablement, restart
and removal; both installer decisions applied, shared store detection stayed
unchanged, and tampered/missing-developer-proof packages were rejected. Stock
Edge already supports MV2. Edge preserves its off-store source label.

Native secur32 name/ordinal forwarding and loader-lock tests passed x64/x86.
Ordinary non-headless Chrome/Edge startup passed on a private Windows desktop;
Chrome's nine decisions matched, but no desktop performance endpoint was timed.
An earlier carrier-only report recorded an unrelated winmm x86 ordinal failure;
its 19/20 count is historical and superseded by the final 16/16 suite after those
other carriers were removed. Its early Edge recognition decline is likewise
superseded by the later Edge result.

ARM64 cross-builds and host analysis passed; emulated module/optional/reference
and simulated CPU-budget checks passed. The updated hash executable cannot run
in that emulator because its real CPU-set query is unimplemented. Native ARM64
hash/proxy/browser behavior, native x86 browser launches, browser updates, DRM,
controlled cold boots and broad hybrid/AVX/NUMA hardware remain unvalidated.
`complete_enforcement_coverage_proven` remains false: bounded local reasoning
cannot prove every enforcement site was found, heuristic x86 bounds and new
compiler forms can escape prescreens, and a future browser may remove MV2.

These are historical pre-cleanup artifact identities, not hashes of a new build.
The full final scanner/carrier records remain recoverable using the provenance
table. Only useful compact identity/result data is embedded here:

```json
{
  "recorded_at": "2026-11-13",
  "configuration": "Release /MD",
  "size_limit_bytes_exclusive": 300000,
  "complete_enforcement_coverage_proven": false,
  "secur32_artifacts": [
    {"arch": "x64", "bytes": 241152, "sha256": "9d583640fec2e3ee5b6786927884525bae4d904face499ae7948990105201078"},
    {"arch": "x86", "bytes": 243200, "sha256": "f97da1ed8c99cc386bb37044aaa0ff73811ba4adaaf89795ea714243472eee6b"},
    {"arch": "arm64", "bytes": 171008, "sha256": "6d2d9cb78b020c9df6f5b58f7e173b6f94f45f5f76080da187df2faacebaa15c"}
  ],
  "native_tests": {"x64_passed": 20, "x86_passed": 16, "arm64_cross_build": true, "arm64_native_runtime": false},
  "chrome": {"version": "157.0.8103.79", "exe_sha256": "a527591d96df1f30bdabf5599d257b8b80c83d90c405ff997ddbc202ba5e9ada", "dll_sha256": "db7ebeb22a6f731d85af882d314fecbab770eac22744dca033811d4c61cbd087", "memory_decisions": 9, "lifecycle_passed": true},
  "edge": {"version": "157.0.4341.46", "exe_sha256": "3e2c8557b5ca4d78868d3089346146ceab94f198ce3d58526ce8f6c8d4b4167c", "dll_sha256": "cb4951a5e61986871b698cdb5e74f7dbf27577dd5eaffe157ef8a57dd499672d", "installer_decisions": 2, "shared_store_detection_patched": false, "developer_signature_checks_preserved": true},
  "scanner_matrix_2026_11_12": {"native_images": 23, "core_gates": 166, "install_verifier_gates": 23, "crx_download_gates": 20, "arm64_analysis_images": 2}
}
```

## Benchmark acceptance and provenance

Measurements used four physical cores/eight logical processors and about 8 GiB
RAM with ordinary background activity. AVX2/AVX-512 performance was not exercised.
File caches and the machine were not reset. Fresh mappings do not mean cold
storage. Initial first-touch observations sometimes exceeded 1.6–2.1 seconds.
Individual actual-browser cached traces of 341/491/1,056 ms are functional
observations, not acceptance medians. Independent columns' medians need not sum.

For the next candidate, use paired actual `secur32.dll` launches with exact artifact
and browser hashes, a separate browser copy/profile and isolated owned jobs/cache.
Separate cache-hit/miss, retained-map, warm-file fresh-view, cold disk and low-memory
populations. Measure p50/p95, first usable window or real extension request, Patch
return, eventual cleanup, total CPU, peak commit/working set and IO bytes. Retain
outliers and enough samples; prove endpoint ownership. Check every final decision,
MV2/MV3 behavior, Win32k policy, cache identity, original-file hashes and restoration.

Use WPR/WPA/xperf sampled CPU, CSwitch/ReadyThread, loader, disk, hard-fault and
working-set/soft-fault views. QPC stages distinguish work; aggregate PageFaultCount
does not attribute backing-store reads. Do not run competing benchmarks during
paired observations. Compiler layout, observer overhead, cache drift and eventual
cleanup remain limits even when all functional checks pass.

The original records are at commit `e48491de76ea280fed94ae6ccd58e8e136784c5a`.
For example, inspect a raw report with:

```powershell
git show e48491de76ea280fed94ae6ccd58e8e136784c5a:mv2-mem-patch-win/PERFORMANCE-IO-STARTUP.json
```

| Original JSON record | Bytes | SHA-256 |
| --- | ---: | --- |
| `PERFORMANCE-DEEP-DIVE.json` | 388,588 | `4f3865f2cdeb8ccc6c59d686b8a1135525ea24705013a8ab18d71cdf0c986c58` |
| `PERFORMANCE-FOLLOWUP.json` | 467,564 | `f3053f7e2d4cef80088d0165ba791b6dfe68b744e9539f4149913bfe1342d4a3` |
| `PERFORMANCE-FRONTIER.json` | 299,776 | `4e32263cc82d7def7cba6ffd4cf5db8124c2a519595e65cdf53b3193c5730e3a` |
| `PERFORMANCE-IO-STARTUP.json` | 562,035 | `fa6e8bfcbb9424230a5d719e7362c6c3848d31405e50f76fff3744c995a1053a` |
| `PERFORMANCE-NEXT.json` | 62,772 | `6496c76f48cc53219b28f3ef970975dc234fa20b1a26de981e51baa9d4fd6128` |
| `PERFORMANCE-RESEARCH.json` | 381,202 | `4cfa2a597da9c7a8b74af17077215a1363c236d0a7c825931272492ee67831c5` |
| `PERFORMANCE-THREADING.json` | 16,082 | `73fd798a0aafffe9ccd1dcd443f9b0e087e1f876b5e29a811407c60ec36d4ba1` |
| `AUTOSCAN-RESULTS.json` | 63,188 | `e573b050fd1c5f584a1cf4f5b4c2c1d617abe8dabd3a1dd0cdf1d88c1bdcc569` |
| `SECUR32-AUTOPATCH-RESULTS.json` | 20,802 | `0f1825d07f65e003606e21521c7aefcc1af13bd5ab898e781cb6cfefa761fb55` |
| `EDGE-CRX-RESULTS.json` | 6,856 | `4147049a4819911743ad5f2ed876ce0b7dc3f67e64195779e5c634a7aab10c37` |

## Primary sources

- [Capture a process snapshot](https://learn.microsoft.com/windows/win32/api/processsnapshot/nf-processsnapshot-psscapturesnapshot)
- [Walk snapshot entries](https://learn.microsoft.com/windows/win32/api/processsnapshot/nf-processsnapshot-psswalksnapshot)
- [Captured thread identity and creation time](https://learn.microsoft.com/windows/win32/api/processsnapshot/ns-processsnapshot-pss_thread_entry)
- [Process snapshot capture flags](https://learn.microsoft.com/windows/win32/api/processsnapshot/ne-processsnapshot-pss_capture_flags)
- [Create a snapshot walk marker](https://learn.microsoft.com/windows/win32/api/processsnapshot/nf-processsnapshot-psswalkmarkercreate)
- [DllMain process-start parameters](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain#parameters)
- [Synchronous and asynchronous IO tradeoffs](https://learn.microsoft.com/en-us/windows/win32/fileio/synchronous-and-asynchronous-i-o)
- [Delay-loaded DLL constraints](https://learn.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls?view=msvc-170#constraints-on-delay-load-dlls)
- [upstream tree implementation](https://github.com/BLAKE3-team/BLAKE3/blob/f3149ec5bb5449af877ba20377a11008ff499fa2/c/blake3.c)
- [threaded API and identical-result contract](https://github.com/BLAKE3-team/BLAKE3/blob/f3149ec5bb5449af877ba20377a11008ff499fa2/c/README.md)
- [unmap behavior](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile)
- [callback submission](https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-trysubmitthreadpoolcallback)
- [module reference counting](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw)
- [release after callback return](https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-freelibrarywhencallbackreturns)
- [packed-pair implementation](https://github.com/BurntSushi/memchr/blob/master/src/arch/generic/packedpair.rs)
- [why excessive prefilter candidates can slow a search](https://github.com/BurntSushi/memchr/blob/master/src/memmem/searcher.rs)
- [multi-pattern/prefilter design](https://github.com/BurntSushi/aho-corasick/blob/master/DESIGN.md)
- [CPU Sets](https://learn.microsoft.com/en-us/windows/win32/procthread/cpu-sets)
- [SPGO](https://learn.microsoft.com/en-us/cpp/build/sample-profile-guided-optimization?view=msvc-170)
- [MSVC scheduling options](https://learn.microsoft.com/en-us/cpp/build/reference/favor-optimize-for-architecture-specifics?view=msvc-170)
- [instruction flush ranges](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache)
- [prefetch semantics](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-prefetchvirtualmemory)
- [cache-hint scope](https://devblogs.microsoft.com/oldnewthing/20120120-00/?p=8493)
- [mapping/large-page rules](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw)
- [DirectStorage](https://learn.microsoft.com/en-us/windows/win32/dstorage/dstorage-portal)
- [WPR/WPA](https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/support-tools-xperf-wpa-wpr)
- [Cloudflare's AVX experiment](https://blog.cloudflare.com/on-the-dangers-of-intels-frequency-scaling/)
- [timestamp guarantees](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times)
- [journal continuity](https://learn.microsoft.com/en-us/windows/win32/fileio/using-the-change-journal-identifier)
- [accumulated journal records](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journal-records)
- [oplock details](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [COW reporting](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery)
- [working-set query](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-queryworkingsetex)
- [Authenticode coverage](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#appendix-a-calculating-authenticode-pe-image-hash)
- [xxHash's stated model](https://github.com/Cyan4973/xxHash/blob/dev/README.md)
- [BOLT input requirements](https://github.com/llvm/llvm-project/blob/main/bolt/README.md)
- [Valid and Win32Protection](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-psapi_working_set_ex_block)
- [memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [MapViewOfFile3](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3)
- [extended parameters](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-mem_extended_parameter)
- [mapped-view failure handling](https://learn.microsoft.com/en-us/windows/win32/memory/reading-and-writing-from-a-file-view)
- [DLL startup rules](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)
- [LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
- [working sets](https://learn.microsoft.com/en-us/windows/win32/memory/working-set)
- [Modern x64 APX includes R16–R31](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170#x64-register-usage)
- [DLL thread notifications](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-disablethreadlibrarycalls)
- [dynamic TLS](https://learn.microsoft.com/en-us/windows/win32/dlls/using-thread-local-storage-in-a-dynamic-link-library)
- [TlsGetValue2](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsgetvalue2)
- [function ordering](https://learn.microsoft.com/en-us/cpp/build/reference/order-put-functions-in-order?view=msvc-170)
- [QoS](https://learn.microsoft.com/en-us/windows/win32/procthread/quality-of-service)
- [ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile)
- [IO ring read](https://learn.microsoft.com/en-us/windows/win32/api/ioringapi/nf-ioringapi-buildioringreadfile)
- [NUMA](https://learn.microsoft.com/en-us/windows/win32/procthread/numa-support)
- [mapping coherence](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
- [oplock breaks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/breaking-oplocks)
- [General trace events](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/recording-for-basic-system-diagnosis)
- [resource analysis](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/recording-for-resource-based-analysis)
- [TlsGetValue and LastError](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsgetvalue)
- [pending IO cancellation](https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations)
- [MSVC optimization options](https://learn.microsoft.com/en-us/cpp/build/reference/o1-o2-minimize-size-maximize-speed?view=msvc-170)
- [PGO](https://learn.microsoft.com/en-us/cpp/build/profile-guided-optimizations?view=msvc-170)
- [MSVC ISA selection](https://learn.microsoft.com/en-us/cpp/build/reference/arch-x64?view=msvc-170)
- [BLAKE3 design](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- [persistent DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [DPAPI decryption and integrity](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
- [thread-pool completion](https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-waitforthreadpoolworkcallbacks)
- [QPC timing](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)
- [Using the Thread Pool Functions](https://learn.microsoft.com/en-us/windows/win32/procthread/using-the-thread-pool-functions)
- [PPL partitioning work](https://learn.microsoft.com/en-us/cpp/parallel/concrt/parallel-algorithms?view=msvc-170#partitioning-work)
- [General Concurrency Runtime best practices](https://learn.microsoft.com/en-us/cpp/parallel/concrt/general-best-practices-in-the-concurrency-runtime?view=msvc-170)
- [Native thread-pool best practices](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-pools#best-practices)
- [Processor-group affinity](https://learn.microsoft.com/en-us/windows/win32/api/processtopologyapi/nf-processtopologyapi-getprocessgroupaffinity)

## November 14 follow-up: 160 concrete acceleration routes

This inventory answers the request for at least 100 ways to accelerate the
automatic patcher. It contains 160 distinct mechanisms, grouped by the work they
affect. **Current** means already present in the inspected implementation;
**candidate** means a concrete experiment, with no new measured gain implied;
**conditional** needs different hardware, workload or deployment; **rejected**
means prior evidence or the current correctness contract rules it out. It is
not a claim that 160 changes were implemented or that every candidate is faster.
The earlier dated experiments remain the authority for their measurements.
There are 113 candidate/conditional routes beyond the 38 current mechanisms and
nine rejected alternatives, so the requested minimum does not depend on counting
existing implementations or rejected ideas as new opportunities.

Prioritize the residual path: validated runtime-table access and eliminating
redundant solver work before adding larger engines. Exact query
memoization and shared search passes affect cache misses. IO experiments need
cold-storage controls; retained-view gains alone do not establish faster browser
startup. Within each group, the first routes are generally simpler or better
supported. Reject a candidate if complete-path controls lose, even if its kernel
wins. Keep full-file BLAKE3 identity, protected cache authentication, complete
ambiguity search, full loaded-code equality, relocation validation and rollback.

### Identity and hash execution

| # | Route and saved work | Source | Status and required condition |
| --- | --- | --- | --- |
| 1 | Use upstream SIMD/assembly BLAKE3 instead of portable compression | `CMakeLists.txt`, `Blake3` | Current; preserve upstream ISA/OS dispatch and exact digest parity. |
| 2 | Fork large BLAKE3 subtrees onto native workers | `blake3_threads.cpp` join hook | Current; overlap independent compression while preserving tree counters and flags. |
| 3 | Divide the recursive worker budget between left/right subtrees | `BudgetScope`, join hook | Current; avoid starving one side or recursively oversubscribing. |
| 4 | Tune the 16 MiB fork threshold to the measured complete startup crossover | join hook | Conditional; the earlier 8 MiB browser trial lost, so smaller is not automatically faster. |
| 5 | Compare physical-core and SMT worker budgets | `HashThreadCount`, join hook | Candidate; reduce competition for execution units and memory bandwidth on suitable CPUs. |
| 6 | Cap workers by input size in addition to available CPUs | join hook | Candidate; avoid creating workers with too little compression work to amortize scheduling. |
| 7 | Bound simultaneously active recursive callbacks | `active`, join hook | Current; avoid excess worker contention when multiple callers hash concurrently. |
| 8 | Reuse a bounded set of coarse hash work objects | `CreateThreadpoolWork` in join hook | Candidate; save create/close calls, with joined storage and deadlock-safe serial fallback. |
| 9 | Measure a dedicated hash callback environment against the shared pool | hash `compress` callback | Candidate; reduce queue competition only if pool setup and cleanup amortize. |
| 10 | Resolve `TlsGetValue2` once and use it when supported | `currentBudget`, `BudgetScope` | Conditional; Windows 11 24H2+ and older-Windows fallback; include resolver/loader cost. |
| 11 | Replace read-only interlocked TLS-retirement checks with acquire loads | `enabled`, `BudgetScope` | Conditional; the prior nanosecond kernel win did not establish complete-hash improvement. |
| 12 | Reuse a CNG SHA-256 hash object for sequential small internal hashes | `Hash`, `CachePath`, cache digest | Candidate; isolated caller ownership, reset/error semantics and short-message measurements required. |
| 13 | Keep digests binary internally and encode only at filename/report boundaries | `HashValue`, `WirePlan`, cache key | Candidate; saves repeated hex conversion/validation, but requires a complete protocol/cache migration. |
| 14 | Stop before hashing when PE inspection already proves the input invalid | `StockImage` constructor | Candidate; avoids whole-file work on failure paths without changing valid-file identity. |
| 15 | Reuse scanner identity within one proven immutable scanner lifetime | `scannerHash`, `Patch` | Conditional; current browser normally patches once, so establish repeated use before adding state. |
| 16 | Replace create/update/finalize SHA with the CNG one-call API | `Hash` | Rejected in the prior browser population; the tiny warmed SHA saving did not justify the startup regression. |

### File access, memory and scheduling

| # | Route and saved work | Source | Status and required condition |
| --- | --- | --- | --- |
| 17 | Hash a read-only mapped stock file without private read-buffer copies | runtime `View`, `StockImage` | Current; exact file remains locked through authorization. |
| 18 | Supply one whole-file BLAKE3 update rather than tiny serial updates | `Blake3` | Current; exposes large counter-aligned subtrees to parallel compression. |
| 19 | Prefetch a bounded rolling stock-file window ahead of compression | `View`, hash input | Conditional; test genuine hard faults, hint overhead and partial-prefetch failure. |
| 20 | Prefetch the corresponding live-code window ahead of equality | `sameText`, `SameBytes` | Candidate; can overlap live-image faults without duplicating stock reads; include memory pressure. |
| 21 | Double-buffer stock reads while hashing the previous buffer | runtime file/mapping path | Conditional; prior warm-file reader kernels did not consistently beat mapping; cold disk may differ. |
| 22 | Use overlapped reads where storage completion is the bottleneck | runtime file access | Conditional; retain short-read, cancellation and buffer/event lifetime handling. |
| 23 | Test aligned unbuffered reads on a cold sequential workload | runtime file access | Conditional; account for alignment, final tails and loss of useful OS cache. |
| 24 | Add sequential-read hints to an explicit buffered-read variant | runtime `CreateFileW` | Conditional; prior warm buffered kernels gained nothing, and ReadFile hints do not prove mapped-IO gains. |
| 25 | Window file mappings when x86 address-space pressure dominates | runtime `View`, helper `View` | Conditional; random-access discovery and extra mapping calls must still meet the deadline. |
| 26 | Retain a fully touched mapping across repeated operations with a real owner | runtime `View` ownership | Conditional; count initial faults and owner lifetime; a new browser process still has fresh PTEs. |
| 27 | Place worker-private scratch on the NUMA node that runs the worker | hash/comparison callback storage | Conditional; shared cached file pages do not move automatically, and copying must amortize. |
| 28 | Assign adjacent hash/comparison spans to the same NUMA locality | join hook, `SameBytes` | Conditional; reduce remote traffic only on supported multi-node hardware with measured affinity costs. |
| 29 | Prefer performance cores or scoped performance QoS for startup callbacks | native callbacks | Conditional; restore reused-worker state and test hybrid cores, scheduler policy and energy. |
| 30 | Reduce concurrency at the measured low-memory crossover | hash/comparison worker budgets | Candidate; prevent parallel faults from evicting pages immediately needed by the next stage. |
| 31 | Unmap the stock view after patch return on a pinned callback | `queueView`, `releaseView` | Current; removes synchronous view teardown from the blocked startup path. |
| 32 | Tune deferred-cleanup priority/placement to avoid competing with browser initialization | `releaseView` | Candidate; measure usable-browser readiness and eventual cleanup, keeping bounded retained ownership. |

### Plan cache and isolated helper

| # | Route and saved work | Source | Status and required condition |
| --- | --- | --- | --- |
| 33 | Read a protected plan in the parent before creating a helper | runtime `Patch` | Current; a hit skips process creation and all discovery. |
| 34 | Persist the complete structurally validated plan | `WriteCache`, `ReadCache` | Current; keyed to exact image/scanner identities and authenticated with DPAPI. |
| 35 | Prepare the user's protected plan at install/update time | installer, helper entry | Candidate; removes first-launch discovery using final scanner identity and correct user DPAPI scope. |
| 36 | Ship signed precomputed plans for known exact browser digests | helper/cache inputs | Conditional; adds trusted distribution/version maintenance; local identity and code validation remain. |
| 37 | Single-flight concurrent misses for the same exact cache key | `scanInHelper`, cache path | Candidate; recheck after acquiring ownership, bound waits and recover an abandoned owner. |
| 38 | Cache deterministic unsupported-image results | helper report/cache format | Candidate; authenticate identities and distinguish structural rejection from timeout/IO/resource failure. |
| 39 | Share identity through a continuously locked file-owner broker | `StockImage`, helper IPC | Conditional; requires authenticated IPC, immutability, replacement/update handling and a resident process. |
| 40 | Reuse unchanged cryptographic subtrees under authoritative change tracking | BLAKE3/cache design | Conditional; without continuous trusted coverage, finding changes still requires reading every byte. |
| 41 | Bind cache compatibility to a complete semantic scanner version | scanner cache key | Conditional; avoids churn after carrier-only edits, but missed recognition/application/protocol bumps are unsafe. |
| 42 | Recheck cache inside the helper after a parent miss | `VersionMV2ScanW` | Current; a racing successful helper can save the later helper's analysis. |
| 43 | Keep IPC as one bounded fixed-size plan rather than text/JSON parsing | `WirePlan`, helper pipe | Current; avoids serialization, allocation and parser work while retaining validation. |
| 44 | Use pipe-ready notification instead of repeated `PeekNamedPipe` while waiting | `scanInHelper` | Candidate; reduces wait-loop wakeups, with a bounded deadline and successful-exit requirement; 25 ms is not a fixed sleep. |
| 45 | Overlap durable cache publication with parent plan validation | helper `WriteCache`, pipe reply | Conditional; the current protocol waits for helper exit, so moving WriteCache alone hides no work. |
| 46 | Inherit the parent's exact immutable stock mapping | `scanInHelper`, helper `View` | Current; saves a second file open/read/hash and binds analysis to the same bytes. |
| 47 | Pass parent-verified scanner identity through a proven locked scanner mapping | `scannerHash`, helper command | Conditional; saves the helper's small scanner hash only after module/file lifetime and trust are preserved. |
| 48 | Leave cache hits untouched instead of rewriting/reprotecting them | `ReadCache`, helper cache branch | Current; saves writes, DPAPI encryption and cache-directory contention. |

### Candidate and reference searches

| # | Route and saved work | Source | Status and required condition |
| --- | --- | --- | --- |
| 49 | Use SSE2 byte masks to find candidate x86/x64 branch encodings | `Analyze` search loop | Current; avoids lifting every byte in the full code section. |
| 50 | Screen exact CMP start opcodes before backward lifting | `cmpStart`, `Analyze` | Current; retains the supported compare encodings and full predicate proof. |
| 51 | Use a raw ARM64 CMP-immediate mask before lifting | ARM64 `Analyze` loop | Current; preserves width, immediate, shift and register exclusions. |
| 52 | Test raw relative-call targets before full instruction lifting | `crxDownload` caller loop | Current; rejects most x86 calls with inexpensive target arithmetic. |
| 53 | Search the rarer gallery literal byte before full string comparison | `RefBatch` name collection | Current; retain preceding/following NUL, full literal and section-boundary checks. |
| 54 | Apply a different rare-byte anchor to provider-name search | `RefBatch` provider collection | Rejected in the prior pass; the provider-only alternative regressed. |
| 55 | Find both optional names in one physical `.rdata` traversal | `RefBatch` construction | Candidate; compare against optimized `memchr`, and retain separate overflow/ambiguity outcomes. |
| 56 | Use a packed byte-pair filter for literal matches | `RefBatch` name collection | Candidate; fewer false comparisons only if pair density beats extra loads and boundary work. |
| 57 | Batch references for all initially known literals | `RefBatch`, `scanReferences` | Current; shares one code traversal across optional anchor queries. |
| 58 | Use SIMD opcode/ModRM masks before x64 RIP-relative reference decoding | `scanReferences` | Current; the tighter filter is measured above; exact prefix/target/decoder checks remain. |
| 59 | Drain a vector mask once in address order | `scanReferences` | Current; avoids restarting overlapping searches for every match. |
| 60 | Share vector loads between core-candidate and initial-reference searches | `Analyze`, `scanReferences` | Candidate; preserve independent ordering/capacity and still scan later-discovered CRX targets. |
| 61 | Screen x86 absolute references by a selective byte pair | x86 `scanReferences` | Candidate; retain bounded unaligned four-byte windows, exact targets and tail coverage. |
| 62 | Widen supported candidate/reference masks to AVX2 | scanner search loops | Conditional; this host lacks AVX2; CPU/OS dispatch, dense matches and complete-report parity must be measured. |
| 63 | Use AVX-512 mask registers to reduce mask-drain overhead | scanner search loops | Conditional; requires supported hardware, OS state and whole-startup frequency/power controls. |
| 64 | Filter ARM64 ADRP/ADD/BL patterns with NEON lanes | ARM64 reference/caller loops | Conditional; preserve signed target/page arithmetic and measure on native ARM64 hardware. |

### PE boundaries and instruction decoding

| # | Route and saved work | Source | Status and required condition |
| --- | --- | --- | --- |
| 65 | Read runtime entries directly from one fully validated contiguous table span | `Boundaries::entry/find` | Candidate; saves repeated RVA translation while preserving unwind/chained-record validation. |
| 66 | Advance a runtime-table cursor for monotonically ordered candidate addresses | `Analyze`, `Boundaries::find` | Candidate; preserve skipped invalid entries, leaf fallback and exact binary-search behavior for out-of-order queries. |
| 67 | Bypass a low-selectivity filter when measured match density is high | scanner filter dispatch | Candidate; both paths must perform the same complete search and produce identical ordered reports. |
| 68 | Reuse a complete Program for consecutive candidates with identical exact bounds | `Analyze::consider`, `Program::build` | Candidate; include no-return generation/state and retain every candidate's proof and ambiguity result. |
| 69 | Cache exact function-trim input/output for the immutable PE | `Boundaries::trim` | Current; removes repeated decoding of exactly the same range. |
| 70 | Expand the exact trim cache beyond one entry | `Boundaries` trim state | Rejected by earlier measurements; observed reuse did not justify the extra lookup/storage cost. |
| 71 | Delay x64 function trimming until a necessary prefilter survives | `prefilter`, untrimmed boundaries | Current; saves full decoding of rejected ranges without skipping complete surviving checks. |
| 72 | Scan ARM64 trailing BRK padding in bounded vector blocks | `trimUncached` ARM64 branch | Candidate; preserve exact BRK words, last-instruction boundaries and the scalar tail. |
| 73 | Use occupancy generations to avoid clearing byte marks between decodes | `Program::decode` | Candidate; extra mark width/storage and generation wrap handling must beat current active-range clearing. |
| 74 | Clear only the active instruction-occupancy range | `Program::decode` | Current; avoids clearing unused bytes while retaining the 64 KiB limit and byte-ownership checks. |
| 75 | Track pending branch targets to avoid redundant worklist visits | `Program::decode` | Candidate; preserve instruction/interior overlap failures and the original overflow/decline semantics. |
| 76 | Skip node sorting when decode output is already monotonically ordered | `Program::decode` final sort | Candidate; track order without weakening duplicate-address or reachability behavior. |
| 77 | Use a bounded PC-to-node index for repeated exact node lookup | `Program::at` | Candidate; count initialization and added stack/heap footprint against binary-search savings. |
| 78 | Translate hot code spans directly instead of repeatedly searching PE sections | `PeImage::at/code` | Rejected in prior direct-text trials; no measured improvement justified changing the shared lookup. |
| 79 | Reorder decoder opcode groups using the actual instruction distribution | `LiftX86`, `LiftArm64` | Candidate; reduces branch misprediction only if held-out encoding and full-report tests agree. |
| 80 | Add validated fast paths for common simple encodings before generic length decoding | `LiftX86` | Candidate; use bounded reads and exhaustive decoder parity; unknown/prefix encodings keep the pinned fallback. |

### Program provenance and symbolic proof

| # | Route and saved work | Source | Status and required condition |
| --- | --- | --- | --- |
| 81 | Build a reverse predecessor index once per Program | `Program::predecessor` | Rejected after the earlier same-executable controls; initial apparent Chrome gains disappeared. |
| 82 | Memoize exact constant-before queries within a Program generation | `constantBefore` | Candidate; bind PC/register/input assumptions and cache unknown/limit results without losing ambiguity. |
| 83 | Memoize pointer provenance for immutable code and identical entry assumptions | evaluator pointer/prefix analysis | Candidate; include register effects and predecessor ambiguity in the key. |
| 84 | Memoize exact argument-origin queries | `Program::fromArgument` | Candidate; key PC/register/argument/stack-slot/generation and preserve all predecessor paths. |
| 85 | Memoize private-stack-slot proofs | `Program::privateSlot` | Candidate; key PC/slot/frame assumptions and invalidate with rebuilt no-return/CFG state. |
| 86 | Memoize exact stack-address queries | `Program::stackAddress` | Candidate; include entry mode and all offset/register assumptions; failed proofs are not positive facts. |
| 87 | Reuse exact callee return summaries | `trueReturn`, guarded calls | Candidate; immutable callee bytes, entry state, call effects and proof limits must all match. |
| 88 | Precompute each node's conservative register-write mask | `Writes`, `VolatileReg`, `Node` | Candidate; saves repeated opcode classification, with APX/unknown-effect handling and size-cost measurements. |
| 89 | Use bounded visitation marks for repeated PC-only safety traversals | `falseFlagsSafe`, CFG checks | Candidate; only where the existing state is exactly PC; register/constraint-sensitive walks need richer keys. |
| 90 | Merge truly identical symbolic execution states | `Evaluator::walk/branch` | Candidate; compare PC, registers, flags, constraints and checkpoint state, never PC alone. |
| 91 | Index exact visited-state membership instead of repeatedly scanning the seen list | provenance `todo/seen` loops | Candidate; preserve iteration/overflow semantics and measure hash/index overhead at the bounded list sizes. |
| 92 | Stop carrying provably dead register values through symbolic branches | `Evaluator::State` | Candidate; full future-use/call/flags proof is required; unknown liveness stays conservative. |
| 93 | Index checkpoint addresses when a predicate has many checkpoints | `checkpoints`, `falseCheckpoint` | Candidate; save repeated linear matching only after observed density justifies the index. |
| 94 | Evaluate prefix constants only for registers that influence the recognized predicate | `Evaluator::prefix/verify` | Candidate; use complete dependency/call effects; omitted unknown values must remain unknown. |
| 95 | Precompute type/location interval membership reused by role verification | `membership`, `proves`, `roleFor` | Candidate; preserve signed interval edge cases and every accepted/rejected role. |
| 96 | Reuse complete necessary-field summaries across same-range predicates | `prefilter`, evaluator fields | Candidate; finish the original bounded traversal and never bypass a later overflow/decline. |

### Loaded-code comparison and patch transaction

| # | Route and saved work | Source | Status and required condition |
| --- | --- | --- | --- |
| 97 | Use the platform's optimized `memcmp` for unrelocated runs | `SameBytes`, `sameText` | Current; avoids maintaining a slower custom equality engine. |
| 98 | Split sufficiently large equal-code runs across two workers | `SameBytes` | Current; join even on mismatch before caller-owned mappings/storage can disappear. |
| 99 | Reuse one comparison work object across large gaps in an ApplyPlan operation | `SameBytes`, `sameText` | Rejected in this pass: warmed Chrome validation regressed; keep existing joined callback lifetimes. |
| 100 | Query the available comparison CPU budget once per ApplyPlan operation | `HashThreadCount`, `SameBytes` | Candidate; removes repeated topology/CPU-set calls for multiple large code gaps. |
| 101 | Tune the comparator's 16 MiB split crossover | `SameBytes` | Candidate; include fresh-view faults, task setup, unequal inputs and actual browser startup. |
| 102 | Compare four-way splitting against the current two-way comparator | `SameBytes` | Conditional; historical retained-view gains did not establish a full browser gain under hash/compare contention. |
| 103 | Replace platform equality with custom SSE2 | `SameBytes` | Rejected in prior retained-code measurements; custom SSE2 was slower than UCRT `memcmp`. |
| 104 | Fuse exact code equality into coarse BLAKE3 subtree reads | join hook, `sameText` | Conditional; saves a stock-text pass only with the original cryptographic tree and complete relocation/site checks. |
| 105 | Skip relocation blocks whose entire possible span misses the current gap | `ApplyPlan::sameText` | Current; accounts for eight-byte relocations crossing a block's nominal page. |
| 106 | Retain the relocation-block cursor across increasing code gaps | `firstBlock`, `sameText` | Current; avoids restarting sorted-block scans, with unsorted fallback. |
| 107 | Merge validated sorted relocation entries and ordered patch gaps in one traversal | `ApplyPlan` relocation loop | Candidate; mainly dense x86 cases; preserve malformed, unsupported, overlapping and straddling-entry rejection. |
| 108 | Normalize dense relocated words into bounded contiguous comparison buffers | `sameText` | Candidate; larger equality runs must outweigh copying, with exact delta wraparound and site/page boundaries. |
| 109 | Combine image-allocation and readability region walks | `ApplyPlan` allocation walk | Current; selected warmed validation saving above, with unchanged protection checks and failure precedence; browser gain unproven. |
| 110 | Batch execute/read decision-page checks with working-set queries | `K32QueryWorkingSetEx` path | Current; VirtualQuery fallback remains for invalid/unavailable working-set entries. |
| 111 | Coalesce adjacent compatible decision pages into protection ranges | page list, `restore`, write transaction | Candidate; retain complete rollback ownership and exact RX-to-RW-to-RX transitions; current few sites limit payoff. |
| 112 | Flush only changed instruction ranges/pages | write/rollback `FlushInstructionCache` | Candidate; measured current flush cost was tiny; preserve both write and rollback coherency, especially on ARM64. |

### Compiler, loader, forwarding and deployment

| # | Route and saved work | Source | Status and required condition |
| --- | --- | --- | --- |
| 113 | Optimize and inline across translation units with `/O2` and LTCG | `CMakeLists.txt` | Current; reduces call/branch overhead without new runtime machinery. |
| 114 | Link only the pinned read-only Detours import helpers used by the carrier | generated `detours-imports.cpp` | Current; removes unused inline-hook code and associated image/loader footprint. |
| 115 | Fold identical functions and remove unreferenced code/data | `/OPT:ICF`, `/OPT:REF`, `/Gy`, `/Gw` | Current; smaller loaded code improves footprint and instruction locality. |
| 116 | Train instrumented PGO on the actual release DLL | `secur32` build/link | Conditional; frozen-HEAD trial above had a small noisy median gain and worse tail; final-source/held-out training remains required. |
| 117 | Train release-DLL SPGO using real startup samples | toolchain `/spgo`, `/spdin` | Conditional; this token lacks the required sampling privilege; no samples or speedup exist yet. |
| 118 | Tune MSVC `/favor` to supported deployment CPUs | `CMakeLists.txt` release options | Candidate; use representative startup profiles and retain the intended ISA/compatibility baseline. |
| 119 | Order hot/cold functions from measured release-DLL profiles | link `/ORDER`, code layout | Candidate; reduce instruction-cache/page faults while checking DLL size and held-out paths. |
| 120 | Replace MSVC LTCG with Clang ThinLTO | compiler configuration | Rejected by earlier analysis controls; Clang did not consistently improve the tested images. |
| 121 | Forward without scanning in renderer/utility child processes | `DllMain` `--type=` check | Current; avoids repeated expensive authorization in every browser child. |
| 122 | Disable DLL thread notifications using dynamically allocated hash TLS | `DisableThreadLibraryCalls`, `ReleaseHashTls` | Current; avoids carrier attach/detach work for each browser/helper worker thread. |
| 123 | Capture the current initial-thread ID directly during static process attachment | `firstThread(startup)` | Current; avoids enumeration when DllMain's process-start evidence is authoritative. |
| 124 | Capture only the current process's threads during dynamic loading | `PssCaptureSnapshot`, `firstThread` | Current; avoids a whole-system snapshot on the supported path, retaining the original fallback. |
| 125 | Forward system exports with generated assembly tail jumps | `proxy_exports`, `g_secur32Exports` | Current; avoids an extra wrapper frame/call at each forwarded export. |
| 126 | Retain proven clock-import slot addresses for later hook restoration | `HookImports`, `patch` | Candidate; saves re-enumerating imports, with module lifetime, bounded slot storage and full pointer/protection checks. |
| 127 | Resolve forwarded system exports lazily | `forward`, generated export stubs | Rejected without a demonstrated loader bottleneck and complete ABI/concurrency proof; forwarded delay binding is unsupported. |
| 128 | Use a supported persistent disk patch or a browser build that already permits MV2 | deployment/installer design | Conditional; removes repeated runtime authorization by changing the product/signature/update/restore contract, so it is a separate design. |

### Additional source-specific discovery and solver experiments

| # | Route and saved work | Source | Status and required condition |
| --- | --- | --- | --- |
| 129 | Avoid the register seeds immediately overwritten by `prefix()` | `Evaluator::verify/prefix` | Candidate; skip 32 constant queries only when prefix unconditionally replaces all registers; preserve early-return seeding. |
| 130 | Discover constants for all registers in one shared traversal | `Program::constantBefore`, evaluator seeding | Candidate; share predecessor/instruction reads across distinct register queries; retain individual ambiguity, call effects and analysis limits. |
| 131 | Directly initialize known-distinct entry-register expression IDs | `Program::guardedNoReturn` | Candidate; avoids 496 unsuccessful interning comparisons for 32 seeds; preserve exact IDs/order and the 96-expression limit. |
| 132 | Index exact guarded-call expression interning | `guardedNoReturn::intern` | Candidate; save repeated tuple scans while retaining canonical operands, insertion IDs, unknown results and capacity failures. |
| 133 | Replay reachability over lifted nodes after no-return classification | `Program::build` second decode | Candidate; avoid lifting the same immutable bytes again; preserve first-pass failures, traversal order, byte ownership and both limits. |
| 134 | Use ordered no-return membership or existing node flags | `Program::isNoReturn` | Candidate; replace repeated linear membership scans; retain all ordinary/Edge additions and the 16-entry limit. |
| 135 | Walk prefilter fall-through instructions directly | `prefilter` | Candidate; avoid worklist push/pop per straight-line instruction; preserve branch order, terminal handling and original 256-entry failures. |
| 136 | Index exact field interning | `Evaluator::field` | Candidate; avoid scanning up to 32 field tuples repeatedly; preserve first-discovery IDs, widths and overflow/unknown behavior. |
| 137 | Compute a known branch condition once for both outcomes | `Evaluator::walk/branch` | Candidate; avoid repeating flags arithmetic for taken/complementary paths; cover every x86/ARM64 condition and bit branch. |
| 138 | Examine only the zero wrap copy when interval addition is zero | `Evaluator::branch` interval inversion | Candidate; prove the two ±2³² copies cannot intersect the signed domain; retain the general path and INT32 boundary parity. |
| 139 | Drain bounded matching bit-test values from an ordered mask | `Evaluator::branch` | Candidate; replace per-value tests with set-bit iteration; emit identical singleton constraints/order and capacity failures. |
| 140 | Iterate only set changed-register bits at checkpoints | `falseCheckpoint`, store-outcome checks | Candidate; avoid testing all 32 registers; retain return-register exceptions and byte-store widths. |
| 141 | Resolve converted-flag uniqueness once per root base | `Evaluator::roleFor` | Candidate; avoid repeating a full field scan for every type/location pair; retain absent/multiple-flag rejection and field identity. |
| 142 | Collect ordered type/location field candidates before pairing | `Evaluator::verify` | Candidate; avoid repeated comparison-mask qualification in nested loops; preserve pair order, ambiguity and the eight-role limit. |
| 143 | Merge sorted Edge cold nodes with existing nodes directly | `providerProgram` | Candidate; replace nested overlap scans and final sorting; retain overlap/duplicate rejection, no-return updates and node limits. |
| 144 | Resolve immutable Edge export identity once per PE operation | `PeImage::isEdge`, provider analysis | Candidate; avoid repeated export/name RVA translation; bind to the validated immutable view and retain malformed-export behavior. |

### Additional source-specific runtime and cache experiments

| # | Route and saved work | Source | Status and required condition |
| --- | --- | --- | --- |
| 145 | Supply the bounded CNG object buffer without a per-call length query | `Hash`, `BCryptGetProperty` | Candidate; prove the supported provider accepts the 512-byte capacity; preserve oversized-provider/failure rejection and digest vectors. |
| 146 | Avoid clearing CNG-owned scratch fully initialized by the provider | `Hash` object storage | Candidate; prove complete initialization before use; preserve zeroed failure results and never expose uninitialized digest bytes. |
| 147 | Bypass repeated InitOnce helper calls after hash TLS publication | hash `enabled` | Candidate; use synchronized publication and preserve initialization failure, retirement, joined cleanup and no-static-TLS behavior. |
| 148 | Use an acquire read for QPC-hook patch-start state | proxy `counter` | Candidate; avoid locked read/RFO traffic while retaining the one-winner start CAS, pinning and cross-thread visibility. |
| 149 | Check primary-thread identity before QPC-hook atomic state | proxy `counter` | Candidate; avoid patch-start state access on worker QPC calls; preserve LastError, forwarding and main-thread ordering. |
| 150 | Read proven calibrated loader-lock state directly with fault handling | `LoaderLock::outside` | Conditional; avoid ReadProcessMemory only with stable pointer/calibration proof, memory ordering and fail-closed SEH. |
| 151 | Validate the pinned hook-replacement code page once per swap transaction | `HookImports` | Candidate; avoid repeated replacement-page queries; prove lifetime/RX protection through swap/rollback and keep every slot check. |
| 152 | Batch import-pointer swaps on the same validated IAT data page | `HookImports` | Candidate; reduce data-page protection calls; retain atomic pointer checks, per-slot rollback, readonly restoration and fatal failure handling. |
| 153 | Delay-load direct crypto dependencies used after loader-lock release | `secur32` imports, runtime hashes/cache | Conditional; reduce forwarding-only child load work; ensure no DllMain crypto calls and deterministic load-failure decline on supported Windows. |
| 154 | Hash the small scanner DLL using one bounded buffered read | `scannerHash` | Candidate; avoid scanner mapping/unmapping and view faults; retain full bytes, size/short-read checks and deny-write ownership; measure allocation/copy cost. |
| 155 | Carry the parent's first image-region query into immediate application | runtime `Patch`, `ApplyPlan` | Conditional; private one-operation module/mapping proof must stay valid; ordinary callers still query; this differs from the merged readability walk. |
| 156 | Remove the inner SHA checksum in a new fully authenticated DPAPI format | cache read/write | Conditional; prove whole-blob DPAPI integrity, keep strict plan/length and scanner/image bindings, migrate protocol and reject old caches. |
| 157 | Store only used sites in the protected disk-cache payload | cache serialization | Conditional; save DPAPI/IO over unused 64-site capacity; authenticate count/length, bound decode, reconstruct deterministically and migrate protocol. |
| 158 | Create the cache directory first and its ancestor only when missing | `WriteCache` directory creation | Candidate; avoid unconditional ancestor CreateDirectory; distinguish files/existing directories and retain bounded paths/error fallback. |
| 159 | Publish disposable cache atomically without synchronous durability barriers | `WriteCache` publication | Conditional; power loss may lose the plan and require rediscovery; keep complete writes, atomic replacement and authentication; stock/browser files unchanged. |
| 160 | Carry privately validated generated identities through path/read operations | `CachePath`, `ReadCache` | Conditional; save repeated hex scans only inside one operation; external identities and decrypted cache bytes still receive full validation. |

Unsafe shortcuts are not counted as usable speedups: filename/timestamp/USN-only
identity, CRC/xxHash authorization, text-only hashing, site-only code comparison,
unverified old RVAs, dropping ambiguity search, RWX writes and skipped rollback
all weaken the existing contract. Disabling antivirus or changing the machine's
global power/priority settings has no justified implementation here. More code,
workers, prefetch or a wider ISA is selected only after it wins the relevant
complete path and preserves the full result.

<!-- all-experiments-2026-11-14:begin -->
## November 14 execution of all remaining experiments

The frozen baseline is the current source and the `728f30ed...` x64 DLL.
This execution ledger covers all 113 remaining candidate/conditional routes.
Each outcome distinguishes actual measurements from correctness failures and
environment or architecture blockers. Pending work is not counted as tested.
Variant sources, raw samples and assertions are retained under
`_scratch/all-experiments-2026-11-14/`.

Status counts: 30 measured-win, 77 no-gain, 6 skipped-unavailable.

| # | Experiment | Execution outcome | Evidence |
| --- | --- | --- | --- |
| 4 | Tune the 16 MiB fork threshold to the measured complete startup crossover | measured-win: 4/8 MiB thresholds improved isolated full-file kernels, but 12 browser pairs each showed paired -1.23% / -0.30% reductions and only 6/12 faster. Keep the existing 16 MiB threshold. | scheduler.jsonl, scheduler-summary.json, hash_bench.cpp, threshold4.inc, threshold8.inc, threshold32.inc, confirm-threshold4/results.json, confirm-threshold8/results.json |
| 5 | Compare physical-core and SMT worker budgets | no-gain: No consistent improvement against current scheduler; exact full-file and concurrent/threshold parity passed. | scheduler.jsonl, scheduler-summary.json, hash_bench.cpp, budget1.inc, budget2.inc, budget4.inc |
| 6 | Cap workers by input size in addition to available CPUs | no-gain: No consistent improvement against current scheduler; exact full-file and concurrent/threshold parity passed. | scheduler.jsonl, scheduler-summary.json, hash_bench.cpp, inputcap6.inc |
| 8 | Reuse a bounded set of coarse hash work objects | no-gain: No consistent improvement against current scheduler; exact full-file and concurrent/threshold parity passed. | scheduler.jsonl, scheduler-summary.json, hash_bench.cpp, reuse8.inc |
| 9 | Measure a dedicated hash callback environment against the shared pool | no-gain: No consistent improvement against current scheduler; exact full-file and concurrent/threshold parity passed. | scheduler.jsonl, scheduler-summary.json, hash_bench.cpp, pool9.inc |
| 10 | Resolve `TlsGetValue2` once and use it when supported | no-gain: Full-file retained/fresh hash matrix produced no consistent improvement; six native init/install/restore/retirement/concurrency fixtures passed. | tls.jsonl, tls-summary.json, tls-fixtures.json, tls210.inc |
| 11 | Replace read-only interlocked TLS-retirement checks with acquire loads | no-gain: Full-file retained/fresh hash matrix produced no consistent improvement; six native init/install/restore/retirement/concurrency fixtures passed. | tls.jsonl, tls-summary.json, tls-fixtures.json, atomic11.inc |
| 12 | Reuse a CNG SHA-256 hash object for sequential small internal hashes | measured-win: Isolated CNG kernel measured; nanosecond savings do not establish browser startup savings. | cng_bench.cpp, cng_variants.inc, cng.jsonl, cng-summary.json, source-evidence.json |
| 13 | Keep digests binary internally and encode only at filename/report boundaries | no-gain: Raw digest microbenchmark and explicit binary protocol version/invalid-hex rejection, complete field roundtrip, cache-key reconstruction and DPAPI authentication passed. No material plan-sized kernel gain; protocol migration unselected. | cng_bench.cpp, cng_variants.inc, cng.jsonl, cng-summary.json, source-evidence.json |
| 14 | Stop before hashing when PE inspection already proves the input invalid | measured-win: Malformed 32 MiB PE is rejected before hashing; error-path saving only, valid stock identity unchanged. | hash_bench.cpp, invalid.jsonl, invalid-summary.json, invalid-execution.json |
| 15 | Reuse scanner identity within one proven immutable scanner lifetime | measured-win: x64 component prototype; no complete browser gain implied | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\quick-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\quick-sources.json |
| 19 | Prefetch a bounded rolling stock-file window ahead of compression | no-gain: Host-runnable full-file hash experiment completed without a consistent gain. No global memory/cache/power changes. | hash_bench.cpp, prefetch.jsonl, prefetch-summary.json, prefetch-execution.json |
| 20 | Prefetch the corresponding live-code window ahead of equality | no-gain: full retained-stock/live-image ApplyPlan component prototype; hashing/discovery/browser startup excluded | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-chrome.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-edge.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\apply_20.cpp |
| 21 | Double-buffer stock reads while hashing the previous buffer | no-gain: Warm-file full-digest IO matrix completed. Double buffering beats synchronous 32 MiB reads but not canonical fresh mapping; no production startup gain. | io_bench.cpp, io.jsonl, io-summary.json, io-selftest.jsonl |
| 22 | Use overlapped reads where storage completion is the bottleneck | no-gain: Full-digest IO matrix completed; no consistent improvement over relevant baseline. | io_bench.cpp, io.jsonl, io-summary.json, io-selftest.jsonl |
| 23 | Test aligned unbuffered reads on a cold sequential workload | no-gain: Full-digest IO matrix completed; no consistent improvement over relevant baseline. | io_bench.cpp, io.jsonl, io-summary.json, io-selftest.jsonl |
| 24 | Add sequential-read hints to an explicit buffered-read variant | no-gain: Full-digest IO matrix completed; no consistent improvement over relevant baseline. | io_bench.cpp, io.jsonl, io-summary.json, io-selftest.jsonl |
| 25 | Window file mappings when x86 address-space pressure dominates | no-gain: Full-digest IO matrix completed; no consistent improvement over relevant baseline. | io_bench.cpp, io.jsonl, io-summary.json, io-selftest.jsonl |
| 26 | Retain a fully touched mapping across repeated operations with a real owner | measured-win: Retained fully touched mapping speeds repeated hashes; initial mapping/touch setup recorded separately. New browser processes still need fresh mappings, so no startup gain inferred. | io_bench.cpp, io.jsonl, io-summary.json, io-selftest.jsonl |
| 27 | Place worker-private scratch on the NUMA node that runs the worker | skipped-unavailable: User explicitly skipped unavailable NUMA hardware. Actual NUMA-private allocation and node-affinity digest parity passed on the only available node; no multi-node speed claim. | hash_bench.cpp, hardware.jsonl, out-x64/hash-bench.exe |
| 28 | Assign adjacent hash/comparison spans to the same NUMA locality | skipped-unavailable: User explicitly skipped unavailable NUMA hardware. Actual NUMA-private allocation and node-affinity digest parity passed on the only available node; no multi-node speed claim. | hash_bench.cpp, hardware.jsonl, out-x64/hash-bench.exe |
| 29 | Prefer performance cores or scoped performance QoS for startup callbacks | no-gain: No consistent improvement against current scheduler; exact full-file and concurrent/threshold parity passed. | scheduler.jsonl, scheduler-summary.json, hash_bench.cpp, qos29.inc |
| 30 | Reduce concurrency at the measured low-memory crossover | no-gain: Host-runnable full-file hash experiment completed without a consistent gain. No global memory/cache/power changes. | hash_bench.cpp, pressure.jsonl, pressure-summary.json, pressure-execution.json |
| 32 | Tune deferred-cleanup priority/placement to avoid competing with browser initialization | measured-win: low-priority cleanup under controlled two-worker startup contention | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\cleanup-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\cleanup.cpp |
| 35 | Prepare the user's protected plan at install/update time | measured-win: native plan preparation/verification/rejection discovery component prototype | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\plans-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\plans.cpp, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\semantic-manifest.json |
| 36 | Ship signed precomputed plans for known exact browser digests | measured-win: native plan preparation/verification/rejection discovery component prototype | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\plans-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\plans.cpp, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\semantic-manifest.json |
| 37 | Single-flight concurrent misses for the same exact cache key | measured-win: native plan preparation/verification/rejection discovery component prototype | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\plans-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\plans.cpp, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\semantic-manifest.json |
| 38 | Cache deterministic unsupported-image results | measured-win: native plan preparation/verification/rejection discovery component prototype | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\plans-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\plans.cpp, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\semantic-manifest.json |
| 39 | Share identity through a continuously locked file-owner broker | measured-win: corrected isolated process protocol, inherited read-only capabilities, continuously locked files and private authenticated IPC | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc.cpp, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-corrected-validation.json, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\REVIEW.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\results.json, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\ipc-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\failed-review-results.json |
| 40 | Reuse unchanged cryptographic subtrees under authoritative change tracking | measured-win: actual exclusively tracked scratch-file writes; unchanged BLAKE3 tree CVs reused under continuous owner lock | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\tree-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\tree_cache.c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\tree.cpp |
| 41 | Bind cache compatibility to a complete semantic scanner version | measured-win: native plan preparation/verification/rejection discovery component prototype | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\plans-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\plans.cpp, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\semantic-manifest.json |
| 44 | Use pipe-ready notification instead of repeated `PeekNamedPipe` while waiting | no-gain: corrected isolated process protocol, inherited read-only capabilities, continuously locked files and private authenticated IPC | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc.cpp, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-corrected-validation.json, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\REVIEW.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\results.json, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\ipc-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\failed-review-results.json |
| 45 | Overlap durable cache publication with parent plan validation | measured-win: corrected isolated process protocol, inherited read-only capabilities, continuously locked files and private authenticated IPC | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc.cpp, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-corrected-validation.json, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\REVIEW.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\results.json, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\ipc-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\failed-review-results.json |
| 47 | Pass parent-verified scanner identity through a proven locked scanner mapping | measured-win: corrected isolated process protocol, inherited read-only capabilities, continuously locked files and private authenticated IPC | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc.cpp, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-corrected-validation.json, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\REVIEW.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\results.json, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\ipc-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\ipc-original-population\failed-review-results.json |
| 55 | Find both optional names in one physical `.rdata` traversal | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 56 | Use a packed byte-pair filter for literal matches | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 60 | Share vector loads between core-candidate and initial-reference searches | measured-win: Share vector loads between core-candidate and initial-reference searches | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\confirm-combo\results.json |
| 61 | Screen x86 absolute references by a selective byte pair | measured-win: Selected x86 upper-word filter: 16/16 paired Analyze runs faster, 66.37% paired reduction on authentic unbranded Chrome for Testing; 34 reports identical. Scalar fallback for more than 17 queries retained. | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\confirm61\results.json, discovery/confirm61/results.json |
| 62 | Widen supported candidate/reference masks to AVX2 | skipped-unavailable: User explicitly requested skipping unavailable native ISA/hardware cases. | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\hardware-probe.json, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c\autoscan.cpp |
| 63 | Use AVX-512 mask registers to reduce mask-drain overhead | skipped-unavailable: User explicitly requested skipping unavailable native ISA/hardware cases. | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\hardware-probe.json, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c\autoscan.cpp |
| 64 | Filter ARM64 ADRP/ADD/BL patterns with NEON lanes | skipped-unavailable: User explicitly requested skipping unavailable native ISA/hardware cases. | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\hardware-probe.json, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c\autoscan.cpp |
| 65 | Read runtime entries directly from one fully validated contiguous table span | measured-win: Selected validated contiguous table span: paired Analyze reduction 3.40% Chrome and 7.60% Edge, 16/16 faster each; 68 reports identical. All bounds, unwind/chaining and fallback checks retained. | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\confirm65\results.json, discovery/confirm65/results.json |
| 66 | Advance a runtime-table cursor for monotonically ordered candidate addresses | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 67 | Bypass a low-selectivity filter when measured match density is high | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 68 | Reuse a complete Program for consecutive candidates with identical exact bounds | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 72 | Scan ARM64 trailing BRK padding in bounded vector blocks | no-gain: Measured alternating-function ARM64 metadata trim kernel on x64; no native ARM64 timing or x64 browser-path gain. | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c\72-metadata.times, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c\72-metadata.times |
| 73 | Use occupancy generations to avoid clearing byte marks between decodes | no-gain: Use occupancy generations to avoid clearing byte marks between decodes | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 75 | Track pending branch targets to avoid redundant worklist visits | no-gain: Track pending branch targets to avoid redundant worklist visits | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 76 | Skip node sorting when decode output is already monotonically ordered | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 77 | Use a bounded PC-to-node index for repeated exact node lookup | no-gain: Use a bounded PC-to-node index for repeated exact node lookup | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 79 | Reorder decoder opcode groups using the actual instruction distribution | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 80 | Add validated fast paths for common simple encodings before generic length decoding | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 82 | Memoize exact constant-before queries within a Program generation | no-gain: Memoize exact constant-before queries within a Program generation | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 83 | Memoize pointer provenance for immutable code and identical entry assumptions | no-gain: Memoize pointer provenance for immutable code and identical entry assumptions | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 84 | Memoize exact argument-origin queries | no-gain: Memoize exact argument-origin queries | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 85 | Memoize private-stack-slot proofs | no-gain: Memoize private-stack-slot proofs | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 86 | Memoize exact stack-address queries | no-gain: Memoize exact stack-address queries | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 87 | Reuse exact callee return summaries | no-gain: Reuse exact callee return summaries | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 88 | Precompute each node's conservative register-write mask | no-gain: Precompute each node's conservative register-write mask | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 89 | Use bounded visitation marks for repeated PC-only safety traversals | no-gain: Use bounded visitation marks for repeated PC-only safety traversals | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 90 | Merge truly identical symbolic execution states | no-gain: Complete Analyze parity and six alternating pairs on Chrome/Edge; conservative terminal-state/liveness prototype only. | compiler/solver/90-chrome.jsonl, compiler/solver/90-edge.jsonl, compiler/solver/bench.cpp |
| 91 | Index exact visited-state membership instead of repeatedly scanning the seen list | no-gain: Index exact visited-state membership instead of repeatedly scanning the seen list | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 92 | Stop carrying provably dead register values through symbolic branches | no-gain: Complete Analyze parity and six alternating pairs on Chrome/Edge; conservative terminal-state/liveness prototype only. | compiler/solver/92-chrome.jsonl, compiler/solver/92-edge.jsonl, compiler/solver/bench.cpp |
| 93 | Index checkpoint addresses when a predicate has many checkpoints | no-gain: Index checkpoint addresses when a predicate has many checkpoints | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 94 | Evaluate prefix constants only for registers that influence the recognized predicate | no-gain: Evaluate prefix constants only for registers that influence the recognized predicate | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 95 | Precompute type/location interval membership reused by role verification | no-gain: Precompute type/location interval membership reused by role verification | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 96 | Reuse complete necessary-field summaries across same-range predicates | no-gain: Reuse complete necessary-field summaries across same-range predicates | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 100 | Query the available comparison CPU budget once per ApplyPlan operation | no-gain: full retained-stock/live-image ApplyPlan component prototype; hashing/discovery/browser startup excluded | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-chrome.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-edge.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\apply_100.cpp |
| 101 | Tune the comparator's 16 MiB split crossover | no-gain: full retained-stock/live-image ApplyPlan component prototype; hashing/discovery/browser startup excluded | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-chrome.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-edge.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\apply_1018.cpp, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\apply_10132.cpp |
| 102 | Compare four-way splitting against the current two-way comparator | no-gain: full retained-stock/live-image ApplyPlan component prototype; hashing/discovery/browser startup excluded | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-chrome.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-edge.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\apply_102.cpp |
| 104 | Fuse exact code equality into coarse BLAKE3 subtree reads | no-gain: Corrected C-SIMD fusion passed complete safety assertions but lost against canonical current assembly: paired -4.96% Chrome and -22.04% Edge across four alternating process triples/image. C-only also lost24–30%. Former fault populations and C-baseline gains preserved; no production/hint/protocol change selected. | fused-initial-checks.txt, fused-repaired-checks.txt, fused-hash-vectors.txt, fused-debug.json, fused-debug-console.txt, proof_engine.inc, proof_function.inc, fused-csimd-validation.json, fused-csimd-checks.txt, fused-csimd-faults.txt, fused-csimd-vectors.txt, fused_bench.cpp, fused.jsonl, fused-summary.json, fused-execution.json, canonical_bench.cpp, canonical_compare.py, canonical-observations.json, canonical-summary.json, canonical_bench.cpp, canonical_compare.py, canonical-observations.json, canonical-summary.json |
| 107 | Merge validated sorted relocation entries and ordered patch gaps in one traversal | no-gain: full retained-stock/live-image ApplyPlan component prototype; hashing/discovery/browser startup excluded | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-chrome.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-edge.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\apply_107.cpp |
| 108 | Normalize dense relocated words into bounded contiguous comparison buffers | no-gain: full retained-stock/live-image ApplyPlan component prototype; hashing/discovery/browser startup excluded | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-chrome.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-edge.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\apply_108.cpp |
| 111 | Coalesce adjacent compatible decision pages into protection ranges | no-gain: full retained-stock/live-image ApplyPlan component prototype; hashing/discovery/browser startup excluded | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-chrome.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-edge.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\apply_111.cpp |
| 112 | Flush only changed instruction ranges/pages | no-gain: full retained-stock/live-image ApplyPlan component prototype; hashing/discovery/browser startup excluded | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-chrome.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-edge.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\apply_112.cpp |
| 116 | Train instrumented PGO on the actual release DLL | no-gain: Alternating actual Chrome launches with exact patched memory, sandbox, protected-cache and stock-file checks; stage-specific subvariants in metrics. | current-pgo-training/results.json, compiler/pgo-normal.dll, compiler-pgo-normal\results.json, compiler-pgo-aggressive\results.json |
| 117 | Train release-DLL SPGO using real startup samples | skipped-unavailable: User requested skipping unavailable cases; current token lacks SeSystemProfilePrivilege. Current-source SPGO build and host probe retained. | compiler/host-probe.json, compiler/spgo/build.log |
| 118 | Tune MSVC `/favor` to supported deployment CPUs | no-gain: Atom six-pair8.43%screening gain fell to2.16%and7/12faster in independent confirmation; other /favor variants regressed. No compilerflag selected; exact artifact ISA audit retained. | compiler/{blend,intel64,amd64,atom}/build.log, compiler-intel64\results.json, compiler-amd64\results.json, compiler-atom\results.json, confirm-atom/results.json |
| 119 | Order hot/cold functions from measured release-DLL profiles | no-gain: Alternating actual Chrome launches with exact patched memory, sandbox, protected-cache and stock-file checks; stage-specific subvariants in metrics. | compiler/order/order-selection.json, compiler/order/build.log, compiler-order\results.json |
| 126 | Retain proven clock-import slot addresses for later hook restoration | no-gain: bounded synthetic IAT transaction using production SwapPointer semantics; no browser gain implied | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\hooks-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\hooks.cpp |
| 128 | Use a supported persistent disk patch or a browser build that already permits MV2 | measured-win: Isolated persistent disk-patch design improved browser startup by 25.13%, 6/6 pairs faster, with all nine sites/checksum/full-file differences verified. Different signature/update/restore contract; keep the runtime patcher deployment unchanged. | compiler/disk128/report.json, compiler/disk128/complete.ps1, compiler-disk\results.json |
| 129 | Avoid the register seeds immediately overwritten by `prefix()` | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 130 | Discover constants for all registers in one shared traversal | measured-win: Discover constants for all registers in one shared traversal | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\confirm-combo\results.json |
| 131 | Directly initialize known-distinct entry-register expression IDs | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 132 | Index exact guarded-call expression interning | no-gain: Index exact guarded-call expression interning | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 133 | Replay reachability over lifted nodes after no-return classification | no-gain: Replay reachability over lifted nodes after no-return classification | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 134 | Use ordered no-return membership or existing node flags | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 135 | Walk prefilter fall-through instructions directly | no-gain: Walk prefilter fall-through instructions directly | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 136 | Index exact field interning | no-gain: Index exact field interning | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-c, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_b.py, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch_c.py |
| 137 | Compute a known branch condition once for both outcomes | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 138 | Examine only the zero wrap copy when interval addition is zero | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 139 | Drain bounded matching bit-test values from an ordered mask | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 140 | Iterate only set changed-register bits at checkpoints | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 141 | Resolve converted-flag uniqueness once per root base | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 142 | Collect ordered type/location field candidates before pairing | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 143 | Merge sorted Edge cold nodes with existing nodes directly | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 144 | Resolve immutable Edge export identity once per PE operation | no-gain: isolated runtime ID in a frozen-source candidate executable | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\batch-a, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\discovery\prepare_batch.py |
| 145 | Supply the bounded CNG object buffer without a per-call length query | measured-win: Isolated CNG kernel measured; nanosecond savings do not establish browser startup savings. | cng_bench.cpp, cng_variants.inc, cng.jsonl, cng-summary.json, source-evidence.json |
| 146 | Avoid clearing CNG-owned scratch fully initialized by the provider | no-gain: Isolated CNG kernel measured; nanosecond savings do not establish browser startup savings. | cng_bench.cpp, cng_variants.inc, cng.jsonl, cng-summary.json, source-evidence.json |
| 147 | Bypass repeated InitOnce helper calls after hash TLS publication | no-gain: Full-file retained/fresh hash matrix produced no consistent improvement; six native init/install/restore/retirement/concurrency fixtures passed. | tls.jsonl, tls-summary.json, tls-fixtures.json, publish147.inc |
| 148 | Use an acquire read for QPC-hook patch-start state | measured-win: Acquire-state read improved the x64 kernel, but six browser pairs were mixed: 9.16% paired reduction, only 4/6 faster, two regressions. Keep production proxy unchanged. | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\quick-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\quick-sources.json, confirm-proxy148/results.json, runtime/review65_148.md |
| 149 | Check primary-thread identity before QPC-hook atomic state | measured-win: x64 component prototype; no complete browser gain implied | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\quick-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\quick-sources.json |
| 150 | Read proven calibrated loader-lock state directly with fault handling | measured-win: x64 component prototype; no complete browser gain implied | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\quick-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\quick-sources.json |
| 151 | Validate the pinned hook-replacement code page once per swap transaction | measured-win: bounded synthetic IAT transaction using production SwapPointer semantics; no browser gain implied | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\hooks-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\hooks.cpp |
| 152 | Batch import-pointer swaps on the same validated IAT data page | measured-win: bounded synthetic IAT transaction using production SwapPointer semantics; no browser gain implied | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\hooks-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\hooks.cpp |
| 153 | Delay-load direct crypto dependencies used after loader-lock release | measured-win: actual release secur32 DLL delay-import prototype with fail-closed post-loader crypto guards | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\delay-failure.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\delay-native\CMakeLists.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\delay-native\autoscan.cpp, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\delay-native\autoscan_cache.cpp |
| 154 | Hash the small scanner DLL using one bounded buffered read | no-gain: Two component populations conflict or lack enough consistent paired wins; retain baseline until complete-path confirmation. | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\quick-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\quick-sources.json |
| 155 | Carry the parent's first image-region query into immediate application | no-gain: full retained-stock/live-image ApplyPlan component prototype; hashing/discovery/browser startup excluded | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-chrome.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\compare-edge.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\apply_155.cpp |
| 156 | Remove the inner SHA checksum in a new fully authenticated DPAPI format | measured-win: isolated protected-cache format/IO experiment; no browser gain implied | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\cache-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\cache_156.cpp |
| 157 | Store only used sites in the protected disk-cache payload | measured-win: isolated protected-cache format/IO experiment; no browser gain implied | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\cache-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\cache_157.cpp |
| 158 | Create the cache directory first and its ancestor only when missing | no-gain: Two component populations conflict or lack enough consistent paired wins; retain baseline until complete-path confirmation. | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\quick-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\quick-sources.json |
| 159 | Publish disposable cache atomically without synchronous durability barriers | measured-win: isolated protected-cache format/IO experiment; no browser gain implied | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\cache-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\cache_159.cpp |
| 160 | Carry privately validated generated identities through path/read operations | no-gain: isolated protected-cache format/IO experiment; no browser gain implied | C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\cache-raw.txt, C:\Users\Admin\source\repos\chrome-mv2-patch\_scratch\all-experiments-2026-11-14\runtime\cache_160.cpp |

<!-- all-experiments-2026-11-14:end -->
