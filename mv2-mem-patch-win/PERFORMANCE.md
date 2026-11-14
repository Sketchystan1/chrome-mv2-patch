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
adds active-range occupancy clearing and a rarer gallery-literal anchor.

This is the single record for the former performance Markdown/JSON reports and the
scanner, carrier and Edge result files. It retains measured summaries, validation,
distinct optimization proposals, limitations and primary sources. Repetitive raw
per-run samples and obsolete absolute scratch paths are preserved in Git history;
the provenance table below identifies their exact records. Research from November
11–12, 2026 used the historical `version.dll` carrier. Those measurements do not
establish identical timings for the current `secur32.dll`, and separate percentage
improvements must not be added together.

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

