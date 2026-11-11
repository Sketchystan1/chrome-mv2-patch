Sharing reference searches reduced **first-discovery analysis time by 14–22%** in
the next research experiment. This is an additional candidate after the adaptive
hashing, deferred cleanup and exact trim cache committed in `56f893c`.

The two optional recognizers currently search the same `.text` separately for
`InstallVerifier` and `apps-gallery-url`. The prototype collects a bounded set of
literal targets and checks them during one reference traversal. Each target keeps
its original 64-hit limit and complete/incomplete result. Overflow for one target
does not stop discovery of another. Unsupported targets use the original
single-target behavior. Decoder, provenance and optional-gate decisions remain
unchanged.

| Image | Current analysis | Shared references | Reduction |
| --- | ---: | ---: | ---: |
| Chrome 153.0.8010.37 x64 | 605.510 ms | 517.195 ms | 14.59% |
| Chromium 157.0.8103.39 x64 | 557.269 ms | 477.631 ms | 14.29% |
| DCHECK Chrome 159.0.8148.1 x64 | 972.342 ms | 757.618 ms | 22.08% |

Variants ran in `current, batch, batch, current` order, with five analyses per
retained mapping. The first observation in each process is kept in the raw data
and excluded from these medians, leaving eight samples per variant/image. Hashing
is excluded. File-cache state and background load were uncontrolled. These timings
measure discovery; a valid cached plan bypasses this work.

All 60 benchmark reports matched completely after excluding diagnostic hash
fields. Another 105 reports across the 21 reviewed x64 files also matched. The
reference self-check passed 64 fixtures covering SIMD tails, unaligned starts,
63/64/65-reference boundaries, an overflowing target followed by a valid target,
absent anchor names and an uncached literal.

The main saving appears in CRX analysis: its reference traversal has already been
completed for the other recognizer. Normal-image CRX analysis fell from roughly
236–244 ms to 137–138 ms. The diagnostic layout fell from 246 ms to 16 ms because
most of its unsuccessful optional analysis was reference search. InstallVerifier
became slightly slower because it pays for the shared traversal and extra literal
collection up front; total analysis still improved.

The smallest next implementation should collect anchor literals once, preserve
each recognizer's absent/ambiguous-name behavior, and share reference results for
that immutable image. The research prototype repeats some `.rdata` collection to
keep the comparison simple. Removing those extra scans is another bounded follow-up.
It must retain independent overflow handling and complete report parity.

The shared traversal and single literal collection are now implemented in the
working tree. Native x64/x86 reference tests, all reviewed image reports,
cross-builds and three browser lifecycles passed; see
[the current threading/implementation record](PERFORMANCE-THREADING.md).
Native ARM64 runtime validation remains unchecked. The remaining large cached-path
opportunity is concurrent whole-file hashing and complete preflight validation,
joined before any instruction write.

[Raw observations and artifact/source identities](PERFORMANCE-NEXT.json) ·
[Broader optimization catalogue](PERFORMANCE-DEEP-DIVE.md)

Skipped: installing the working-tree build or changing the cache/validation protocol.
Cold boots and native ARM64 remain unchecked; this experiment does not establish
an additional cached-startup speedup.
