The eight-thread ceiling was a measured prototype choice, not a system limit or a
Microsoft recommendation. It has been removed from the implementation. Hashing
now budgets against the process's processor affinity, eligible processor groups
and default CPU-set count. Balanced subtrees and the existing 16 MiB fork
threshold keep the amount of work appropriate to the input. The scheduler places
threads on cores; this does not claim benchmark-optimal placement on every CPU.

The shared-reference experiment is also implemented. Anchor names are collected
once and their references share a `.text` traversal. Each literal retains its own
64-hit overflow status, and each recognizer keeps its absent/ambiguous-name rules.
All changes remain uncommitted after undoing the latest research commit.

**Microsoft examples and their relevance**

| Official example | Appropriate use here |
| --- | --- |
| [Using the Thread Pool Functions](https://learn.microsoft.com/en-us/windows/win32/procthread/using-the-thread-pool-functions) | `CreateThreadpoolWork`, submission, callback completion and closing work objects. The native adapter follows this lifetime pattern and retains serial failure fallback. |
| [PPL partitioning work](https://learn.microsoft.com/en-us/cpp/parallel/concrt/parallel-algorithms?view=msvc-170#partitioning-work) | `static_partitioner` suits fixed uniform iterations; `auto_partitioner` supports redistribution for uneven work. Range counts typically follow available workers. Neither suggests a fixed eight-thread cap. |
| [General Concurrency Runtime best practices](https://learn.microsoft.com/en-us/cpp/parallel/concrt/general-best-practices-in-the-concurrency-runtime?view=msvc-170) | Use lightweight tasks and cooperative waits; oversubscription is useful for blocking/high-latency operations, rather than a general CPU-throughput rule. |
| [Native thread-pool best practices](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-pools#best-practices) | Mark long-running/blocking callbacks, avoid dependency deadlocks and uncontrolled queuing, and retain callback/DLL lifetime safety. Pool capacity is not the desired number of hashing threads. |
| [Processor-group affinity](https://learn.microsoft.com/en-us/windows/win32/api/processtopologyapi/nf-processtopologyapi-getprocessgroupaffinity) | A primary-group affinity mask alone can undercount a process assigned to multiple groups. Eligible group counts must be considered. |

The PPL uniform-work pattern is:

```cpp
concurrency::parallel_for(size_t{0}, count,
    [&](size_t index) { process(index); },
    concurrency::static_partitioner());
```

For irregular work, the default/auto partitioner can rebalance ranges. For the
recursive BLAKE3 join, the research comparison used `parallel_invoke` for the two
subtrees, leaving the upstream compression and digest construction unchanged.
The native comparison used the same upstream library with the current balanced
work callback adapter.

**Measured native pool versus PPL**

| Locked-input identity work on retained mappings | Native pool | PPL `parallel_invoke` |
| --- | ---: | ---: |
| 301.7 MB input | 58.648 ms | 62.321 ms |
| 535.5 MB input | 108.721 ms | 104.563 ms |

Each provider has 20 observations per image in forward/reverse provider order,
after a digest-checked warm-up. All digests matched. PPL was about 6% slower for
the first input and 4% faster for the second, with greater CPU time in both.
There is no consistent winner sufficient to justify changing the runtime
dependency or allocation model. The implementation keeps native work callbacks.
These are hash measurements, not complete browser launch timings. Raw order,
observations and artifact identities are in [PERFORMANCE-THREADING.json](PERFORMANCE-THREADING.json).

The new code passed 10/10 x64 and 7/7 x86 tests, including CPU budgets above eight,
multiple groups and query-failure cases. All 23 reviewed scan reports and both
ARM64 analysis reports matched, and all three isolated browser lifecycles passed.
ARM64 reference and simulated CPU-budget executables also passed under emulation.
The real CPU-set API remains unsupported there, so native ARM64 hashing/browser
validation is still required. The three deployment DLLs remain below 300,000 bytes.

CPU counts above eight are tested with simulated topology. Performance on larger
processor systems and controlled cold boots remain unmeasured. More available
threads can improve throughput, but memory bandwidth, scheduling and workload size
still determine whether they improve launch latency.

Skipped: adding PPL to deployment or changing user CPU/power policy. Native ARM64
and controlled cold boots remain unchecked; higher concurrency can use more CPU.
