// Test-only made-up byte arrays check that code comparisons detect differences in either half.
// Also check that background comparisons finish before the memory they read can be released.
#define NOMINMAX
#include <windows.h>
#include "autoscan.h"
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {
unsigned threads = 2, workers = 0, joins = 0, checks = 0;
bool failWork = false;
unsigned testThreads() noexcept { return threads; }
PTP_WORK WINAPI testWork(PTP_WORK_CALLBACK callback, void* context, PTP_CALLBACK_ENVIRON environment) {
  ++workers;
  return failWork ? nullptr : CreateThreadpoolWork(callback, context, environment);
}
void WINAPI testJoin(PTP_WORK work, BOOL cancel) {
  ++joins;
  WaitForThreadpoolWorkCallbacks(work, cancel);
}
void check(bool ok, const char* message) {
  ++checks;
  if (!ok) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
}
#define HashThreadCount testThreads
#define CreateThreadpoolWork testWork
#define WaitForThreadpoolWorkCallbacks testJoin
#include "text_compare.hpp"
#undef HashThreadCount
#undef CreateThreadpoolWork
#undef WaitForThreadpoolWorkCallbacks

int main() {
  constexpr size_t threshold = 16 * 1024 * 1024;
  std::vector<uint8_t> live(threshold + 3), stock(live.size());
  for (size_t n = 0; n < live.size(); ++n) live[n] = stock[n] = static_cast<uint8_t>(n * 17);
  for (unsigned budget : {1u, 2u}) for (bool failure : {false, true}) {
    threads = budget; failWork = failure;
    for (size_t size : {size_t{0}, size_t{1}, threshold - 1, threshold, threshold + 1}) {
      workers = joins = 0;
      auto equal = [&] { return autoscan::SameBytes(live.data() + 1, stock.data() + 1, size); };
      check(equal(), "equal unaligned and odd-length ranges pass");
      bool attempted = size >= threshold && budget > 1;
      check(workers == unsigned(attempted) && joins == unsigned(attempted && !failure),
            "small/single-CPU/failure paths remain serial; successful workers join");
      if (!size) continue;
      for (size_t at : {size_t{0}, size / 2 - (size > 1), size / 2, size - 1}) {
        live[at + 1] ^= 1;
        unsigned before = joins;
        check(!equal(), "mismatches in either half and at the split decline");
        check(joins == before + unsigned(attempted && !failure), "mismatch still joins its callback");
        live[at + 1] ^= 1;
      }
    }
  }
  std::printf("%u text comparison checks passed\n", checks);
}
