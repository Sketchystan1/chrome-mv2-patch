// Calculate file fingerprints with BLAKE3, using Windows background workers for large inputs.
// These workers read supplied bytes; this file does not open files or send their contents anywhere.
#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <bit>
#include "autoscan.h"
#include "blake3_impl.h"

namespace autoscan {
unsigned HashThreadCount() noexcept {
  // Stay within the processors Windows allows this process to use.
  DWORD_PTR mask = 0, system = 0;
  unsigned count = GetProcessAffinityMask(GetCurrentProcess(), &mask, &system) && mask
    ? std::popcount(mask) : GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
  if (mask && mask == system) {
    std::array<USHORT, 64> groups{}; USHORT size = static_cast<USHORT>(groups.size());
    if (GetProcessGroupAffinity(GetCurrentProcess(), &size, groups.data()) && size > 1 && size <= groups.size()) {
      unsigned grouped = 0;
      for (USHORT n = 0; n < size; ++n) grouped += GetActiveProcessorCount(groups[n]);
      if (grouped) count = grouped;
    }
  }
  ULONG selected = 0;
  if ((GetProcessDefaultCpuSets(GetCurrentProcess(), nullptr, 0, &selected) || GetLastError() == ERROR_INSUFFICIENT_BUFFER) && selected)
    count = std::min(count, static_cast<unsigned>(selected));
  return std::max(count, 1u);
}
}

namespace {
INIT_ONCE budgetOnce = INIT_ONCE_STATIC_INIT;
DWORD budgetIndex = TLS_OUT_OF_INDEXES;
LONG budgetEnabled = 1;
LONG active = 0;
struct Budget { unsigned threads = 0, total = 0; };
BOOL CALLBACK initializeBudget(PINIT_ONCE, void*, void**) {
  budgetIndex = TlsAlloc();
  if (budgetIndex == TLS_OUT_OF_INDEXES) InterlockedExchange(&budgetEnabled, 0);
  return TRUE;
}
bool enabled() {
  return InterlockedCompareExchange(&budgetEnabled, 0, 0) &&
    InitOnceExecuteOnce(&budgetOnce, initializeBudget, nullptr, nullptr) &&
    InterlockedCompareExchange(&budgetEnabled, 0, 0);
}
Budget currentBudget() {
  // If per-thread bookkeeping fails, fingerprint with one worker instead of guessing a limit.
  if (!enabled()) return {1, 1};
  auto value = static_cast<const Budget*>(TlsGetValue(budgetIndex));
  return value ? *value : Budget{};
}
struct BudgetScope {
  DWORD lastError = GetLastError();
  Budget value{};
  void* previous = nullptr;
  bool installed = false;
  explicit BudgetScope(Budget target = {}) { if (target.threads) install(target); }
  bool install(Budget target) {
    if (!enabled()) return false;
    previous = TlsGetValue(budgetIndex); value = target;
    installed = TlsSetValue(budgetIndex, &value) != FALSE;
    return installed;
  }
  ~BudgetScope() {
    if (installed && InterlockedCompareExchange(&budgetEnabled, 0, 0) &&
        !TlsSetValue(budgetIndex, previous)) {
      // Stop using this bookkeeping if Windows cannot restore it before its storage expires.
      InterlockedExchange(&budgetEnabled, 0);
    }
    SetLastError(lastError);
  }
};
struct Task {
  const uint8_t* input;
  size_t size;
  const uint32_t* key;
  uint64_t counter;
  uint8_t flags;
  uint8_t* cvs;
  size_t* count;
  Budget budget;
};
void CALLBACK compress(PTP_CALLBACK_INSTANCE instance, void* raw, PTP_WORK) {
  auto& task = *static_cast<Task*>(raw);
  BudgetScope scope(task.budget);
  CallbackMayRunLong(instance);
  *task.count = blake3_compress_subtree_wide(task.input, task.size, task.key,
    task.counter, task.flags, task.cvs, scope.installed);
  InterlockedDecrement(&active);
}
}

namespace autoscan {
void ReleaseHashTls() noexcept {
  // Release only the Windows bookkeeping slot owned by this fingerprinting code.
  DWORD error = GetLastError();
  InterlockedExchange(&budgetEnabled, 0);
  if (budgetIndex != TLS_OUT_OF_INDEXES) {
    TlsFree(budgetIndex); budgetIndex = TLS_OUT_OF_INDEXES;
  }
  SetLastError(error);
}
}

// BLAKE3 names this callback "tbb", but this implementation uses Windows' own worker pool.
extern "C" void blake3_compress_subtree_wide_join_tbb(
    const uint32_t key[8], uint8_t flags, bool use_tbb,
    const uint8_t* l_input, size_t l_input_len, uint64_t l_chunk_counter, uint8_t* l_cvs, size_t* l_n,
    const uint8_t* r_input, size_t r_input_len, uint64_t r_chunk_counter, uint8_t* r_cvs, size_t* r_n) noexcept {
  if (use_tbb && l_input_len + r_input_len >= 16 * 1024 * 1024) {
    // Split large jobs only when another worker fits the processor limit; small jobs stay local.
    BudgetScope scope;
    auto allowed = currentBudget();
    if (!allowed.threads) allowed.threads = allowed.total = autoscan::HashThreadCount();
    if (allowed.threads > 1) {
      LONG count = InterlockedIncrement(&active);
      if (count < static_cast<LONG>(allowed.total)) {
        Task task{l_input, l_input_len, key, l_chunk_counter, flags, l_cvs, l_n, {allowed.threads / 2, allowed.total}};
        if (scope.install({allowed.threads - task.budget.threads, allowed.total})) {
          PTP_WORK worker = CreateThreadpoolWork(compress, &task, nullptr);
          if (worker) {
            SubmitThreadpoolWork(worker);
            *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key, r_chunk_counter, flags, r_cvs, true);
            WaitForThreadpoolWorkCallbacks(worker, FALSE);
            CloseThreadpoolWork(worker);
            return;
          }
        }
      }
      InterlockedDecrement(&active);
    }
  }
  *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key, l_chunk_counter, flags, l_cvs, false);
  *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key, r_chunk_counter, flags, r_cvs, false);
}
