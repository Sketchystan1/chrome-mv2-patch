#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <bit>
#include "autoscan.h"
#include "blake3_impl.h"

namespace autoscan {
unsigned HashThreadCount() noexcept {
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
LONG active = 0;
struct Budget { unsigned threads = 0, total = 0; };
thread_local Budget budget;
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
  CallbackMayRunLong(instance);
  auto& task = *static_cast<Task*>(raw);
  auto previous = budget; budget = task.budget;
  *task.count = blake3_compress_subtree_wide(task.input, task.size, task.key, task.counter, task.flags, task.cvs, true);
  budget = previous;
  InterlockedDecrement(&active);
}
}

// Upstream names this join hook "tbb"; scheduling uses Windows without a TBB dependency.
extern "C" void blake3_compress_subtree_wide_join_tbb(
    const uint32_t key[8], uint8_t flags, bool use_tbb,
    const uint8_t* l_input, size_t l_input_len, uint64_t l_chunk_counter, uint8_t* l_cvs, size_t* l_n,
    const uint8_t* r_input, size_t r_input_len, uint64_t r_chunk_counter, uint8_t* r_cvs, size_t* r_n) noexcept {
  if (use_tbb && l_input_len + r_input_len >= 16 * 1024 * 1024) {
    auto allowed = budget;
    if (!allowed.threads) allowed.threads = allowed.total = autoscan::HashThreadCount();
    if (allowed.threads > 1) {
      LONG count = InterlockedIncrement(&active);
      if (count < static_cast<LONG>(allowed.total)) {
        Task task{l_input, l_input_len, key, l_chunk_counter, flags, l_cvs, l_n, {allowed.threads / 2, allowed.total}};
        PTP_WORK worker = CreateThreadpoolWork(compress, &task, nullptr);
        if (worker) {
          SubmitThreadpoolWork(worker);
          auto previous = budget; budget = {allowed.threads - task.budget.threads, allowed.total};
          *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key, r_chunk_counter, flags, r_cvs, true);
          budget = previous;
          WaitForThreadpoolWorkCallbacks(worker, FALSE);
          CloseThreadpoolWork(worker);
          return;
        }
      }
      InterlockedDecrement(&active);
    }
  }
  *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key, l_chunk_counter, flags, l_cvs, false);
  *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key, r_chunk_counter, flags, r_cvs, false);
}
