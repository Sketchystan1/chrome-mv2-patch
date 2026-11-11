#define NOMINMAX
#include <windows.h>
#include "blake3_impl.h"

namespace {
LONG active = 0;
struct Task {
  const uint8_t* input;
  size_t size;
  const uint32_t* key;
  uint64_t counter;
  uint8_t flags;
  uint8_t* cvs;
  size_t* count;
};
void CALLBACK compress(PTP_CALLBACK_INSTANCE instance, void* raw, PTP_WORK) {
  CallbackMayRunLong(instance);
  auto& task = *static_cast<Task*>(raw);
  *task.count = blake3_compress_subtree_wide(task.input, task.size, task.key, task.counter, task.flags, task.cvs, true);
  InterlockedDecrement(&active);
}
}

// Upstream names this join hook "tbb"; scheduling uses Windows without a TBB dependency.
// shortcut: one hash uses at most four threads; retune with startup measurements on newer CPUs.
extern "C" void blake3_compress_subtree_wide_join_tbb(
    const uint32_t key[8], uint8_t flags, bool use_tbb,
    const uint8_t* l_input, size_t l_input_len, uint64_t l_chunk_counter, uint8_t* l_cvs, size_t* l_n,
    const uint8_t* r_input, size_t r_input_len, uint64_t r_chunk_counter, uint8_t* r_cvs, size_t* r_n) noexcept {
  if (use_tbb && l_input_len + r_input_len >= 16 * 1024 * 1024) {
    DWORD processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    LONG count = InterlockedIncrement(&active);
    if (count < 4 && static_cast<DWORD>(count) < processors) {
      Task task{l_input, l_input_len, key, l_chunk_counter, flags, l_cvs, l_n};
      PTP_WORK worker = CreateThreadpoolWork(compress, &task, nullptr);
      if (worker) {
        SubmitThreadpoolWork(worker);
        *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key, r_chunk_counter, flags, r_cvs, true);
        WaitForThreadpoolWorkCallbacks(worker, FALSE);
        CloseThreadpoolWork(worker);
        return;
      }
    }
    InterlockedDecrement(&active);
  }
  *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key, l_chunk_counter, flags, l_cvs, false);
  *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key, r_chunk_counter, flags, r_cvs, false);
}
