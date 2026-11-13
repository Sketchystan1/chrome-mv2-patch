#pragma once

#include "autoscan.h"
#include <windows.h>
#include <cstring>

namespace autoscan {
struct TextCompareTask {
  const uint8_t* live;
  const uint8_t* stock;
  size_t size;
  bool equal = false;
};
inline void CALLBACK compareText(PTP_CALLBACK_INSTANCE instance, void* context, PTP_WORK) {
  CallbackMayRunLong(instance);
  auto& task = *static_cast<TextCompareTask*>(context);
  task.equal = !memcmp(task.live, task.stock, task.size);
}
inline bool SameBytes(const uint8_t* live, const uint8_t* stock, size_t size) {
  if (size >= 16 * 1024 * 1024 && HashThreadCount() > 1) {
    size_t half = size / 2;
    TextCompareTask task{live + half, stock + half, size - half};
    PTP_WORK work = CreateThreadpoolWork(compareText, &task, nullptr);
    if (work) {
      SubmitThreadpoolWork(work);
      bool equal = !memcmp(live, stock, half);
      // Join even on mismatch: the callback reads caller-owned mappings and storage.
      WaitForThreadpoolWorkCallbacks(work, FALSE);
      CloseThreadpoolWork(work);
      return equal && task.equal;
    }
  }
  return !memcmp(live, stock, size);
}
} // namespace autoscan
