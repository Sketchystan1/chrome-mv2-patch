// Change imported function addresses in the current process without rewriting Windows functions.
#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstdint>
#include <array>
#include <intrin.h>
#include "detours.h"

static_assert(DETOURS_VERSION == 0x4c0c1, "Keep Microsoft Detours 4.0.1 pinned");
namespace autoscan {
enum class ApplyResult { applied, alreadyApplied, declined, fatal };
struct MemoryOps {
  decltype(&VirtualProtect) protect = ::VirtualProtect;
  decltype(&FlushInstructionCache) flush = ::FlushInstructionCache;
};

// Accept only a read-only address slot pointing to the expected function; code pages are refused.
inline ApplyResult SwapPointer(void* volatile* slot, void* expected, void* replacement, MemoryOps ops = {}) {
  if (!slot || !expected || !replacement || (reinterpret_cast<uintptr_t>(slot) % alignof(void*))) return ApplyResult::declined;
  MEMORY_BASIC_INFORMATION data{}, code{};
  if (!VirtualQuery(const_cast<void**>(slot), &data, sizeof(data)) || data.State != MEM_COMMIT || data.Protect != PAGE_READONLY ||
      !VirtualQuery(replacement, &code, sizeof(code)) || code.State != MEM_COMMIT || code.Protect != PAGE_EXECUTE_READ)
    return ApplyResult::declined;
  if (*slot == replacement) return ApplyResult::alreadyApplied;
  if (*slot != expected) return ApplyResult::declined;
  DWORD old = 0, ignored = 0;
  if (!ops.protect(const_cast<void**>(slot), sizeof(void*), PAGE_READWRITE, &old)) return ApplyResult::declined;
  void* previous = InterlockedCompareExchangePointer(slot, replacement, expected);
  // Restore read-only protection; undo our pointer change if that restoration fails.
  if (ops.protect(const_cast<void**>(slot), sizeof(void*), PAGE_READONLY, &ignored))
    return previous == expected ? ApplyResult::applied : previous == replacement ? ApplyResult::alreadyApplied : ApplyResult::declined;
  if (previous == expected && InterlockedCompareExchangePointer(slot, expected, replacement) != replacement) return ApplyResult::fatal;
  return ops.protect(const_cast<void**>(slot), sizeof(void*), PAGE_READONLY, &ignored) ? ApplyResult::declined : ApplyResult::fatal;
}

struct ImportHook { void* original; void* replacement; unsigned count = 0; };
// Detours lists imported addresses without changing them; only the checked pointer swap above writes.
inline bool HookImports(HMODULE module, ImportHook& hook) {
  struct Context {
    ImportHook* hook;
    std::array<void**, 32> slots{};
    unsigned count = 0;
    bool full = false;
  } context{&hook};
  auto callback = [](PVOID raw, DWORD, LPCSTR, PVOID* slot) -> BOOL {
    auto& c = *static_cast<Context*>(raw);
    if (slot && *slot == c.hook->original) {
      if (c.count == 32) { c.full = true; return FALSE; }
      c.slots[c.count++] = slot;
    }
    return TRUE;
  };
  if (!DetourEnumerateImportsEx(module, &context, nullptr, callback) || context.full) return false;
  unsigned applied = 0;
  for (; applied < context.count; ++applied) {
    auto result = SwapPointer(context.slots[applied], hook.original, hook.replacement);
    if (result == ApplyResult::fatal) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    if (result != ApplyResult::applied && result != ApplyResult::alreadyApplied) break;
  }
  if (applied == context.count) { hook.count += applied; return true; }
  // Undo earlier swaps if any slot fails; stop the process if an original address cannot be restored.
  while (applied) {
    auto result = SwapPointer(context.slots[--applied], hook.replacement, hook.original);
    if (result != ApplyResult::applied && result != ApplyResult::alreadyApplied) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
  }
  return false;
}
} // namespace autoscan
