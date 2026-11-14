// Check whether Windows is still loading DLLs; scanning at that time could deadlock browser startup.
#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstdint>

namespace autoscan {
struct LoaderLock {
  const RTL_CRITICAL_SECTION* address = nullptr;
  bool calibrated = false;

  bool read(RTL_CRITICAL_SECTION& state) const {
    SIZE_T bytes = 0;
    return address && ReadProcessMemory(GetCurrentProcess(), address, &state, sizeof(state), &bytes) && bytes == sizeof(state);
  }
  bool initialize() {
    // shortcut: Windows loader-lock locations are fixed here; recheck if Windows changes its layout.
    constexpr size_t offset = sizeof(void*) == 8 ? 0x110 : 0xa0;
    SIZE_T bytes = 0;
    auto peb = reinterpret_cast<const uint8_t*>(NtCurrentTeb()->ProcessEnvironmentBlock);
    RTL_CRITICAL_SECTION state{};
    // Verify that the discovered lock belongs to our current DLL-loading thread before trusting it.
    calibrated = peb && ReadProcessMemory(GetCurrentProcess(), peb + offset, &address, sizeof(address), &bytes) &&
        bytes == sizeof(address) && read(state) && state.RecursionCount > 0 &&
        reinterpret_cast<uintptr_t>(state.OwningThread) == GetCurrentThreadId();
    return calibrated;
  }
  bool outside() const {
    // Unknown or unreadable lock state refuses scanning; proceed only when no thread owns it.
    RTL_CRITICAL_SECTION state{};
    return calibrated && read(state) && !state.OwningThread && !state.RecursionCount;
  }
};
}  // namespace autoscan
