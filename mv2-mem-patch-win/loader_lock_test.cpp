// Test-only: load a fixture DLL and briefly hold Windows' loading lock in this process.
// Check that the patcher would wait or refuse to scan when the lock's state cannot be trusted.
#include "loader_lock.h"
#include <cstdio>
#include <cstdlib>
#include <initializer_list>

#ifdef MV2_LOADER_LOCK_HELPER
static autoscan::LoaderLock loader;
static bool inside = false;
extern "C" DWORD Inside() { return inside; }
extern "C" DWORD Outside() { return loader.outside(); }
extern "C" DWORD Uncalibrated() { return autoscan::LoaderLock{}.outside(); }
extern "C" DWORD Unreadable() {
  auto invalid = loader;
  invalid.address = reinterpret_cast<const RTL_CRITICAL_SECTION*>(1);
  return invalid.outside();
}
extern "C" DWORD OtherBlocked() {
  struct Events { HANDLE entered, release; } events{CreateEventW(nullptr, TRUE, FALSE, nullptr), CreateEventW(nullptr, TRUE, FALSE, nullptr)};
  if (!events.entered || !events.release) {
    if (events.entered) CloseHandle(events.entered);
    if (events.release) CloseHandle(events.release);
    return 0;
  }
  HANDLE thread = CreateThread(nullptr, 0, [](void* input) -> DWORD {
    auto& events = *static_cast<Events*>(input);
    EnterCriticalSection(const_cast<RTL_CRITICAL_SECTION*>(loader.address));
    SetEvent(events.entered);
    WaitForSingleObject(events.release, INFINITE);
    LeaveCriticalSection(const_cast<RTL_CRITICAL_SECTION*>(loader.address));
    return 0;
  }, &events, 0, nullptr);
  bool blocked = thread && WaitForSingleObject(events.entered, 5000) == WAIT_OBJECT_0 && !loader.outside();
  SetEvent(events.release);
  if (thread) { WaitForSingleObject(thread, INFINITE); CloseHandle(thread); }
  CloseHandle(events.entered); CloseHandle(events.release);
  return blocked;
}
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) inside = loader.initialize() && !loader.outside();
  return TRUE;
}
#else
static void check(bool passed, const char* message) {
  if (!passed) { std::fprintf(stderr, "FAIL: %s (%lu)\n", message, GetLastError()); std::exit(1); }
}
int wmain(int argc, wchar_t** argv) {
  check(argc == 2, "usage: loader-lock-test <helper.dll>");
  HMODULE module = LoadLibraryW(argv[1]);
  check(module != nullptr, "load calibration helper");
  for (auto name : {"Inside", "Outside", "OtherBlocked", "Uncalibrated", "Unreadable"}) {
    auto probe = reinterpret_cast<DWORD (*)()>(GetProcAddress(module, name));
    check(probe != nullptr, "resolve loader-lock probe");
    check(probe() == (name[0] == 'U' ? 0 : 1), name);
  }
  check(FreeLibrary(module) != FALSE, "unload calibration helper");
  std::puts("PASS: DllMain, unlocked loader, another loader thread, missing calibration and unreadable state");
}
#endif
