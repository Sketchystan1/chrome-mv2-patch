// Test-only: load a fixture DLL and check that background cleanup releases its mapped memory.
// Simulated failures check that the DLL stays loaded until its cleanup work has finished.
#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>

#if defined(AUTOSCAN_RUNTIME_HELPER)
namespace {
bool failRetain = false, failSubmit = false;
HANDLE releaseEvent = nullptr, completedEvent = nullptr;
PTP_SIMPLE_CALLBACK queuedCallback = nullptr;
void* queuedContext = nullptr;
void CALLBACK invoke(PTP_CALLBACK_INSTANCE instance, void*) {
  if (WaitForSingleObject(releaseEvent, 5000) != WAIT_OBJECT_0) std::abort();
  queuedCallback(instance, queuedContext);
  SetEvent(completedEvent);
}
BOOL WINAPI testSubmit(PTP_SIMPLE_CALLBACK callback, void* context, PTP_CALLBACK_ENVIRON environment) {
  if (failSubmit) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
  queuedCallback = callback; queuedContext = context;
  return TrySubmitThreadpoolCallback(invoke, nullptr, environment);
}
BOOL WINAPI testRetain(DWORD flags, LPCWSTR address, HMODULE* module) {
  if (failRetain) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
  return GetModuleHandleExW(flags, address, module);
}
}
// Use the real cleanup code in a test DLL so unloading it while work is pending can be checked.
#define TrySubmitThreadpoolCallback testSubmit
#define GetModuleHandleExW testRetain
#include "autoscan_runtime.cpp"
#undef TrySubmitThreadpoolCallback
#undef GetModuleHandleExW

extern "C" void ConfigureCleanup(unsigned failure, HANDLE release, HANDLE completed) {
  failRetain = failure == 1; failSubmit = failure == 2;
  releaseEvent = release; completedEvent = completed;
}
extern "C" BOOL QueueCleanup(HANDLE mapping, const void** address) {
  View view(mapping, 4096); *address = view.data;
  if (!view.data || !queueView(view.data)) return FALSE;
  view.data = nullptr; return TRUE;
}
#else
namespace {
void check(bool condition, const char* message) {
  if (!condition) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
bool freeView(const void* address) {
  MEMORY_BASIC_INFORMATION memory{};
  return VirtualQuery(address, &memory, sizeof(memory)) && memory.State == MEM_FREE;
}
}
int wmain(int argc, wchar_t** argv) {
  check(argc == 2, "cleanup test requires its fixture DLL");
  HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 4096, nullptr);
  HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE completed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  check(mapping && release && completed, "create view and callback gates");
  using Configure = void(*)(unsigned, HANDLE, HANDLE);
  using Queue = BOOL(*)(HANDLE, const void**);
  for (unsigned failure : {1u, 2u, 0u}) {
    HMODULE library = LoadLibraryW(argv[1]); check(library != nullptr, "load cleanup fixture");
    auto configure = reinterpret_cast<Configure>(GetProcAddress(library, "ConfigureCleanup"));
    auto queue = reinterpret_cast<Queue>(GetProcAddress(library, "QueueCleanup"));
    check(configure && queue, "resolve fixture ABI");
    configure(failure, release, completed);
    const void* view = nullptr;
    bool queued = queue(mapping, &view) != FALSE;
    check(view && queued == (failure == 0), "retain/submission failure preserves synchronous ownership");
    if (failure) check(freeView(view), "failed queue leaves no mapping behind");
    else {
      check(!freeView(view), "callback owns a live mapping while queued");
      const void* second = nullptr;
      check(!queue(mapping, &second) && second && freeView(second), "busy slot falls back without replacing pending ownership");
    }
    check(FreeLibrary(library) != FALSE, "release caller DLL reference");
    if (!failure) {
      check(GetModuleHandleW(argv[1]) != nullptr, "pending callback retains its DLL");
      check(SetEvent(release) && WaitForSingleObject(completed, 5000) == WAIT_OBJECT_0, "callback completes");
      check(freeView(view), "callback released the mapping");
    }
    ULONGLONG deadline = GetTickCount64() + 5000;
    while (GetModuleHandleW(argv[1]) && GetTickCount64() < deadline) Sleep(1);
    check(!GetModuleHandleW(argv[1]), "no leaked callback DLL reference");
  }
  check(CloseHandle(completed) && CloseHandle(release) && CloseHandle(mapping), "close fixture handles");
  std::puts("PASS: view cleanup, retain/submission failures, busy fallback and DLL unload");
  return 0;
}
#endif
