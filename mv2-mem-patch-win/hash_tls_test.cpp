// Test-only: force failures in hash workers' private storage and check fallback and cleanup.
// A fixture DLL is also loaded and unloaded inside this test process to check memory is released.
#define NOMINMAX
#include <windows.h>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cwchar>

namespace {
LONG failInit = 0, failInstall = 0, failRestore = 0;
LONG allocations = 0, lookups = 0, frees = 0;
LONG* freeCounter = nullptr;
DWORD WINAPI testAlloc() {
  InterlockedIncrement(&allocations);
  if (InterlockedExchange(&failInit, 0)) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return TLS_OUT_OF_INDEXES; }
  return TlsAlloc();
}
void* WINAPI testGet(DWORD index) {
  InterlockedIncrement(&lookups); return TlsGetValue(index);
}
BOOL WINAPI testSet(DWORD index, void* value) {
  LONG& failure = value ? failInstall : failRestore;
  if (InterlockedExchange(&failure, 0)) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
  return TlsSetValue(index, value);
}
BOOL WINAPI testFree(DWORD index) {
  BOOL result = TlsFree(index);
  if (result) { InterlockedIncrement(&frees); if (freeCounter) InterlockedIncrement(freeCounter); }
  return result;
}
}
// Pretend selected Windows storage calls fail, without adding failure switches to the shipped DLL.
#define TlsAlloc testAlloc
#define TlsGetValue testGet
#define TlsSetValue testSet
#define TlsFree testFree
#include "blake3_threads.cpp"
#undef TlsAlloc
#undef TlsGetValue
#undef TlsSetValue
#undef TlsFree
#include "blake3.h"

#if defined(AUTOSCAN_HASH_TLS_HELPER)
namespace { BOOL notificationsDisabled = FALSE; }
BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, void*) {
  if (reason == DLL_PROCESS_ATTACH) notificationsDisabled = DisableThreadLibraryCalls(self);
  if (reason == DLL_PROCESS_DETACH) autoscan::ReleaseHashTls();
  return TRUE;
}
extern "C" void SetHashTlsFreeCounter(LONG* counter) { freeCounter = counter; }
extern "C" BOOL HashTlsProbe(const uint8_t* input, size_t size, uint8_t* output) {
  if (!notificationsDisabled) return FALSE;
  BudgetScope scope({3, 3});
  if (!scope.installed || currentBudget().threads != 3) return FALSE;
  blake3_hasher hasher; blake3_hasher_init(&hasher);
  blake3_hasher_update_tbb(&hasher, input, size);
  blake3_hasher_finalize(&hasher, output, 32);
  return active == 0;
}
#else
#include <thread>
namespace {
std::array<uint8_t, 32 * 1024 * 1024 + 3> input{};
void check(bool condition, const char* message) {
  if (!condition) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
std::array<uint8_t, 32> digest(size_t size, bool parallel) {
  blake3_hasher hasher; blake3_hasher_init(&hasher);
  if (parallel) blake3_hasher_update_tbb(&hasher, input.data(), size);
  else blake3_hasher_update(&hasher, input.data(), size);
  std::array<uint8_t, 32> result{};
  blake3_hasher_finalize(&hasher, result.data(), result.size()); return result;
}
}
int wmain(int argc, wchar_t** argv) {
  check(argc >= 2, "TLS test requires a mode");
  const wchar_t* mode = argv[1];
  auto is = [&](const wchar_t* name) { return std::wcscmp(mode, name) == 0; };
  for (size_t n = 0; n < input.size(); ++n) input[n] = static_cast<uint8_t>(n % 251);
  LONG retiredLookups = -1;
  if (is(L"init-failure")) failInit = 1;
  else if (is(L"install-failure")) {
    BudgetScope forced({3, 3}); check(forced.installed, "install parent budget");
    failInstall = 1;
    check(digest(input.size(), true) == digest(input.size(), false), "failed subtree install hashes serially");
    check(!failInstall && !active, "failed install was consumed without a worker leak");
  } else if (is(L"restore-failure") || is(L"restore-during-hash")) {
    { BudgetScope forced({3, 3}); check(forced.installed, "install retirement fixture");
      check(currentBudget().threads == 3, "read owned budget"); failRestore = 1;
      if (is(L"restore-during-hash"))
        check(digest(input.size(), true) == digest(input.size(), false), "retirement during joined hash preserves digest");
    }
    retiredLookups = lookups;
    check(!enabled() && currentBudget().threads == 1 && lookups == retiredLookups, "retirement prevents stale-pointer lookup");
  } else if (is(L"release-before-init")) autoscan::ReleaseHashTls();
  else check(is(L"normal"), "known TLS test mode");

  for (size_t size : {size_t{0}, size_t{1024}, size_t{16 * 1024 * 1024 - 1},
                      size_t{16 * 1024 * 1024}, size_t{16 * 1024 * 1024 + 1}, input.size()})
    check(digest(size, true) == digest(size, false), "threshold and irregular digest parity");
  std::array<std::array<uint8_t, 32>, 2> concurrent{};
  std::thread other([&] { concurrent[0] = digest(input.size(), true); });
  concurrent[1] = digest(input.size(), true); other.join();
  check(concurrent[0] == concurrent[1] && concurrent[0] == digest(input.size(), false) && !active, "concurrent digest and callback joins");

  if (is(L"normal") || is(L"install-failure")) {
    check(enabled() && !currentBudget().threads, "restore original empty slot");
    SetLastError(12345);
    { BudgetScope outer({3, 3}); check(outer.installed, "odd parent budget");
      check(digest(input.size(), true) == digest(input.size(), false), "odd-budget digest parity");
      { BudgetScope inner({1, 3}); check(inner.installed && currentBudget().threads == 1, "nested budget"); }
      check(currentBudget().threads == 3, "restore outer budget");
    }
    check(GetLastError() == 12345, "restore caller LastError");
    auto oddHash = [&](size_t n) { BudgetScope scope({3, 3}); check(scope.installed, "concurrent odd budget"); concurrent[n] = digest(input.size(), true); };
    std::thread odd([&] { oddHash(0); }); oddHash(1); odd.join();
    check(concurrent[0] == concurrent[1] && concurrent[0] == digest(input.size(), false) && !active, "concurrent odd-budget parity");
  } else check(!enabled(), "failed initialization or retirement stays serial");
  if (is(L"init-failure")) check(allocations == 1 && !lookups, "failed initialization allocates once and never looks up");
  if (is(L"release-before-init")) check(!allocations && !lookups, "release does not initialize or reactivate TLS");
  if (retiredLookups >= 0) check(lookups == retiredLookups, "retired slots are never queried again");

  LONG expectedFrees = frees + (budgetIndex != TLS_OUT_OF_INDEXES);
  SetLastError(24680); autoscan::ReleaseHashTls();
  check(GetLastError() == 24680, "cleanup preserves LastError");
  check(frees == expectedFrees && budgetIndex == TLS_OUT_OF_INDEXES, "cleanup frees the allocated index");
  LONG priorAllocations = allocations;
  autoscan::ReleaseHashTls();
  check(frees == expectedFrees && digest(input.size(), true) == digest(input.size(), false) && allocations == priorAllocations, "cleanup is idempotent and cannot allocate again");

  if (is(L"normal")) {
    check(argc == 3, "normal mode requires the TLS fixture DLL");
    auto expected = digest(input.size(), false);
    for (unsigned n = 0; n < 3; ++n) {
      LONG released = 0;
      HMODULE library = LoadLibraryW(argv[2]); check(library != nullptr, "load TLS fixture");
      auto counter = reinterpret_cast<void(*)(LONG*)>(GetProcAddress(library, "SetHashTlsFreeCounter"));
      auto hash = reinterpret_cast<BOOL(*)(const uint8_t*, size_t, uint8_t*)>(GetProcAddress(library, "HashTlsProbe"));
      check(counter && hash, "resolve TLS fixture exports"); counter(&released);
      std::array<uint8_t, 32> output{};
      check(hash(input.data(), input.size(), output.data()) && output == expected, "DLL has no static TLS and joins its hash");
      check(FreeLibrary(library) && released == 1, "DLL detach frees its TLS index");
      check(!GetModuleHandleW(argv[2]), "TLS fixture fully unloaded before reload");
    }
  }
  std::puts("PASS: scoped TLS, failure fallback, retirement, concurrent digests and unload cleanup");
  return 0;
}
#endif
