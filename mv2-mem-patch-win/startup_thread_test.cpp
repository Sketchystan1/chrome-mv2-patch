#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdlib>

static unsigned snapshots = 0;
static HANDLE WINAPI countSnapshot(DWORD flags, DWORD pid) {
  ++snapshots;
  return CreateToolhelp32Snapshot(flags, pid);
}
#define CreateToolhelp32Snapshot countSnapshot
#include "autopatch_proxy.cpp"
#undef CreateToolhelp32Snapshot

namespace autoscan { void Patch(HMODULE) noexcept {} }

static void check(bool ok) { if (!ok) std::exit(1); }
int main() {
  DWORD initial = GetCurrentThreadId();
  check(firstThread(nullptr) == initial && snapshots == 1);
  check(firstThread(&initial) == initial && snapshots == 1);
  HANDLE worker = CreateThread(nullptr, 0, [](void* input) -> DWORD {
    DWORD initial = *static_cast<DWORD*>(input);
    check(firstThread(nullptr) == initial && snapshots == 2);
    check(firstThread(input) == GetCurrentThreadId() && snapshots == 2);
    return 0;
  }, &initial, 0, nullptr);
  check(worker && WaitForSingleObject(worker, 5000) == WAIT_OBJECT_0);
  CloseHandle(worker);
  LARGE_INTEGER frequency{}, start{}, end{};
  QueryPerformanceFrequency(&frequency);
  for (bool startup : {false, true}) {
    QueryPerformanceCounter(&start);
    for (unsigned n = 0; n < 20; ++n) check(firstThread(startup ? &initial : nullptr) == initial);
    QueryPerformanceCounter(&end);
    std::printf("%s: %.6f ms/call\n", startup ? "startup" : "dynamic",
        (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart / 20);
  }
  std::puts("PASS: startup skips snapshots; dynamic loads retain initial-thread discovery");
}
