// Test-only: simulated Windows query failures and a real test thread check startup-thread selection.
// The browser patch operation is replaced with an empty function in this test.
#include <windows.h>
#include <tlhelp32.h>
#include <processsnapshot.h>
#include <cstdio>
#include <cstdlib>

enum class Fault { none, capture, marker, walk, partialWalk, zeroTime, tiedTime, tiedThenEarlier, wrongProcess, freeMarker, freeSnapshot };
static Fault fault = Fault::none;
static unsigned captures = 0, snapshots = 0, snapshotFrees = 0, markerCreates = 0, markerFrees = 0, walkCalls = 0;
static bool failTool = false;
static HANDLE WINAPI countSnapshot(DWORD flags, DWORD pid) {
  ++snapshots;
  return failTool ? INVALID_HANDLE_VALUE : CreateToolhelp32Snapshot(flags, pid);
}
static DWORD WINAPI countCapture(HANDLE process, PSS_CAPTURE_FLAGS flags, DWORD context, HPSS* snapshot) {
  ++captures; walkCalls = 0;
  if (process != GetCurrentProcess() || flags != PSS_CAPTURE_THREADS || context) std::exit(1);
  return fault == Fault::capture ? ERROR_NOT_ENOUGH_MEMORY : PssCaptureSnapshot(process, flags, context, snapshot);
}
static DWORD WINAPI countMarker(PSS_ALLOCATOR const* allocator, HPSSWALK* value) {
  ++markerCreates;
  return fault == Fault::marker ? ERROR_NOT_ENOUGH_MEMORY : PssWalkMarkerCreate(allocator, value);
}
static DWORD WINAPI countWalk(HPSS snapshot, PSS_WALK_INFORMATION_CLASS kind, HPSSWALK marker, void* buffer, DWORD size) {
  ++walkCalls;
  if (fault == Fault::walk || (fault == Fault::partialWalk && walkCalls == 2)) return ERROR_INVALID_HANDLE;
  auto entry = static_cast<PSS_THREAD_ENTRY*>(buffer);
  if (fault == Fault::tiedTime || fault == Fault::tiedThenEarlier) {
    if (walkCalls > (fault == Fault::tiedTime ? 2u : 3u)) return ERROR_NO_MORE_ITEMS;
    *entry = {}; entry->ProcessId = GetCurrentProcessId(); entry->ThreadId = GetCurrentThreadId() + walkCalls;
    entry->CreateTime.dwLowDateTime = walkCalls == 3 ? 1 : 2;
    if (walkCalls == 3) entry->ThreadId = GetCurrentThreadId();
    return ERROR_SUCCESS;
  }
  DWORD status = PssWalkSnapshot(snapshot, kind, marker, buffer, size);
  if (!status && fault == Fault::zeroTime) entry->CreateTime = {};
  if (!status && fault == Fault::wrongProcess) ++entry->ProcessId;
  return status;
}
static DWORD WINAPI countFreeMarker(HPSSWALK marker) {
  ++markerFrees;
  DWORD status = PssWalkMarkerFree(marker);
  return fault == Fault::freeMarker ? ERROR_INVALID_HANDLE : status;
}
static DWORD WINAPI countFreeSnapshot(HANDLE process, HPSS snapshot) {
  ++snapshotFrees;
  DWORD status = PssFreeSnapshot(process, snapshot);
  return fault == Fault::freeSnapshot ? ERROR_INVALID_HANDLE : status;
}
#define CreateToolhelp32Snapshot countSnapshot
#define PssCaptureSnapshot countCapture
#define PssWalkMarkerCreate countMarker
#define PssWalkSnapshot countWalk
#define PssWalkMarkerFree countFreeMarker
#define PssFreeSnapshot countFreeSnapshot
#include "autopatch_proxy.cpp"
#undef PssFreeSnapshot
#undef PssWalkMarkerFree
#undef PssWalkSnapshot
#undef PssWalkMarkerCreate
#undef PssCaptureSnapshot
#undef CreateToolhelp32Snapshot

namespace autoscan { void Patch(HMODULE) noexcept {} }

static void check(bool ok) { if (!ok) std::exit(1); }
int main() {
  DWORD initial = GetCurrentThreadId();
  check(firstThread(nullptr) == initial && captures == 1 && snapshots == 0);
  check(firstThread(&initial) == initial && captures == 1 && snapshots == 0);
  HANDLE worker = CreateThread(nullptr, 0, [](void* input) -> DWORD {
    DWORD initial = *static_cast<DWORD*>(input);
    check(firstThread(nullptr) == initial && captures == 2 && snapshots == 0);
    check(firstThread(input) == GetCurrentThreadId() && captures == 2 && snapshots == 0);
    return 0;
  }, &initial, 0, nullptr);
  check(worker && WaitForSingleObject(worker, 5000) == WAIT_OBJECT_0);
  CloseHandle(worker);
  fault = Fault::tiedThenEarlier;
  check(firstThread(nullptr) == initial && snapshots == 0);
  for (Fault failure : {Fault::capture, Fault::marker, Fault::walk, Fault::partialWalk,
                        Fault::zeroTime, Fault::tiedTime, Fault::wrongProcess, Fault::freeMarker, Fault::freeSnapshot}) {
    fault = failure;
    unsigned previous = snapshots, freed = snapshotFrees, created = markerCreates, freedMarkers = markerFrees;
    check(firstThread(nullptr) == initial && snapshots == previous + 1);
    check(snapshotFrees == freed + (failure != Fault::capture));
    check(markerCreates == created + (failure != Fault::capture));
    check(markerFrees == freedMarkers + (failure != Fault::capture && failure != Fault::marker));
  }
  fault = Fault::capture; failTool = true;
  check(firstThread(nullptr) == 0);
  unsigned attempts = captures;
  check(firstThread(&initial) == initial && captures == attempts);
  fault = Fault::none; failTool = false;
  LARGE_INTEGER frequency{}, start{}, end{};
  QueryPerformanceFrequency(&frequency);
  for (bool startup : {false, true}) {
    QueryPerformanceCounter(&start);
    for (unsigned n = 0; n < 20; ++n) check(firstThread(startup ? &initial : nullptr) == initial);
    QueryPerformanceCounter(&end);
    std::printf("%s: %.6f ms/call\n", startup ? "startup" : "dynamic",
        (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart / 20);
  }
  std::puts("PASS: startup skips snapshots; process-only discovery and conservative fallback pass");
}
