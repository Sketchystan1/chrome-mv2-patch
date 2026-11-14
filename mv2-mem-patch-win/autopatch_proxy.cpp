// Chrome loads this DLL in place of secur32.dll; normal security calls go to Windows' real DLL.
// The extra startup work identifies Chrome or Edge and requests one checked memory patch.
#include <windows.h>
#include <array>
#include <cstring>
#include <cwchar>
#include "autoscan_runtime.h"
#include "secur32-forward-exports.h"
#include <tlhelp32.h>
#include <processsnapshot.h>
#include "loader_lock.h"

extern "C" {
std::array<void*, std::size(mv2ForwardExports)> g_secur32Exports{};
}

namespace {
const wchar_t* browserName = nullptr;
LONG patchStarted = 0;
autoscan::LoaderLock loaderLock;
DWORD mainThread = 0;
BOOL WINAPI counter(LARGE_INTEGER* value);

DWORD firstThread(LPVOID startup) {
  // Find the browser's original thread so patching happens before it starts normal work.
  // If Windows loads us at process startup, we are already running on that thread.
  if (startup) return GetCurrentThreadId();
  HPSS processSnapshot = nullptr;
  if (!PssCaptureSnapshot(GetCurrentProcess(), PSS_CAPTURE_THREADS, 0, &processSnapshot)) {
    HPSSWALK marker = nullptr;
    DWORD result = 0, status = ERROR_INVALID_HANDLE;
    if (!PssWalkMarkerCreate(nullptr, &marker)) {
      PSS_THREAD_ENTRY entry{};
      ULONGLONG earliest = ~ULONGLONG{};
      while (!(status = PssWalkSnapshot(processSnapshot, PSS_WALK_THREADS, marker, &entry, sizeof(entry)))) {
        if (entry.ProcessId != GetCurrentProcessId()) { result = 0; break; }
        if (entry.Flags & PSS_THREAD_FLAGS_TERMINATED) continue;
        ULONGLONG stamp = (static_cast<ULONGLONG>(entry.CreateTime.dwHighDateTime) << 32) | entry.CreateTime.dwLowDateTime;
        if (!stamp) { result = 0; break; }
        if (stamp < earliest) { earliest = stamp; result = entry.ThreadId; }
        else if (stamp == earliest) result = 0;
      }
      if (PssWalkMarkerFree(marker)) status = ERROR_INVALID_HANDLE;
    }
    // If the snapshot is incomplete or ambiguous, try Windows' other thread-list API.
    if (!PssFreeSnapshot(GetCurrentProcess(), processSnapshot) && status == ERROR_NO_MORE_ITEMS && result) return result;
  }
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return 0;
  THREADENTRY32 entry{}; entry.dwSize = sizeof(entry);
  ULONGLONG earliest = ~ULONGLONG{};
  DWORD result = 0;
  for (BOOL ok = Thread32First(snapshot, &entry); ok; ok = Thread32Next(snapshot, &entry)) {
    if (entry.th32OwnerProcessID != GetCurrentProcessId()) continue;
    HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
    if (!thread) continue;
    FILETIME created{}, exited{}, kernel{}, user{};
    if (GetThreadTimes(thread, &created, &exited, &kernel, &user)) {
      ULONGLONG stamp = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
      if (stamp < earliest) { earliest = stamp; result = entry.th32ThreadID; }
    }
    CloseHandle(thread);
  }
  CloseHandle(snapshot);
  return result;
}

bool forward() {
  // Use the full Windows system path so another local DLL cannot become the forwarding target.
  std::array<wchar_t, MAX_PATH + 32> path{};
  DWORD length = GetSystemDirectoryW(path.data(), MAX_PATH);
  if (!length || length >= MAX_PATH) return false;
  const wchar_t systemDll[] = L"\\secur32.dll";
  if (length + std::size(systemDll) > path.size()) return false;
  std::memcpy(path.data() + length, systemDll, sizeof(systemDll));
  HMODULE real = LoadLibraryExW(path.data(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!real) return false;
  auto& exports = g_secur32Exports;
  // shortcut: requires all listed Windows functions; update the list before supporting older Windows.
  for (size_t n = 0; n < exports.size(); ++n) {
    auto entry = mv2ForwardExports[n];
    exports[n] = reinterpret_cast<void*>(GetProcAddress(real,
        entry.name ? entry.name : MAKEINTRESOURCEA(entry.ordinal)));
    if (!exports[n]) { FreeLibrary(real); return false; }
  }
  return true;
}

void patch(HMODULE module) {
  // Run once, on the original browser thread, after Windows finishes loading DLLs.
  if (GetCurrentThreadId() != mainThread || !loaderLock.outside()) return;
  if (!module || InterlockedCompareExchange(&patchStarted, 1, 0)) return;
  autoscan::ImportHook restore{reinterpret_cast<void*>(&counter), reinterpret_cast<void*>(&QueryPerformanceCounter)};
  // Put the normal clock call back before scanning; the clock was only a startup trigger.
  if (!autoscan::HookImports(module, restore))
    OutputDebugStringA("[mv2patch autoscan] clock import restore failed; forwarding continues");
  autoscan::Patch(module);
}

BOOL WINAPI counter(LARGE_INTEGER* value) {
  // A clock call can trigger the patch, then receives the real Windows result and error state.
  DWORD error = GetLastError();
  if (!InterlockedCompareExchange(&patchStarted, 0, 0) && GetCurrentThreadId() == mainThread)
    patch(GetModuleHandleW(browserName));
  SetLastError(error);
  return QueryPerformanceCounter(value);
}

FARPROC WINAPI lookup(HMODULE module, LPCSTR name) {
  FARPROC result = GetProcAddress(module, name);
  DWORD error = GetLastError();
  if (result && reinterpret_cast<uintptr_t>(name) > 0xffff && !std::strcmp(name, "ChromeMain") &&
      module == GetModuleHandleW(browserName)) {
    // Looking up ChromeMain signals that loading has finished and browser startup is next.
    patch(module);
  }
  SetLastError(error);
  return result;
}
}  // namespace

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID startup) {
  if (reason == DLL_PROCESS_DETACH) { autoscan::ReleaseHashTls(); return TRUE; }
  if (reason != DLL_PROCESS_ATTACH) return TRUE;
  DisableThreadLibraryCalls(self);
  if (!forward()) return FALSE;
  std::array<wchar_t, 32768> host{};
  DWORD length = GetModuleFileNameW(nullptr, host.data(), static_cast<DWORD>(host.size()));
  if (!length || length == host.size()) return TRUE;
  const wchar_t* filename = std::wcsrchr(host.data(), L'\\');
  filename = filename ? filename + 1 : host.data();
  if (!_wcsicmp(filename, L"chrome.exe")) browserName = L"chrome.dll";
  else if (!_wcsicmp(filename, L"msedge.exe")) browserName = L"msedge.dll";
  else return TRUE;
  auto command = GetCommandLineW();
  // Other applications and the browser's child processes only receive normal DLL forwarding.
  if (command && std::wcsstr(command, L"--type=")) return TRUE;
  mainThread = firstThread(startup);
  // Keep this DLL loaded while the browser can call its startup-trigger functions.
  HMODULE pinned = nullptr;
  if (!mainThread || !loaderLock.initialize() || !GetModuleHandleExW(
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, reinterpret_cast<LPCWSTR>(&counter), &pinned)) {
    OutputDebugStringA("[mv2patch autoscan] main thread or loader-lock calibration unavailable; scan will not run");
    return TRUE;
  }
  HMODULE browser = GetModuleHandleW(browserName);
  // Replace only these imported function addresses in this process to catch browser startup.
  autoscan::ImportHook clock{reinterpret_cast<void*>(&QueryPerformanceCounter), reinterpret_cast<void*>(&counter)};
  if (browser && (!autoscan::HookImports(browser, clock) || !clock.count))
    OutputDebugStringA("[mv2patch autoscan] clock import unavailable; lookup trigger remains");
  autoscan::ImportHook entry{reinterpret_cast<void*>(&GetProcAddress), reinterpret_cast<void*>(&lookup)};
  if (!autoscan::HookImports(GetModuleHandleW(nullptr), entry) || !entry.count) {
    OutputDebugStringA("[mv2patch autoscan] ChromeMain lookup import unavailable; scan depends on clock import");
  }
  return TRUE;
}
