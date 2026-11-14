// Read the browser DLL, obtain a checked patch plan, and apply it to this process's memory.
// A cache miss starts a hidden Windows helper; the browser DLL on disk is opened read-only.
#include "autoscan_runtime.h"
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cwchar>
#include <intrin.h>

namespace {
struct PendingView { const uint8_t* view = nullptr; HMODULE module = nullptr; };
PendingView pendingView;
LONG cleanupActive = 0;
void CALLBACK releaseView(PTP_CALLBACK_INSTANCE instance, void*) {
  CallbackMayRunLong(instance);
  auto task = pendingView;
  UnmapViewOfFile(task.view);
  InterlockedExchange(&cleanupActive, 0);
  FreeLibraryWhenCallbackReturns(instance, task.module);
}
bool queueView(const uint8_t* view) {
  // Release the read-only file view in the background, keeping our DLL loaded until that job ends.
  if (InterlockedCompareExchange(&cleanupActive, 1, 0)) return false;
  HMODULE module = nullptr;
  if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(&releaseView), &module)) {
    InterlockedExchange(&cleanupActive, 0); return false;
  }
  pendingView = {view, module};
  if (TrySubmitThreadpoolCallback(releaseView, nullptr, nullptr)) return true;
  FreeLibrary(module); InterlockedExchange(&cleanupActive, 0); return false;
}
struct Handle {
  // Close Windows file/process handles when leaving a function, including early failures.
  HANDLE value = nullptr;
  explicit Handle(HANDLE h = nullptr) : value(h) {}
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  void close() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); value = nullptr; }
  ~Handle() { close(); }
};
struct View {
  // This is a read-only window onto file bytes; closing it does not delete or edit the file.
  const uint8_t* data = nullptr;
  explicit View(HANDLE mapping, size_t size) : data(static_cast<const uint8_t*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, size))) {}
  void close() { if (data) UnmapViewOfFile(data); data = nullptr; }
  ~View() { close(); }
};
struct Attributes {
  alignas(void*) std::array<uint8_t, 4096> storage{};
  LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
  bool init(HANDLE* handles, size_t count) {
    SIZE_T size = 0; InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    if (!size || size > storage.size()) return false;
    auto p = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(p, 1, 0, &size)) return false;
    list = p;
    return UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, count * sizeof(HANDLE), nullptr, nullptr) != FALSE;
  }
  ~Attributes() { if (list) DeleteProcThreadAttributeList(list); }
};
void trace(std::string_view message) {
  // Send local diagnostic messages to Windows' debugger output; no log upload is made here.
  std::array<char, 512> buffer{};
  _snprintf_s(buffer.data(), buffer.size(), _TRUNCATE, "[mv2patch autoscan] %.*s", static_cast<int>(message.size()), message.data());
  OutputDebugStringA(buffer.data());
}
bool scanInHelper(HANDLE mapping, size_t size, const autoscan::HashValue& hash, autoscan::WirePlan& plan) {
  // Windows' own rundll32.exe loads this DLL to scan without holding up DLL loading in Chrome.
  HMODULE self = nullptr;
  if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         reinterpret_cast<LPCWSTR>(&scanInHelper), &self)) return false;
  std::array<wchar_t, 32768> dll{}, command{};
  std::array<wchar_t, MAX_PATH + 16> executable{};
  DWORD length = GetModuleFileNameW(self, dll.data(), static_cast<DWORD>(dll.size()));
  DWORD systemLength = GetSystemDirectoryW(executable.data(), MAX_PATH);
  if (!length || length == dll.size() || !systemLength || systemLength >= MAX_PATH) return false;
  memcpy(executable.data() + systemLength, L"\\rundll32.exe", sizeof(L"\\rundll32.exe"));
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  Handle read, write;
  if (!CreatePipe(&read.value, &write.value, &security, 4096) || !SetHandleInformation(read.value, HANDLE_FLAG_INHERIT, 0)) return false;
  HANDLE inherited[] = {mapping, write.value}; Attributes attributes;
  // Inherit only the read-only browser mapping and reply pipe; the helper still runs with this user's permissions.
  if (!attributes.init(inherited, std::size(inherited))) return false;
  if (_snwprintf_s(command.data(), command.size(), _TRUNCATE, L"\"%ls\" \"%ls\",VersionMV2Scan %llu %llu %llu %.*hs",
      executable.data(), dll.data(), static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mapping)),
      static_cast<unsigned long long>(size), static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(write.value)), 64, hash.data()) < 0) return false;
  STARTUPINFOEXW start{}; start.StartupInfo.cb = sizeof(start); start.lpAttributeList = attributes.list;
  start.StartupInfo.dwFlags = STARTF_USESHOWWINDOW; start.StartupInfo.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(executable.data(), command.data(), nullptr, nullptr, TRUE,
                      EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr, &start.StartupInfo, &process)) return false;
  Handle child(process.hProcess), thread(process.hThread); write.close();
  size_t received = 0; bool exited = false, valid = true;
  ULONGLONG deadline = GetTickCount64() + 30000;
  // Accept exactly one complete reply; malformed output or a 30-second timeout cancels patching.
  while (GetTickCount64() < deadline) {
    DWORD available = 0;
    if (!PeekNamedPipe(read.value, nullptr, 0, nullptr, &available, nullptr) && GetLastError() != ERROR_BROKEN_PIPE) { valid = false; break; }
    if (available) {
      if (available > sizeof(plan) - received) { valid = false; break; }
      DWORD got = 0;
      if (!ReadFile(read.value, reinterpret_cast<uint8_t*>(&plan) + received, available, &got, nullptr) || !got) { valid = false; break; }
      received += got; continue;
    }
    DWORD wait = WaitForSingleObject(child.value, 25);
    if (wait == WAIT_OBJECT_0) { if (exited) break; exited = true; }
    else if (wait != WAIT_TIMEOUT) { valid = false; break; }
  }
  DWORD code = 1;
  bool success = valid && exited && received == sizeof(plan) && GetExitCodeProcess(child.value, &code) && code == 0;
  // Stop only the helper we created if it has not finished; Chrome continues without a patch.
  if (!exited) { TerminateProcess(child.value, ERROR_TIMEOUT); WaitForSingleObject(child.value, 2000); }
  return success;
}
autoscan::HashValue scannerHash() {
  // Fingerprint our own DLL so updating the patcher also invalidates old cached plans.
  HMODULE self = nullptr;
  if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         reinterpret_cast<LPCWSTR>(&scannerHash), &self)) return {};
  std::array<wchar_t, 32768> path{};
  DWORD length = GetModuleFileNameW(self, path.data(), static_cast<DWORD>(path.size()));
  if (!length || length == path.size()) return {};
  Handle file(CreateFileW(path.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  LARGE_INTEGER size{};
  if (file.value == INVALID_HANDLE_VALUE || !GetFileSizeEx(file.value, &size) || size.QuadPart <= 0 || size.QuadPart > ULONG_MAX) return {};
  Handle mapping(CreateFileMappingW(file.value, nullptr, PAGE_READONLY, 0, 0, nullptr));
  if (!mapping.value) return {};
  View view(mapping.value, static_cast<size_t>(size.QuadPart));
  return view.data ? autoscan::Hash({view.data, static_cast<size_t>(size.QuadPart)}) : autoscan::HashValue{};
}
bool number(const wchar_t*& command, uint64_t& value) {
  if (*command < L'0' || *command > L'9') return false;
  value = 0;
  do {
    unsigned digit = *command++ - L'0';
    if (value > (UINT64_MAX - digit) / 10) return false;
    value = value * 10 + digit;
  } while (*command >= L'0' && *command <= L'9');
  if (*command++ != L' ') return false;
  return value != 0;
}
} // namespace

extern "C" void CALLBACK VersionMV2ScanW(HWND, HINSTANCE, LPWSTR input, int) {
  // Helper entry point: reject malformed arguments before reading the shared file view.
  if (!input) return;
  const wchar_t* command = input;
  uint64_t mapValue = 0, size = 0, pipeValue = 0;
  if (!number(command, mapValue) || !number(command, size) || !number(command, pipeValue) ||
      mapValue > UINTPTR_MAX || pipeValue > UINTPTR_MAX || size > ULONG_MAX) return;
  autoscan::HashValue imageHash{};
  for (auto& c : imageHash) {
    wchar_t digit = *command++;
    if (!((digit >= L'0' && digit <= L'9') || (digit >= L'a' && digit <= L'f'))) return;
    c = static_cast<char>(digit);
  }
  if (*command) return;
  Handle mapping(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(mapValue))), pipe(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pipeValue)));
  View view(mapping.value, static_cast<size_t>(size)); if (!view.data) return;
  auto scanner = scannerHash(); std::array<wchar_t, 1024> cache{};
  std::string_view scannerView(scanner.data(), scanner.size()), imageView(imageHash.data(), imageHash.size());
  autoscan::CachePath(scannerView, imageView, cache);
  autoscan::WirePlan plan;
  // Reuse a valid local cache or inspect the read-only bytes and save a successful plan.
  if (!autoscan::ReadCache(cache.data(), scannerView, imageView, plan)) {
    auto report = autoscan::Analyze({view.data, static_cast<size_t>(size)});
    report.blake3 = imageHash; plan = autoscan::MakePlan(report);
    if (!plan.status) autoscan::WriteCache(cache.data(), scannerView, plan);
  }
  size_t offset = 0;
  // Send the plan back through the inherited local pipe; the helper does not patch Chrome.
  while (offset < sizeof(plan)) {
    DWORD sent = 0;
    if (!WriteFile(pipe.value, reinterpret_cast<const uint8_t*>(&plan) + offset, static_cast<DWORD>(sizeof(plan) - offset), &sent, nullptr) || !sent) break;
    offset += sent;
  }
}

namespace autoscan {
void Patch(HMODULE chrome) noexcept {
  LARGE_INTEGER started{}, identified{}, scanned{}, applied{}, completed{}, frequency{};
  QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&started);
  std::array<wchar_t, 32768> path{};
  DWORD length = GetModuleFileNameW(chrome, path.data(), static_cast<DWORD>(path.size()));
  if (!length || length == path.size()) { trace("cannot resolve chrome.dll"); return; }
  // Lock the installed DLL for reading so its bytes cannot change underneath this check.
  Handle file(CreateFileW(path.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  LARGE_INTEGER size{};
  if (file.value == INVALID_HANDLE_VALUE || !GetFileSizeEx(file.value, &size) || size.QuadPart <= 0 || size.QuadPart > ULONG_MAX) {
    trace("cannot lock the stock image for reading"); return;
  }
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  Handle mapping(CreateFileMappingW(file.value, &security, PAGE_READONLY, 0, 0, nullptr));
  if (!mapping.value) { trace("cannot create read-only image mapping"); return; }
  View view(mapping.value, static_cast<size_t>(size.QuadPart));
  if (!view.data) { trace("cannot map the stock image"); return; }
  StockImage stockImage({view.data, static_cast<size_t>(size.QuadPart)});
  if (!stockImage.info().imageSize || !stockImage.blake3()[0]) { trace("cannot identify stock image"); return; }
  QueryPerformanceCounter(&identified);
  MEMORY_BASIC_INFORMATION memory{};
  if (!VirtualQuery(chrome, &memory, sizeof(memory)) || memory.Type != MEM_IMAGE || memory.AllocationBase != chrome) {
    trace("chrome.dll is not a loaded image"); return;
  }
  WirePlan plan;
  auto scanner = scannerHash(); std::array<wchar_t, 1024> cache{};
  std::string_view scannerView(scanner.data(), scanner.size()), imageView(stockImage.blake3().data(), stockImage.blake3().size());
  bool cached = CachePath(scannerView, imageView, cache) && ReadCache(cache.data(), scannerView, imageView, plan);
  if (!cached && !scanInHelper(mapping.value, static_cast<size_t>(size.QuadPart), stockImage.blake3(), plan)) {
    trace("scan helper failed or exceeded 30 seconds; no patches applied"); return;
  }
  QueryPerformanceCounter(&scanned);
  if (plan.status) { trace({plan.error.data(), static_cast<size_t>(std::find(plan.error.begin(), plan.error.end(), '\0') - plan.error.begin())}); return; }
  if (!plan.offstoreRva) trace("no verified InstallVerifier gate was found");
  if (!plan.crxDownloadRva) trace("no verified CRX download gate was found");
  std::string_view reason;
  auto result = ApplyPlan({reinterpret_cast<uint8_t*>(chrome), stockImage.info().imageSize}, stockImage, plan, reason);
  if (result == ApplyResult::fatal) {
    // End this browser process if restoring bytes or memory permissions failed.
    trace("rollback failed; stopping before Chrome can run partially patched code");
    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
  }
  if (result == ApplyResult::declined) trace(reason);
  else {
    QueryPerformanceCounter(&applied);
    bool deferred = queueView(view.data);
    if (deferred) view.data = nullptr; else view.close();
    QueryPerformanceCounter(&completed);
    auto ms = [&](LARGE_INTEGER from, LARGE_INTEGER to) { return (to.QuadPart - from.QuadPart) * 1000.0 / frequency.QuadPart; };
    std::array<char, 256> message{};
    _snprintf_s(message.data(), message.size(), _TRUNCATE, "%u decisions %s; offstore=%s; crx-download=%s; %s: identity=%.3fms helper=%.3fms apply=%.3fms cleanup-%s=%.3fms total=%.3fms",
      plan.count, result == ApplyResult::applied ? "applied" : "already applied",
      plan.offstoreRva ? "on" : "unavailable", plan.crxDownloadRva ? "on" : "unavailable", plan.cacheHit ? "cached" : "scanned",
      ms(started, identified), ms(identified, scanned), ms(scanned, applied), deferred ? "queued" : "sync", ms(applied, completed), ms(started, completed));
    trace(message.data());
  }
}
} // namespace autoscan
