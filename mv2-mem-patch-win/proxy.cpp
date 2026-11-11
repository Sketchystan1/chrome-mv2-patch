#include "autoscan_runtime.h"
#include <array>
#include <cwchar>
#include <cstring>

// Assembly tail jumps preserve every argument, including the undocumented ByHandle export.
extern "C" { std::array<void*, 17> g_versionExports{}; }
namespace {
constexpr const char* names[] = {
  "GetFileVersionInfoA", "GetFileVersionInfoByHandle", "GetFileVersionInfoExA", "GetFileVersionInfoExW",
  "GetFileVersionInfoSizeA", "GetFileVersionInfoSizeExA", "GetFileVersionInfoSizeExW", "GetFileVersionInfoSizeW",
  "GetFileVersionInfoW", "VerFindFileA", "VerFindFileW", "VerInstallFileA", "VerInstallFileW",
  "VerLanguageNameA", "VerLanguageNameW", "VerQueryValueA", "VerQueryValueW"
};
bool forward() {
  std::array<wchar_t, MAX_PATH + 16> path{};
  DWORD length = GetSystemDirectoryW(path.data(), MAX_PATH);
  if (!length || length >= MAX_PATH) return false;
  std::memcpy(path.data() + length, L"\\version.dll", sizeof(L"\\version.dll"));
  HMODULE real = LoadLibraryExW(path.data(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!real) return false;
  for (size_t n = 0; n < g_versionExports.size(); ++n) {
    g_versionExports[n] = reinterpret_cast<void*>(GetProcAddress(real, names[n]));
    if (!g_versionExports[n]) return false;
  }
  return true;
}
BOOL WINAPI updateAttribute(LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD flags, DWORD_PTR attribute,
    PVOID value, SIZE_T size, PVOID previous, PSIZE_T returned) {
  if (attribute == PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY && value && size >= sizeof(DWORD64))
    *static_cast<DWORD64*>(value) &= ~(DWORD64{1} << 44);
  return UpdateProcThreadAttribute(list, flags, attribute, value, size, previous, returned);
}
autoscan::ImportHook mitigation{reinterpret_cast<void*>(&UpdateProcThreadAttribute), reinterpret_cast<void*>(&updateAttribute)};

void loaded(HMODULE module, LPCWSTR path) {
  if (!module || (reinterpret_cast<uintptr_t>(module) & 3) || !path) return;
  auto filename = path;
  for (auto p = path; *p; ++p) if (*p == L'\\' || *p == L'/') filename = p + 1;
  if (_wcsicmp(filename, L"chrome.dll")) return;
  if (!autoscan::HookImports(module, mitigation)) {
    OutputDebugStringA("[mv2patch autoscan] child mitigation import swap failed; scan declined"); return;
  }
  auto command = GetCommandLineW();
  if (!command || !std::wcsstr(command, L"--type=")) autoscan::Patch(module);
}
HMODULE WINAPI loadEx(LPCWSTR path, HANDLE file, DWORD flags) {
  HMODULE module = LoadLibraryExW(path, file, flags); DWORD error = GetLastError();
  if (!(flags & (DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE)))
    loaded(module, path);
  SetLastError(error); return module;
}
HMODULE WINAPI load(LPCWSTR path) {
  HMODULE module = LoadLibraryW(path); DWORD error = GetLastError();
  loaded(module, path); SetLastError(error); return module;
}
} // namespace

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID) {
  if (reason != DLL_PROCESS_ATTACH) return TRUE;
  if (!forward()) return FALSE;
  std::array<wchar_t, 32768> host{};
  DWORD length = GetModuleFileNameW(nullptr, host.data(), static_cast<DWORD>(host.size()));
  if (!length || length == host.size()) return TRUE;
  const wchar_t* filename = std::wcsrchr(host.data(), L'\\');
  if (_wcsicmp(filename ? filename + 1 : host.data(), L"chrome.exe")) return TRUE;
  HMODULE main = GetModuleHandleW(nullptr);
  autoscan::ImportHook extended{reinterpret_cast<void*>(&LoadLibraryExW), reinterpret_cast<void*>(&loadEx)};
  autoscan::ImportHook simple{reinterpret_cast<void*>(&LoadLibraryW), reinterpret_cast<void*>(&load)};
  if (!autoscan::HookImports(main, mitigation) || !autoscan::HookImports(main, extended) ||
      !autoscan::HookImports(main, simple) || (!extended.count && !simple.count))
    OutputDebugStringA("[mv2patch autoscan] required loader imports unavailable; scan will not run");
  return TRUE;
}
