// Test-only DLL: isolate the external-extension provider without changing real registrations.
#define NOMINMAX
#include <windows.h>
#include <string>
#include "detours.h"

static std::wstring testRoot;
static auto realOpen = ::RegOpenKeyExW;
static auto realCreate = ::RegCreateKeyExW;
static std::wstring redirect(HKEY& root, LPCWSTR key) {
  const wchar_t* prefix = L"Software\\Google\\Chrome\\Extensions";
  size_t length = wcslen(prefix);
  if (!key || (root != HKEY_CURRENT_USER && root != HKEY_LOCAL_MACHINE) ||
      _wcsnicmp(key, prefix, length) || (key[length] && key[length] != L'\\')) return {};
  std::wstring path = testRoot + (root == HKEY_CURRENT_USER ? L"\\user\\" : L"\\machine\\") + key;
  root = HKEY_CURRENT_USER;
  return path;
}
static LSTATUS WINAPI openKey(HKEY root, LPCWSTR key, DWORD options, REGSAM access, PHKEY out) {
  auto path = redirect(root, key);
  return realOpen(root, path.empty() ? key : path.c_str(), options, access, out);
}
static LSTATUS WINAPI createKey(HKEY root, LPCWSTR key, DWORD reserved, LPWSTR type, DWORD options,
                               REGSAM access, const LPSECURITY_ATTRIBUTES security, PHKEY out, LPDWORD disposition) {
  auto path = redirect(root, key);
  return realCreate(root, path.empty() ? key : path.c_str(), reserved, type, options, access, security, out, disposition);
}
extern "C" __declspec(dllexport) void TestRegistryMarker() {}
#pragma comment(linker, "/export:TestRegistryMarker,@1")
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
  if (reason != DLL_PROCESS_ATTACH || DetourIsHelperProcess()) return TRUE;
  DetourRestoreAfterWith();
  wchar_t key[256]{};
  DWORD length = GetEnvironmentVariableW(L"MV2_TEST_REGISTRY", key, static_cast<DWORD>(std::size(key)));
  if (!length || length >= 240 || std::wstring(key).rfind(L"Software\\MV2AutoScan-", 0) != 0) return FALSE;
  testRoot = key;
  DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
  DetourAttach(reinterpret_cast<PVOID*>(&realOpen), reinterpret_cast<PVOID>(openKey));
  DetourAttach(reinterpret_cast<PVOID*>(&realCreate), reinterpret_cast<PVOID>(createKey));
  return DetourTransactionCommit() == NO_ERROR;
}
