// Test-only DLL: redirect Chrome extension registry open/create requests to a separate test folder of keys.
// Other registry requests keep their original destination; this DLL is not part of the shipped patcher.
#define NOMINMAX
#include <windows.h>
#include <string>
#include "detours.h"

static std::wstring testRoot;
static auto realOpen = ::RegOpenKeyExW;
static auto realCreate = ::RegCreateKeyExW;
// Only browser extension keys are redirected into the test area named by MV2_TEST_REGISTRY.
static std::wstring redirect(HKEY& root, LPCWSTR key) {
  if (!key || (root != HKEY_CURRENT_USER && root != HKEY_LOCAL_MACHINE)) return {};
  for (const wchar_t* prefix : {L"Software\\Google\\Chrome\\Extensions", L"Software\\Microsoft\\Edge\\Extensions"}) {
    size_t length = wcslen(prefix);
    if (_wcsnicmp(key, prefix, length) || (key[length] && key[length] != L'\\')) continue;
    std::wstring path = testRoot + (root == HKEY_CURRENT_USER ? L"\\user\\" : L"\\machine\\") + key;
    root = HKEY_CURRENT_USER;
    return path;
  }
  return {};
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
extern "C" void TestRegistryMarker() {}
#if defined(_M_IX86)
#pragma comment(linker, "/export:TestRegistryMarker=_TestRegistryMarker,@1")
#else
#pragma comment(linker, "/export:TestRegistryMarker,@1")
#endif
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
