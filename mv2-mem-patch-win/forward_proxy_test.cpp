#include <windows.h>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "secur32-forward-exports.h"
#define SECURITY_WIN32
#include <security.h>

static void check(bool passed, const char* message) {
  if (!passed) { std::fprintf(stderr, "FAIL: %s (%lu)\n", message, GetLastError()); std::exit(1); }
}

int wmain(int argc, wchar_t** argv) {
  check(argc == 2, "usage: secur32-proxy-test <proxy.dll>");
  HMODULE proxy = LoadLibraryW(argv[1]);
  check(proxy != nullptr, "load proxy");
  std::array<wchar_t, MAX_PATH + 32> path{};
  DWORD length = GetSystemDirectoryW(path.data(), MAX_PATH);
  check(length && length < MAX_PATH, "locate system directory");
  const wchar_t systemDll[] = L"\\secur32.dll";
  check(length + std::size(systemDll) <= path.size(), "system DLL path fits");
  std::memcpy(path.data() + length, systemDll, sizeof(systemDll));
  HMODULE real = LoadLibraryExW(path.data(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  check(real && real != proxy, "load distinct system DLL");
  size_t named = 0;
  for (size_t n = 0; n < std::size(mv2ForwardExports); ++n) {
    auto entry = mv2ForwardExports[n];
    FARPROC proxyByOrdinal = GetProcAddress(proxy, MAKEINTRESOURCEA(entry.ordinal));
    FARPROC systemByOrdinal = GetProcAddress(real, MAKEINTRESOURCEA(entry.ordinal));
    check(proxyByOrdinal && systemByOrdinal, "resolve export ordinal");
    if (entry.name) {
      ++named;
      check(GetProcAddress(proxy, entry.name) == proxyByOrdinal, "match proxy name and ordinal");
      check(GetProcAddress(real, entry.name) == systemByOrdinal, "match system name and ordinal");
    }
  }

  auto proxyName = reinterpret_cast<decltype(&GetUserNameExW)>(GetProcAddress(proxy, "GetUserNameExW"));
  auto systemName = reinterpret_cast<decltype(&GetUserNameExW)>(GetProcAddress(real, "GetUserNameExW"));
  check(proxyName && systemName, "resolve GetUserNameExW");
  wchar_t proxyUser[512]{}, systemUser[512]{};
  ULONG proxySize = 512, systemSize = 512;
  SetLastError(0);
  BOOLEAN proxyOk = proxyName(NameSamCompatible, proxyUser, &proxySize);
  DWORD proxyError = GetLastError();
  SetLastError(0);
  BOOLEAN systemOk = systemName(NameSamCompatible, systemUser, &systemSize);
  check(proxyOk && proxyOk == systemOk && proxyError == GetLastError() &&
        proxySize == systemSize && !std::wcscmp(proxyUser, systemUser), "forward username and last error");
  proxySize = systemSize = 0;
  SetLastError(0);
  proxyOk = proxyName(NameSamCompatible, nullptr, &proxySize);
  proxyError = GetLastError();
  SetLastError(0);
  systemOk = systemName(NameSamCompatible, nullptr, &systemSize);
  check(!proxyOk && proxyOk == systemOk && proxyError == GetLastError() && proxySize == systemSize && proxySize,
        "forward username buffer-size failure");
  auto proxyInterface = reinterpret_cast<decltype(&InitSecurityInterfaceW)>(GetProcAddress(proxy, "InitSecurityInterfaceW"));
  auto systemInterface = reinterpret_cast<decltype(&InitSecurityInterfaceW)>(GetProcAddress(real, "InitSecurityInterfaceW"));
  check(proxyInterface && systemInterface, "resolve InitSecurityInterfaceW");
  auto table = proxyInterface();
  check(table && table == systemInterface() && table->dwVersion && table->EnumerateSecurityPackagesW,
        "forward original SSPI function table");
  FARPROC helper = GetProcAddress(proxy, "VersionMV2ScanW");
  check(helper && helper == GetProcAddress(proxy, MAKEINTRESOURCEA(1000)), "export private scan helper");

  FreeLibrary(proxy); FreeLibrary(real);
  std::printf("PASS: %zu exports (%zu named) and native forwarding for secur32.dll\n",
      std::size(mv2ForwardExports), named);
}
