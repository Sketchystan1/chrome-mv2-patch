#include "autoscan_cache.h"
#include <wincrypt.h>
#include <algorithm>
#include <cstring>
#include <cwchar>

namespace autoscan {
namespace {
constexpr size_t CacheSize = (sizeof(WirePlan) + 128 + 15) & ~size_t{15};
bool validHash(std::string_view hash) {
  return hash.size() == 64 && std::all_of(hash.begin(), hash.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  });
}
bool complete(const WirePlan& plan) {
  return plan.magic == 0x32564d41 && plan.protocol == 4 && !plan.status && !plan.cacheHit &&
    plan.count && plan.count <= plan.sites.size() && validHash({plan.sha256.data(), plan.sha256.size()});
}
}
bool CachePath(std::string_view scannerHash, std::string_view imageHash, std::span<wchar_t> path) noexcept {
  if (path.empty()) return false;
  path[0] = 0;
  if (!validHash(scannerHash) || !validHash(imageHash)) return false;
  std::array<uint8_t, 128> key{};
  memcpy(key.data(), scannerHash.data(), 64); memcpy(key.data() + 64, imageHash.data(), 64);
  auto hash = Hash(key); if (!hash[0]) return false;
  DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", path.data(), static_cast<DWORD>(path.size()));
  if (!length || length >= path.size() || length + 110 >= path.size() ||
      !((length >= 3 && path[1] == L':' && path[2] == L'\\') || (length >= 2 && path[0] == L'\\' && path[1] == L'\\'))) {
    path[0] = 0; return false;
  }
  constexpr wchar_t suffix[] = L"\\chrome-mv2-patch\\autoscan\\";
  std::copy_n(suffix, std::size(suffix) - 1, path.data() + length); length += static_cast<DWORD>(std::size(suffix) - 1);
  for (auto c : hash) path[length++] = static_cast<wchar_t>(c);
  std::copy_n(L".bin", 5, path.data() + length); return true;
}
bool ReadCache(const wchar_t* path, std::string_view scannerHash, std::string_view imageHash, WirePlan& plan) noexcept {
  if (!path || !*path || !validHash(scannerHash) || !validHash(imageHash)) return false;
  HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  LARGE_INTEGER size{}; DWORD got = 0; std::array<uint8_t, CacheSize> clear{};
  bool ok = GetFileSizeEx(file, &size) && size.QuadPart == clear.size() &&
    ReadFile(file, clear.data(), static_cast<DWORD>(clear.size()), &got, nullptr) && got == clear.size();
  CloseHandle(file);
  if (!ok || !CryptUnprotectMemory(clear.data(), static_cast<DWORD>(clear.size()), CRYPTPROTECTMEMORY_SAME_LOGON)) return false;
  auto checksum = Hash(std::span(clear).subspan(64));
  if (!checksum[0] || memcmp(clear.data(), checksum.data(), 64) || memcmp(clear.data() + 64, scannerHash.data(), 64)) return false;
  WirePlan cached; memcpy(&cached, clear.data() + 128, sizeof(cached));
  if (!complete(cached) || memcmp(cached.sha256.data(), imageHash.data(), 64)) return false;
  cached.cacheHit = 1; plan = cached; return true;
}
bool WriteCache(const wchar_t* path, std::string_view scannerHash, const WirePlan& plan) noexcept {
  if (!path || !*path || !validHash(scannerHash) || !complete(plan)) return false;
  std::array<uint8_t, CacheSize> clear{};
  memcpy(clear.data() + 64, scannerHash.data(), 64); memcpy(clear.data() + 128, &plan, sizeof(plan));
  auto checksum = Hash(std::span(clear).subspan(64));
  if (!checksum[0]) return false;
  memcpy(clear.data(), checksum.data(), 64);
  // SAME_LOGON uses caller storage; a new Windows logon safely causes a fresh scan.
  if (!CryptProtectMemory(clear.data(), static_cast<DWORD>(clear.size()), CRYPTPROTECTMEMORY_SAME_LOGON)) return false;
  // shortcut: cache paths are bounded to 1024 characters; longer profiles still scan without caching.
  std::array<wchar_t, 1152> temporary{};
  if (wcslen(path) > 1024) return false;
  wcscpy_s(temporary.data(), temporary.size(), path);
  wchar_t* slash = wcsrchr(temporary.data(), L'\\');
  if (slash) {
    *slash = 0; wchar_t* parent = wcsrchr(temporary.data(), L'\\');
    if (parent) { *parent = 0; CreateDirectoryW(temporary.data(), nullptr); *parent = L'\\'; }
    CreateDirectoryW(temporary.data(), nullptr);
  }
  if (_snwprintf_s(temporary.data(), temporary.size(), _TRUNCATE, L"%ls.%lu.%llu.tmp", path,
                  GetCurrentProcessId(), GetTickCount64()) < 0) return false;
  HANDLE file = CreateFileW(temporary.data(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  DWORD written = 0;
  bool ok = WriteFile(file, clear.data(), static_cast<DWORD>(clear.size()), &written, nullptr) && written == clear.size() && FlushFileBuffers(file);
  ok = CloseHandle(file) && ok;
  if (ok && MoveFileExW(temporary.data(), path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return true;
  DeleteFileW(temporary.data()); return false;
}
} // namespace autoscan
