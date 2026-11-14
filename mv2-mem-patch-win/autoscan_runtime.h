#pragma once
// Shared description of proposed memory edits, used by the browser, helper and tests.
#define NOMINMAX
#include <windows.h>
#include "autoscan.h"
#include "hook.hpp"

namespace autoscan {
// The helper sends a fixed-size list of proposed edits; the browser checks it before writing any bytes.
struct WireSite {
  uint32_t rva = 0, width = 0;
  std::array<uint8_t, 6> stock{}, patch{};
};
struct WirePlan {
  uint32_t magic = 0x32564D41, protocol = 5, count = 0, status = 1, cacheHit = 0, offstoreRva = 0, crxDownloadRva = 0;
  std::array<char, 64> blake3{};
  std::array<char, 160> error{};
  std::array<WireSite, 64> sites{};
};
static_assert(sizeof(WirePlan) == 1532); // Both processes must agree on the exact message size.

WirePlan MakePlan(const Report& report);
ApplyResult ApplyPlan(std::span<uint8_t> image, const StockImage& stockImage,
                      const WirePlan& plan, std::string_view& reason, MemoryOps ops = {});
void Patch(HMODULE chrome) noexcept;

// Store and reuse checked plans in the user's cache; browser files are never written here.
bool CachePath(std::string_view scannerHash, std::string_view imageHash, std::span<wchar_t> path) noexcept;
bool ReadCache(const wchar_t* path, std::string_view scannerHash, std::string_view imageHash, WirePlan& plan) noexcept;
bool WriteCache(const wchar_t* path, std::string_view scannerHash, const WirePlan& plan) noexcept;
}  // namespace autoscan
