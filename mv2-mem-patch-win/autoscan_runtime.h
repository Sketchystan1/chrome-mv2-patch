#pragma once
#define NOMINMAX
#include <windows.h>
#include "autoscan.h"
#include "hook.hpp"

namespace autoscan {
// Private, fixed-size IPC between two processes loading the identical DLL.
struct WireSite {
  uint32_t rva = 0, width = 0;
  std::array<uint8_t, 6> stock{}, patch{};
};
struct WirePlan {
  uint32_t magic = 0x32564D41, protocol = 4, count = 0, status = 1, cacheHit = 0, offstoreRva = 0, crxDownloadRva = 0;
  std::array<char, 64> sha256{};
  std::array<char, 160> error{};
  std::array<WireSite, 64> sites{};
};
static_assert(sizeof(WirePlan) == 1532);

WirePlan MakePlan(const Report& report);
ApplyResult ApplyPlan(std::span<uint8_t> image, const StockImage& stockImage,
                      const WirePlan& plan, std::string_view& reason, MemoryOps ops = {});
void Patch(HMODULE chrome) noexcept;
}  // namespace autoscan
