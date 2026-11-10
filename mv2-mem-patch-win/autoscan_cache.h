#pragma once
#include "autoscan_runtime.h"
namespace autoscan {
bool CachePath(std::string_view scannerHash, std::string_view imageHash, std::span<wchar_t> path) noexcept;
bool ReadCache(const wchar_t* path, std::string_view scannerHash, std::string_view imageHash, WirePlan& plan) noexcept;
bool WriteCache(const wchar_t* path, std::string_view scannerHash, const WirePlan& plan) noexcept;
} // namespace autoscan
