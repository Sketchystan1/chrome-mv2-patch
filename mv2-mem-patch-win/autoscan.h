#pragma once

// Shared descriptions for the scanner: a "gate" is a browser decision, and an RVA is its position inside the DLL.
#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace autoscan {
// Fixed limits keep an unexpected browser file from growing the scanner's lists without a bound.
template<class T, size_t Capacity> struct FixedList {
  std::array<T, Capacity> items{};
  size_t count = 0;
  bool push_back(const T& value) { if (count == Capacity) return false; items[count++] = value; return true; }
  size_t size() const { return count; }
  bool empty() const { return !count; }
  auto begin() { return items.begin(); }
  auto end() { return items.begin() + count; }
  auto begin() const { return items.begin(); }
  auto end() const { return items.begin() + count; }
  auto& operator[](size_t i) { return items[i]; }
  const auto& operator[](size_t i) const { return items[i]; }
  auto& front() { return items[0]; }
  const auto& front() const { return items[0]; }
  auto& back() { return items[count - 1]; }
  const auto& back() const { return items[count - 1]; }
};
using HashValue = std::array<char, 64>;
enum OptionalGate : uint8_t { Core, InstallVerifier, CrxDownload };
struct Gate {
  uint32_t compare = 0, rva = 0, function = 0, affected = 0, unaffected = 0, exit = 0;
  unsigned kind = 0, width = 0, decoded = 0;
  std::array<uint8_t, 6> stock{}, patch{};
  std::array<int64_t, 5> fields{};  // version, manifest pointer, type, location, converted flag
  bool freePredicate = false;
  OptionalGate optional = Core;
};
struct Issue { uint32_t rva; std::string_view reason; };
struct Report {
  HashValue sha256{}, blake3{};
  std::string_view error, installVerifier, crxDownload;
  unsigned heads = 0, screened = 0, rejected = 0;
  FixedList<Gate, 64> gates;
  FixedList<Issue, 64> unresolved;
  // A possible match is not enough: every suspicious candidate must be resolved before the report is usable.
  bool ready() const { return error.empty() && !gates.empty() && unresolved.empty(); }
};

struct ImageInfo { uint32_t textRva, textRaw, textSize, imageSize; };

HashValue Hash(std::span<const uint8_t> bytes);
HashValue Blake3(std::span<const uint8_t> bytes);
unsigned HashThreadCount() noexcept;
// Free hashing helpers only after all their work has finished, including when Windows unloads this DLL.
void ReleaseHashTls() noexcept;
ImageInfo Inspect(std::span<const uint8_t> bytes);
// Keep the original browser file open and unchanged while comparing it with the running browser.
class StockImage {
  std::span<const uint8_t> bytes_;
  ImageInfo info_;
  HashValue blake3_;
 public:
  explicit StockImage(std::span<const uint8_t> bytes) : bytes_(bytes), info_(Inspect(bytes)), blake3_(Blake3(bytes)) {}
  auto bytes() const { return bytes_; }
  const auto& info() const { return info_; }
  const auto& blake3() const { return blake3_; }
};

// Analyze only reads bytes; its caller must attach the fingerprint of the original file it supplied.
Report Analyze(std::span<const uint8_t> bytes);
// Discover adds file fingerprints to the same read-only analysis for the command-line report.
Report Discover(std::span<const uint8_t> bytes);
}  // namespace autoscan
