#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include "lifter.hpp"

namespace autoscan {
// IMAGE_RUNTIME_FUNCTION_ENTRY itself aliases the ARM64 format on an ARM64 build.
using X64RuntimeFunction = _IMAGE_RUNTIME_FUNCTION_ENTRY;
struct Range {
  uint32_t begin = 0, end = 0;
  bool contains(uint32_t p) const { return p >= begin && p < end; }
  explicit operator bool() const { return begin < end; }
};
struct Section {
  uint32_t rva = 0, raw = 0, size = 0, virtualSize = 0, flags = 0;
  bool contains(uint32_t p, size_t n = 1) const { return p >= rva && p - rva <= size && n <= size - (p - rva); }
};
constexpr uint16_t NativeMachine() {
#if defined(AUTOSCAN_X64)
  return IMAGE_FILE_MACHINE_AMD64;
#elif defined(AUTOSCAN_X86)
  return IMAGE_FILE_MACHINE_I386;
#elif defined(AUTOSCAN_ARM64)
  return IMAGE_FILE_MACHINE_ARM64;
#endif
}

// File-layout PE view: every RVA is translated through its owning section.
class PeImage {
  std::span<const uint8_t> bytes_;
  std::array<Section, 96> sections_{};
  std::array<IMAGE_DATA_DIRECTORY, 16> directories_{};
  unsigned sectionCount_ = 0;
 public:
  Section text{}, rdata{}, pdata{};
  uint32_t imageSize = 0, headersSize = 0;
  uint64_t imageBase = 0;
  uint16_t machine = 0;
  const char* error = nullptr;
  explicit PeImage(std::span<const uint8_t> bytes) : bytes_(bytes) { parse(); }
  bool valid() const { return !error; }
  auto bytes() const { return bytes_; }
  const auto& directory(unsigned n) const { return directories_[n]; }
  template<class T> bool read(size_t pos, T& value) const {
    if (pos > bytes_.size() || sizeof(T) > bytes_.size() - pos) return false;
    std::memcpy(&value, bytes_.data() + pos, sizeof value); return true;
  }
  std::span<const uint8_t> at(uint32_t rva, size_t length) const {
    if (rva < headersSize && rva <= bytes_.size() && length <= headersSize - rva && length <= bytes_.size() - rva)
      return bytes_.subspan(rva, length);
    for (unsigned n = 0; n < sectionCount_; ++n) if (sections_[n].contains(rva, length))
      return bytes_.subspan(static_cast<size_t>(sections_[n].raw) + (rva - sections_[n].rva), length);
    return {};
  }
  template<class T> bool rvaRead(uint32_t rva, T& value) const {
    auto b = at(rva, sizeof(T)); if (b.size() != sizeof(T)) return false;
    std::memcpy(&value, b.data(), sizeof value); return true;
  }
  auto code(uint32_t rva) const {
    return text.contains(rva) ? at(rva, text.size - (rva - text.rva)) : std::span<const uint8_t>{};
  }
  bool executable(uint32_t rva, size_t length) const {
    for (unsigned n = 0; n < sectionCount_; ++n)
      if ((sections_[n].flags & IMAGE_SCN_MEM_EXECUTE) && sections_[n].contains(rva, length)) return true;
    return false;
  }
 private:
  void parse() {
    auto fail = [&](const char* message) { error = message; };
    IMAGE_DOS_HEADER dos{}; IMAGE_FILE_HEADER file{}; uint32_t signature = 0;
    if (!read(0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(dos)) { fail("invalid DOS header"); return; }
    size_t nt = static_cast<uint32_t>(dos.e_lfanew);
    if (!read(nt, signature) || signature != IMAGE_NT_SIGNATURE || !read(nt + 4, file)) { fail("truncated PE header"); return; }
    machine = file.Machine;
    bool pe32 = machine == IMAGE_FILE_MACHINE_I386;
    if (!pe32 && machine != IMAGE_FILE_MACHINE_AMD64 && machine != IMAGE_FILE_MACHINE_ARM64) { fail("unsupported PE machine"); return; }
    size_t optional = nt + 24, table = optional + file.SizeOfOptionalHeader;
    const unsigned directoryOffset = pe32 ? 96 : 112;
    uint16_t magic = 0; uint32_t count = 0;
    if (!read(optional, magic) || magic != (pe32 ? 0x10b : 0x20b) || file.SizeOfOptionalHeader < directoryOffset ||
        !file.NumberOfSections || file.NumberOfSections > sections_.size() || table > bytes_.size() ||
        file.NumberOfSections > (bytes_.size() - table) / sizeof(IMAGE_SECTION_HEADER) ||
        !read(optional + 56, imageSize) || !read(optional + 60, headersSize) ||
        !read(optional + directoryOffset - 4, count) || count > 16 ||
        count > (file.SizeOfOptionalHeader - directoryOffset) / sizeof(IMAGE_DATA_DIRECTORY)) {
      fail("invalid PE optional header or sections"); return;
    }
    if (pe32) { uint32_t base = 0; read(optional + 28, base); imageBase = base; }
    else read(optional + 24, imageBase);
    if (!imageSize || headersSize > imageSize || headersSize > bytes_.size() ||
        table + file.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > headersSize) { fail("invalid PE image size"); return; }
    for (unsigned n = 0; n < count; ++n) read(optional + directoryOffset + n * 8, directories_[n]);
    for (unsigned n = 0; n < file.NumberOfSections; ++n) {
      IMAGE_SECTION_HEADER header{}; read(table + n * sizeof(header), header);
      uint32_t extent = std::max(header.Misc.VirtualSize, header.SizeOfRawData);
      if ((extent && header.VirtualAddress < headersSize) || (header.SizeOfRawData && header.PointerToRawData < headersSize) ||
          header.PointerToRawData > bytes_.size() || header.SizeOfRawData > bytes_.size() - header.PointerToRawData ||
          header.VirtualAddress > imageSize || extent > imageSize - header.VirtualAddress) { fail("PE section exceeds file or image"); return; }
      Section section{header.VirtualAddress, header.PointerToRawData,
        header.Misc.VirtualSize ? std::min(header.SizeOfRawData, header.Misc.VirtualSize) : header.SizeOfRawData,
        extent, header.Characteristics};
      for (unsigned j = 0; j < sectionCount_; ++j) {
        const auto& other = sections_[j];
        if (extent && other.virtualSize && section.rva < static_cast<uint64_t>(other.rva) + other.virtualSize &&
            other.rva < static_cast<uint64_t>(section.rva) + extent) { fail("overlapping PE sections"); return; }
      }
      sections_[sectionCount_++] = section;
      Section* named = !std::memcmp(header.Name, ".text\0", 6) ? &text :
        !std::memcmp(header.Name, ".rdata\0", 7) ? &rdata : !std::memcmp(header.Name, ".pdata\0", 7) ? &pdata : nullptr;
      if (named) {
        if (named->size) { fail("duplicate PE section"); return; }
        *named = section;
      }
    }
    if (!text.size || !(text.flags & IMAGE_SCN_MEM_EXECUTE)) { fail("missing executable .text"); return; }
  }
};

class Boundaries {
  const PeImage& pe_;
  uint32_t table_ = 0, entries_ = 0, stride_ = 0;
  bool arm_ = false;
  bool unwind64(uint32_t rva, Range function) const {
    std::array<uint32_t, 8> visited{};
    for (unsigned depth = 0; depth < visited.size(); ++depth) {
      if (!rva || (rva & 3)) return false;
      for (unsigned n = 0; n < depth; ++n) if (visited[n] == rva) return false;
      visited[depth] = rva;
      auto header = pe_.at(rva, 4); if (header.empty()) return false;
      unsigned version = header[0] & 7, flags = header[0] >> 3, codes = header[2];
      if ((version != 1 && version != 2) || flags > 7 || ((flags & 4) && (flags & 3)) ||
          header[1] > function.end - function.begin) return false;
      unsigned length = 4 + ((codes + 1) & ~1u) * 2;
      if (pe_.at(rva, length + (flags & 4 ? 12 : flags & 3 ? 4 : 0)).empty()) return false;
      if (!(flags & 4)) return true;
      X64RuntimeFunction parent{};
      if (!pe_.rvaRead(rva + length, parent) || parent.BeginAddress >= parent.EndAddress ||
          !pe_.text.contains(parent.BeginAddress, parent.EndAddress - parent.BeginAddress)) return false;
      rva = parent.UnwindInfoAddress; function = {parent.BeginAddress, parent.EndAddress};
    }
    return false;
  }
  bool entry(uint32_t index, Range& range, bool validate = true) const {
    if (index >= entries_) return false;
    uint32_t unwind = 0;
    if (arm_) {
      IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY record{};
      if (!pe_.rvaRead(table_ + index * 8, record)) return false;
      range.begin = record.BeginAddress; unwind = record.UnwindData;
      uint32_t length = 0;
      if (unwind & 3) {
        if ((unwind & 3) == 3) return false; // Flag 3 is reserved by the Windows ABI.
        length = ((unwind >> 2) & 0x7ff) * 4;
      } else {
        uint32_t header = 0;
        if (!unwind || !pe_.rvaRead(unwind, header) || ((header >> 18) & 3)) return false;
        length = (header & 0x3ffff) * 4;
        if (validate) {
          uint32_t epilogs = (header >> 22) & 31, words = header >> 27, offset = 4;
          if (!epilogs && !words) {
            uint32_t extended = 0;
            if (!pe_.rvaRead(unwind + 4, extended) || (extended >> 24)) return false;
            epilogs = extended & 0xffff; words = (extended >> 16) & 0xff; offset += 4;
          }
          if (!(header & (1u << 21))) offset += epilogs * 4;
          offset += words * 4 + ((header & (1u << 20)) ? 4 : 0);
          if (pe_.at(unwind, offset).empty()) return false;
        }
      }
      if ((range.begin & 3) || !length || length > UINT32_MAX - range.begin) return false;
      range.end = range.begin + length;
    } else {
      X64RuntimeFunction record{};
      if (!pe_.rvaRead(table_ + index * 12, record)) return false;
      range = {record.BeginAddress, record.EndAddress}; unwind = record.UnwindInfoAddress;
    }
    if (!range || (!pe_.text.contains(range.begin, range.end - range.begin) &&
                   !(arm_ && pe_.executable(range.begin, range.end - range.begin)))) return false;
    return arm_ || !validate || unwind64(unwind, range);
  }
  bool prologue(uint32_t at) const {
    auto b = pe_.at(at, 3); if (b.size() != 3) return false;
    return (b[0] == 0x55 && ((b[1] == 0x8b && b[2] == 0xec) || (b[1] == 0x89 && b[2] == 0xe5))) ||
      (b[0] == 0x8b && b[1] == 0xff);
  }
  bool paddingBefore(uint32_t at) const {
    if (at == pe_.text.rva) return true;
    auto b = pe_.at(at - 1, 1); return !b.empty() && (b[0] == 0xcc || b[0] == 0x90);
  }
  // One immutable PE view owns the cached trim result.
  mutable Range trimSource_{}, trimResult_{};
  Range trim(Range range) const {
    if (range.begin == trimSource_.begin && range.end == trimSource_.end) return trimResult_;
    trimSource_ = range; trimResult_ = trimUncached(range); return trimResult_;
  }
  Range trimUncached(Range range) const {
    if (arm_) {
      uint32_t word = 0;
      while (range.end - range.begin >= 4 && pe_.rvaRead(range.end - 4, word) && word == 0xd4200000) range.end -= 4;
      return range;
    }
#if defined(AUTOSCAN_X86) || defined(AUTOSCAN_X64) || defined(AUTOSCAN_ALL_ARCH_TESTS)
    uint32_t last = range.begin;
    for (uint32_t p = range.begin; p < range.end;) {
      auto b = pe_.at(p, range.end - p);
      auto i = LiftX86(b, p, pe_.machine == IMAGE_FILE_MACHINE_AMD64);
      if (!i.length()) return range;
      if (!(i.length() == 1 && (b[0] == 0xcc || b[0] == 0x90))) last = p + i.length();
      p += i.length();
    }
    range.end = last;
#endif
    return range;
  }
  Range leaf(uint32_t position, uint32_t after = 0) const {
    if (arm_) {
      if (!after || after > position || position - after > 4096) return {};
      uint32_t begin = after;
      for (uint32_t pc = after; pc < position; pc += 4) {
        uint32_t word = 0;
        if (!pe_.rvaRead(pc, word)) return {};
        if (!word || (word & 0xffe0001f) == 0xd4200000) begin = pc + 4;
      }
      uint32_t end = std::min<uint32_t>(pe_.text.rva + pe_.text.size, begin + 4096);
      for (uint32_t pc = position + 4; pc < end; pc += 4) {
        uint32_t word = 0;
        if (!pe_.rvaRead(pc, word)) return {};
        if (!word || (word & 0xffe0001f) == 0xd4200000) { end = pc; break; }
      }
      return {begin, end};
    }
#if defined(AUTOSCAN_X86) || defined(AUTOSCAN_X64) || defined(AUTOSCAN_ALL_ARCH_TESTS)
    uint32_t lower = position - pe_.text.rva > 4096 ? position - 4096 : pe_.text.rva;
    for (uint32_t begin = position & ~15u; begin >= lower && begin >= pe_.text.rva; begin -= 16) {
      if (begin == pe_.text.rva || (!pe_.at(begin - 1, 1).empty() && pe_.at(begin - 1, 1)[0] == 0xcc)) {
        uint32_t end = std::min<uint32_t>(pe_.text.rva + pe_.text.size, begin + 4096);
        for (uint32_t p = begin; p < end;) {
          auto b = pe_.at(p, end - p);
          if (b.size() >= 4 && ReadInsn<uint32_t>(b.data()) == 0xcccccccc)
            return position < p ? trim({begin, p}) : Range{};
          auto i = LiftX86(b, p, pe_.machine == IMAGE_FILE_MACHINE_AMD64);
          if (!i.length()) break;
          p += i.length();
        }
      }
      if (begin < 16) break;
    }
#endif
    return {};
  }
 public:
  const char* error = nullptr;
  explicit Boundaries(const PeImage& pe) : pe_(pe), arm_(pe.machine == IMAGE_FILE_MACHINE_ARM64) {
    if (!pe.valid()) { error = pe.error; return; }
    if (pe.machine == IMAGE_FILE_MACHINE_I386) {
      const auto& config = pe.directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
      if (!config.VirtualAddress && !config.Size) return;
      constexpr size_t required = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardFlags) + sizeof(DWORD);
      uint32_t size = 0;
      if (!pe.rvaRead(config.VirtualAddress, size) || config.Size < 4 || size > config.Size) { error = "invalid load config"; return; }
      if (size < required) return;
      IMAGE_LOAD_CONFIG_DIRECTORY32 load{};
      auto bytes = pe.at(config.VirtualAddress, required);
      if (bytes.empty()) { error = "truncated load config"; return; }
      std::memcpy(&load, bytes.data(), required);
      if (!load.GuardCFFunctionCount) return;
      stride_ = 4 + (load.GuardFlags >> 28);
      if (load.GuardCFFunctionTable < pe.imageBase || load.GuardCFFunctionTable - pe.imageBase > UINT32_MAX ||
          load.GuardCFFunctionCount > UINT32_MAX / stride_) { error = "invalid CFG table"; return; }
      table_ = static_cast<uint32_t>(load.GuardCFFunctionTable - pe.imageBase); entries_ = load.GuardCFFunctionCount;
      if (pe.at(table_, static_cast<size_t>(entries_) * stride_).empty()) { error = "truncated CFG table"; return; }
      uint32_t previous = 0;
      for (uint32_t n = 0; n < entries_; ++n) {
        uint32_t rva = 0; pe.rvaRead(table_ + n * stride_, rva);
        if (!pe.text.contains(rva) || (n && rva <= previous)) { error = "invalid CFG function RVA"; return; }
        previous = rva;
      }
      return;
    }
    const auto& exceptions = pe.directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    table_ = exceptions.VirtualAddress ? exceptions.VirtualAddress : pe.pdata.rva;
    uint32_t size = exceptions.VirtualAddress ? exceptions.Size : pe.pdata.size;
    stride_ = arm_ ? 8 : 12;
    if (!size && !table_) return;
    if (!size || size % stride_ || pe.at(table_, size).empty()) { error = "invalid runtime function table"; return; }
    entries_ = size / stride_;
    Range previous{}; uint32_t previousBegin = 0;
    for (uint32_t n = 0; n < entries_; ++n) {
      Range current{};
      uint32_t begin = 0; pe.rvaRead(table_ + n * stride_, begin);
      if (n && begin < previousBegin) { error = "unsorted runtime function table"; return; }
      previousBegin = begin;
      if (!arm_) {
        X64RuntimeFunction record{}; pe.rvaRead(table_ + n * stride_, record);
        // LLVM emits some empty/reversed x64 entries; they provide no boundary evidence.
        if (record.BeginAddress >= record.EndAddress || !pe.text.contains(record.BeginAddress, record.EndAddress - record.BeginAddress)) continue;
      }
      if (!entry(n, current) || (n && previous.end > current.begin)) { error = "invalid unwind range or xdata"; return; }
      previous = current;
    }
  }
  Range find(uint32_t position) const {
    if (error || !pe_.text.contains(position)) return {};
    uint32_t low = 0, high = entries_;
    while (low < high) {
      uint32_t mid = low + (high - low) / 2, begin = 0;
      pe_.rvaRead(table_ + mid * stride_, begin);
      if (begin <= position) low = mid + 1; else high = mid;
    }
    if (pe_.machine != IMAGE_FILE_MACHINE_I386) {
      Range range{};
      while (low) {
        if (entry(--low, range, false)) {
          if (range.contains(position)) return trim(range);
          break;
        }
      }
      return leaf(position, range.end);
    }
    Range range{0, pe_.text.rva + pe_.text.size};
    if (low) pe_.rvaRead(table_ + (low - 1) * stride_, range.begin);
    if (low < entries_) pe_.rvaRead(table_ + low * stride_, range.end);
    // shortcut: x86 call/prologue recovery searches 64 KiB around the candidate; larger gaps decline.
#if defined(AUTOSCAN_X86) || defined(AUTOSCAN_X64) || defined(AUTOSCAN_ALL_ARCH_TESTS)
    uint32_t first = std::max(range.begin, position - pe_.text.rva > 65536 ? position - 65536 : pe_.text.rva);
    uint32_t last = static_cast<uint32_t>(std::min<uint64_t>(range.end, static_cast<uint64_t>(position) + 65536));
    bool anchored = range.begin && first == range.begin;
    auto consider = [&](uint32_t rva) {
      if (rva <= position) range.begin = std::max(range.begin, rva);
      else range.end = std::min(range.end, rva);
    };
    for (uint32_t p = first; p < last;) {
      if (prologue(p) && paddingBefore(p)) {
        consider(p); anchored = true;
        if (p > position) break;
      }
      if (!anchored) { ++p; continue; }
      auto instruction = LiftX86(pe_.code(p), p, false);
      if (!instruction.length()) { anchored = false; ++p; continue; }
      if (instruction.op == Op::Other && instruction.other() == Other::Call && instruction.target() && pe_.text.contains(instruction.target()))
        consider(instruction.target());
      if (instruction.op == Op::Ret || (instruction.op == Op::Other && instruction.other() == Other::Trap)) anchored = false;
      p += instruction.length();
    }
#endif
    if (!range.begin || !range.contains(position) || range.end - range.begin > 65536) return {};
    return trim(range);
  }
};
} // namespace autoscan
