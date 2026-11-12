#include "autoscan_runtime.h"

#include <algorithm>
#include <cstring>
#include <psapi.h>
#include "boundaries.hpp"

namespace autoscan {
WirePlan MakePlan(const Report& report) {
  WirePlan plan;
  std::copy_n(report.blake3.begin(), std::min(report.blake3.size(), plan.blake3.size()), plan.blake3.begin());
  std::string_view error = report.error.empty() && !report.unresolved.empty() ? report.unresolved.front().reason : report.error;
  std::copy_n(error.begin(), std::min(error.size(), plan.error.size() - 1), plan.error.begin());
  if (!report.ready() || !report.blake3[0] || report.gates.size() > plan.sites.size()) return plan;
  plan.count = static_cast<uint32_t>(report.gates.size());
  for (size_t n = 0; n < report.gates.size(); ++n) {
    const auto& gate = report.gates[n];
    if (gate.optional) {
      if (gate.optional != InstallVerifier && gate.optional != CrxDownload) return plan;
      auto& rva = gate.optional == CrxDownload ? plan.crxDownloadRva : plan.offstoreRva;
      if (rva || !gate.rva) return plan;
      rva = gate.rva;
    }
    plan.sites[n] = {gate.rva, gate.width, gate.stock, gate.patch};
  }
  if (plan.count > unsigned(plan.offstoreRva != 0) + unsigned(plan.crxDownloadRva != 0)) plan.status = 0;
  return plan;
}

static bool readable(std::span<uint8_t> image) {
  uintptr_t end = reinterpret_cast<uintptr_t>(image.data()) + image.size();
  for (uintptr_t p = reinterpret_cast<uintptr_t>(image.data()); p < end;) {
    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQuery(reinterpret_cast<void*>(p), &info, sizeof info) || info.State != MEM_COMMIT ||
        info.Protect & (PAGE_GUARD | PAGE_NOACCESS) || !(info.Protect & (PAGE_READONLY | PAGE_READWRITE |
        PAGE_WRITECOPY | PAGE_EXECUTE_READ))) return false;
    uintptr_t next = reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
    if (next <= p) return false;
    p = next;
  }
  return true;
}

ApplyResult ApplyPlan(std::span<uint8_t> image, const StockImage& stockImage,
                      const WirePlan& plan, std::string_view& reason, MemoryOps ops) {
  auto decline = [&](const char* why) { reason = why; return ApplyResult::declined; };
  const auto& info = stockImage.info();
  auto disk = stockImage.bytes();
  if (plan.magic != 0x32564D41 || plan.protocol != 5 || plan.status || !plan.count || plan.count > plan.sites.size() || plan.cacheHit > 1)
    return decline("incomplete or incompatible scan response");
  if (!plan.blake3[0] || plan.blake3 != stockImage.blake3()) return decline("image hash differs from scan response");
  PeImage pe(disk);
  if (!pe.valid() || !info.imageSize || info.imageSize != image.size()) return decline("loaded image size differs");
  uintptr_t base = reinterpret_cast<uintptr_t>(image.data());
  if (image.size() > UINTPTR_MAX - base) return decline("loaded image address overflows");
  for (uintptr_t p = base; p < base + image.size();) {
    MEMORY_BASIC_INFORMATION region{};
    if (!VirtualQuery(reinterpret_cast<void*>(p), &region, sizeof region) || region.AllocationBase != image.data())
      return decline("loaded image crosses allocation boundaries");
    uintptr_t next = reinterpret_cast<uintptr_t>(region.BaseAddress) + region.RegionSize;
    if (next <= p) return decline("invalid loaded image region");
    p = next;
  }
  auto liveText = image.subspan(info.textRva, info.textSize);
  if (!readable(liveText)) return decline("loaded code is not fully readable");

  auto sameText = [&](uint32_t from, uint32_t to) {
    uint32_t cursor = from;
    const auto& reloc = pe.directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    auto table = pe.at(reloc.VirtualAddress, reloc.Size);
    if (reloc.Size && table.size() != reloc.Size) return false;
    uint64_t delta = static_cast<uint64_t>(base) - pe.imageBase;
    for (size_t offset = 0; offset < table.size();) {
      if (table.size() - offset < 8) return false;
      auto block = ReadInsn<IMAGE_BASE_RELOCATION>(table.data() + offset);
      if (block.SizeOfBlock < 8 || block.SizeOfBlock > table.size() - offset || (block.SizeOfBlock & 1)) return false;
      // A 12-bit offset plus an eight-byte relocation can cross the block's page.
      uint64_t blockEnd = uint64_t{block.VirtualAddress} + 0xfff + 8;
      if (block.VirtualAddress >= to || blockEnd <= from) { offset += block.SizeOfBlock; continue; }
      for (size_t n = 8; n < block.SizeOfBlock; n += 2) {
        uint16_t entry = ReadInsn<uint16_t>(table.data() + offset + n);
        unsigned type = entry >> 12;
        if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
        uint64_t rva = static_cast<uint64_t>(block.VirtualAddress) + (entry & 0xfff);
        unsigned width = type == IMAGE_REL_BASED_HIGHLOW ? 4 : type == IMAGE_REL_BASED_DIR64 ? 8 : 0;
        if (rva >= to || rva + (width ? width : 1) <= from) continue;
        if (!width || rva < cursor || rva + width > to) return false;
        if (memcmp(image.data() + cursor, disk.data() + info.textRaw + cursor - info.textRva, rva - cursor)) return false;
        uint64_t value = 0;
        memcpy(&value, disk.data() + info.textRaw + rva - info.textRva, width);
        value += delta;
        if (memcmp(image.data() + rva, &value, width)) return false;
        cursor = static_cast<uint32_t>(rva) + width;
      }
      offset += block.SizeOfBlock;
    }
    return !memcmp(image.data() + cursor, disk.data() + info.textRaw + cursor - info.textRva, to - cursor);
  };
  uint32_t previous = info.textRva;
  unsigned done = 0, optional = 0;
  for (uint32_t n = 0; n < plan.count; ++n) {
    const auto& site = plan.sites[n];
    bool offstore = site.rva == plan.offstoreRva, crxDownload = site.rva == plan.crxDownloadRva;
    if (offstore && crxDownload) return decline("overlapping optional decisions");
    optional += offstore || crxDownload;
    if (site.rva < previous || !pe.text.contains(site.rva, site.width))
      return decline("invalid, overlapping or unsorted decision addresses");
    auto expected = site.stock;
    int64_t target = 0;
#if defined(AUTOSCAN_ARM64)
    if (site.width != 4 || (site.rva & 3)) return decline("invalid ARM64 decision");
    uint32_t word = ReadInsn<uint32_t>(site.stock.data());
    uint32_t replacement = 0;
    if (offstore || crxDownload) {
      if (offstore ? (word & 0xfff80000) != 0x37180000 || (word & 31) == 31 : (word & 0xfff8001f) != 0x36000000)
        return decline("optional ARM64 decision metadata differs");
      int32_t offset = static_cast<int32_t>(word << 13) >> 18;
      target = static_cast<int64_t>(site.rva) + int64_t{offset} * 4;
      replacement = offstore ? 0x14000000 | (static_cast<uint32_t>(offset) & 0x03ffffff) : 0xd503201f;
    } else {
      unsigned cc = word & 15;
      if ((word & 0xff000010) != 0x54000000 || cc < 10 || cc > 13) return decline("unsupported decision instruction");
      replacement = cc == 11 || cc == 13 ? 0xd503201f : (word & ~15u) | 14;
      target = static_cast<int64_t>(site.rva) + (static_cast<int32_t>(word << 8) >> 13) * int64_t{4};
    }
    memcpy(expected.data(), &replacement, 4);
#else
    if (site.width != 2 && site.width != 6) return decline("invalid decision width");
    unsigned opcode = site.width == 2 ? site.stock[0] : site.stock[1];
    if ((site.width == 6 && site.stock[0] != 0x0F) ||
        (site.width == 2 ? (opcode < 0x74 || opcode > 0x75) && (opcode < 0x7C || opcode > 0x7F) :
                          (opcode < 0x84 || opcode > 0x85) && (opcode < 0x8C || opcode > 0x8F)))
      return decline("unsupported decision instruction");
    if ((opcode == 0x75 || opcode == 0x85) != offstore) return decline("optional decision metadata differs");
    if ((opcode == 0x74 || opcode == 0x84) != crxDownload) return decline("CRX download metadata differs");
    bool inverted = (opcode & 3) == 0 || (opcode & 3) == 2;
    if (inverted) std::fill_n(expected.begin(), site.width, uint8_t{0x90});
    else if (site.width == 2) expected[0] = 0xEB;
    else { expected[0] = 0x90; expected[1] = 0xE9; }
    int32_t displacement = static_cast<int8_t>(site.stock[1]);
    if (site.width == 6) memcpy(&displacement, site.stock.data() + 2, 4);
    target = static_cast<int64_t>(site.rva) + site.width + displacement;
#endif
    if (memcmp(expected.data(), site.patch.data(), site.width)) return decline("patch does not select the recognized outcome");
    if (target < info.textRva || target >= static_cast<int64_t>(info.textRva) + info.textSize)
      return decline("decision target leaves executable section");
    const uint8_t* stock = disk.data() + info.textRaw + site.rva - info.textRva;
    uint8_t* live = image.data() + site.rva;
    if (memcmp(stock, site.stock.data(), site.width)) return decline("decision differs from scanned file");
    if (!memcmp(live, site.patch.data(), site.width)) ++done;
    else if (memcmp(live, site.stock.data(), site.width)) return decline("loaded decision differs");
    if (!sameText(previous, site.rva)) return decline("loaded code differs from the scanned file");
    previous = site.rva + site.width;
  }
  if (optional != unsigned(plan.offstoreRva != 0) + unsigned(plan.crxDownloadRva != 0) || optional == plan.count)
    return decline("invalid optional decision metadata");
  if (!sameText(previous, info.textRva + info.textSize)) return decline("loaded code differs from the scanned file");
  if (done && done != plan.count) return decline("mixed stock and patched state");
  if (done == plan.count) return ApplyResult::alreadyApplied;

  SYSTEM_INFO system{}; GetSystemInfo(&system);
  struct Page { uintptr_t address; DWORD old = 0; bool changed = false; };
  FixedList<Page, 128> pages;
  auto addPage = [&](uintptr_t address) {
    if (pages.empty() || pages.back().address != address) pages.push_back({address});
  };
  for (uint32_t n = 0; n < plan.count; ++n) {
    auto& site = plan.sites[n];
    uintptr_t first = reinterpret_cast<uintptr_t>(image.data()) + site.rva;
    uintptr_t last = first + site.width - 1;
    addPage(first & ~(static_cast<uintptr_t>(system.dwPageSize) - 1));
    addPage(last & ~(static_cast<uintptr_t>(system.dwPageSize) - 1));
  }
  std::array<PSAPI_WORKING_SET_EX_INFORMATION, 128> pageInfo{};
  for (size_t n = 0; n < pages.size(); ++n)
    pageInfo[n].VirtualAddress = reinterpret_cast<void*>(pages[n].address);
  bool queriedPages = K32QueryWorkingSetEx(GetCurrentProcess(), pageInfo.data(),
    static_cast<DWORD>(pages.size() * sizeof(pageInfo[0]))) != FALSE;
  for (size_t n = 0; n < pages.size(); ++n) {
    const auto& attributes = pageInfo[n].VirtualAttributes;
    if (queriedPages && attributes.Valid && attributes.Win32Protection == PAGE_EXECUTE_READ) continue;
    MEMORY_BASIC_INFORMATION memory{};
    if (!VirtualQuery(reinterpret_cast<void*>(pages[n].address), &memory, sizeof(memory)) || memory.Protect != PAGE_EXECUTE_READ)
      return decline("decision page is not execute/read");
  }
  auto restore = [&]() {
    bool ok = true;
    for (auto& page : pages) if (page.changed) {
      DWORD ignored;
      if (ops.protect(reinterpret_cast<void*>(page.address), system.dwPageSize, PAGE_EXECUTE_READ, &ignored)) page.changed = false;
      else ok = false;
    }
    return ok;
  };
  for (auto& page : pages) {
    if (!ops.protect(reinterpret_cast<void*>(page.address), system.dwPageSize, PAGE_READWRITE, &page.old)) {
      reason = "could not make every decision writable";
      return restore() ? ApplyResult::declined : ApplyResult::fatal;
    }
    page.changed = true;
  }
  auto write = [&](bool rollback) {
    for (uint32_t n = 0; n < plan.count; ++n) {
      const auto& site = plan.sites[n];
      memcpy(image.data() + site.rva, (rollback ? site.stock : site.patch).data(), site.width);
    }
    bool ok = ops.flush(GetCurrentProcess(), liveText.data(), liveText.size()) != FALSE;
    for (uint32_t n = 0; n < plan.count; ++n) {
      const auto& site = plan.sites[n];
      ok &= !memcmp(image.data() + site.rva, (rollback ? site.stock : site.patch).data(), site.width);
    }
    return ok;
  };
  bool written = write(false), protectedAgain = restore();
  if (written && protectedAgain) return ApplyResult::applied;

  reason = "post-write check failed; rolling back all decisions";
  for (auto& page : pages) {
    DWORD ignored;
    if (!ops.protect(reinterpret_cast<void*>(page.address), system.dwPageSize, PAGE_READWRITE, &ignored)) return ApplyResult::fatal;
    page.changed = true;
  }
  bool rolledBack = write(true), restored = restore();
  return rolledBack && restored ? ApplyResult::declined : ApplyResult::fatal;
}
}  // namespace autoscan
