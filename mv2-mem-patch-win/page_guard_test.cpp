#include "autoscan_runtime.h"
#include <psapi.h>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>

namespace {
enum class BatchMode { native, fail, invalidLast, wrongProtection };
BatchMode batchMode = BatchMode::native;
bool failPageQuery = false;
unsigned checks = 0, batchCalls = 0, batchEntries = 0, fallbackCalls = 0, protectCalls = 0;
void check(bool ok, const char* message, std::string_view reason = {}) {
  ++checks;
  if (!ok) {
    std::fprintf(stderr, "FAIL %u: %s; %.*s; Windows error %lu\n", checks, message,
                 static_cast<int>(reason.size()), reason.data(), GetLastError());
    std::exit(1);
  }
}
BOOL WINAPI testBatch(HANDLE process, PVOID buffer, DWORD size) {
  ++batchCalls;
  batchEntries = size / sizeof(PSAPI_WORKING_SET_EX_INFORMATION);
  check(size % sizeof(PSAPI_WORKING_SET_EX_INFORMATION) == 0 && batchEntries && batchEntries <= 128,
        "protection batch has bounded complete entries");
  if (batchMode == BatchMode::fail) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
  BOOL ok = K32QueryWorkingSetEx(process, buffer, size);
  if (ok) {
    auto* entries = static_cast<PSAPI_WORKING_SET_EX_INFORMATION*>(buffer);
    auto& last = entries[batchEntries - 1].VirtualAttributes;
    if (batchMode == BatchMode::invalidLast) { last.Flags = 0; last.Win32Protection = PAGE_NOACCESS; }
    if (batchMode == BatchMode::wrongProtection) { last.Valid = 1; last.Win32Protection = PAGE_READONLY; }
  }
  return ok;
}
SIZE_T WINAPI testQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION info, SIZE_T size) {
  if (batchCalls) {
    ++fallbackCalls;
    if (failPageQuery) { SetLastError(ERROR_INVALID_ADDRESS); return 0; }
  }
  return VirtualQuery(address, info, size);
}
BOOL WINAPI testProtect(LPVOID address, SIZE_T size, DWORD protection, PDWORD old) {
  ++protectCalls;
  return VirtualProtect(address, size, protection, old);
}
}
// Exercise the production guard without adding failure controls to the shipped API.
#define K32QueryWorkingSetEx testBatch
#define VirtualQuery testQuery
#include "autoscan_apply.cpp"
#undef K32QueryWorkingSetEx
#undef VirtualQuery

namespace {
#pragma section(".text$guard", read, execute)
__declspec(allocate(".text$guard")) __declspec(align(4096)) uint8_t cowPage[4096]{};
template<class T, size_t N> void put(std::array<uint8_t, N>& bytes, size_t at, T value) {
  std::memcpy(bytes.data() + at, &value, sizeof(value));
}
struct Fixture {
  std::array<uint8_t, 0x4000> disk{};
  autoscan::WirePlan plan{};
  std::string_view reason{};
  uint8_t* live = nullptr;
  explicit Fixture(bool straddle = false) {
    bool x86 = autoscan::NativeMachine() == IMAGE_FILE_MACHINE_I386;
    put<uint16_t>(disk, 0, IMAGE_DOS_SIGNATURE); put<uint32_t>(disk, 0x3c, 0x80);
    put<uint32_t>(disk, 0x80, IMAGE_NT_SIGNATURE); put<uint16_t>(disk, 0x84, autoscan::NativeMachine());
    put<uint16_t>(disk, 0x86, 1); put<uint16_t>(disk, 0x94, x86 ? 0xe0 : 0xf0);
    put<uint16_t>(disk, 0x98, x86 ? 0x10b : 0x20b);
    put<uint32_t>(disk, 0xd0, 0x4000); put<uint32_t>(disk, 0xd4, 0x400);
    put<uint32_t>(disk, x86 ? 0xf4 : 0x104, 16);
    IMAGE_SECTION_HEADER text{};
    std::memcpy(text.Name, ".text", 5);
    text.Misc.VirtualSize = text.SizeOfRawData = 0x2000;
    text.VirtualAddress = text.PointerToRawData = 0x1000;
    text.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;
    put(disk, x86 ? 0x178 : 0x188, text);
    plan.status = 0; plan.count = 2;
    for (unsigned n = 0; n < plan.count; ++n) {
      auto& site = plan.sites[n]; site.rva = n ? 0x2040 : 0x1040;
#if defined(AUTOSCAN_ARM64)
      site.width = 4;
      put<uint32_t>(site.stock, 0, 0x5400004c); put<uint32_t>(site.patch, 0, 0x5400004e);
#else
      site.width = 2; site.stock = {0x7f, 8}; site.patch = {0xeb, 8};
      if (straddle && !n) {
        site.rva = 0x1ffd; site.width = 6;
        site.stock = {0x0f, 0x8f, 8, 0, 0, 0}; site.patch = {0x90, 0xe9, 8, 0, 0, 0};
      }
#endif
      std::memcpy(disk.data() + site.rva, site.stock.data(), site.width);
    }
    plan.blake3 = autoscan::Blake3(disk);
    live = static_cast<uint8_t*>(VirtualAlloc(nullptr, disk.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    check(live != nullptr, "allocate application fixture");
    std::memcpy(live, disk.data(), disk.size());
    DWORD old = 0;
    check(VirtualProtect(live, disk.size(), PAGE_EXECUTE_READ, &old) != FALSE, "make fixture execute/read");
  }
  ~Fixture() { if (live) VirtualFree(live, 0, MEM_RELEASE); }
  autoscan::ApplyResult apply(BatchMode mode = BatchMode::native, bool queryFailure = false) {
    batchMode = mode; failPageQuery = queryFailure;
    batchCalls = batchEntries = fallbackCalls = protectCalls = 0;
    reason = {};
    return autoscan::ApplyPlan({live, disk.size()}, autoscan::StockImage(disk), plan, reason,
                              {testProtect, FlushInstructionCache});
  }
  bool bytesMatch(bool patched) const {
    for (unsigned n = 0; n < plan.count; ++n) {
      const auto& site = plan.sites[n];
      if (std::memcmp(live + site.rva, (patched ? site.patch : site.stock).data(), site.width)) return false;
    }
    return true;
  }
  bool protectedAgain() const {
    for (unsigned n = 0; n < plan.count; ++n) {
      MEMORY_BASIC_INFORMATION info{};
      if (!VirtualQuery(live + plan.sites[n].rva, &info, sizeof(info)) || info.Protect != PAGE_EXECUTE_READ) return false;
    }
    return true;
  }
  void writableLastPage() {
    DWORD old = 0;
    check(VirtualProtect(live + 0x2000, 0x1000, PAGE_READWRITE, &old) != FALSE, "prepare non-RX decision page");
  }
  void privateFirstPage() {
    DWORD old = 0;
    check(VirtualProtect(live + 0x1000, 0x1000, PAGE_READWRITE, &old) != FALSE, "prepare private-page store");
    auto byte = reinterpret_cast<volatile uint8_t*>(live + plan.sites[0].rva);
    uint8_t stock = *byte; *byte = stock;
    check(VirtualProtect(live + 0x1000, 0x1000, PAGE_EXECUTE_READ, &old) != FALSE, "restore private execute/read page");
    PSAPI_WORKING_SET_EX_INFORMATION info{}; info.VirtualAddress = live + plan.sites[0].rva;
    check(K32QueryWorkingSetEx(GetCurrentProcess(), &info, sizeof(info)) && info.VirtualAttributes.Valid &&
          !info.VirtualAttributes.Shared && info.VirtualAttributes.Win32Protection == PAGE_EXECUTE_READ,
          "private allocated page retains exact execute/read protection");
  }
};
void imageCopyOnWrite() {
  MEMORY_BASIC_INFORMATION memory{};
  check(!(reinterpret_cast<uintptr_t>(cowPage) & 0xfff) &&
        VirtualQuery(cowPage, &memory, sizeof(memory)) && memory.Type == MEM_IMAGE && memory.Protect == PAGE_EXECUTE_READ,
        "dedicated image data page is aligned execute/read");
  DWORD old = 0;
  check(VirtualProtect(cowPage, sizeof(cowPage), PAGE_READWRITE, &old) != FALSE, "make nonexecuted image page writable");
  auto byte = reinterpret_cast<volatile uint8_t*>(cowPage); uint8_t stock = *byte; *byte = stock;
  check(VirtualProtect(cowPage, sizeof(cowPage), PAGE_EXECUTE_READ, &old) != FALSE, "restore image page execute/read");
  PSAPI_WORKING_SET_EX_INFORMATION info{}; info.VirtualAddress = cowPage;
  check(K32QueryWorkingSetEx(GetCurrentProcess(), &info, sizeof(info)) && info.VirtualAttributes.Valid &&
        !info.VirtualAttributes.Shared && info.VirtualAttributes.Win32Protection == PAGE_EXECUTE_READ &&
        VirtualQuery(cowPage, &memory, sizeof(memory)) && memory.Protect == PAGE_EXECUTE_READ,
        "real image copy-on-write preserves equivalent per-page and region RX protection");
}
}

int main() {
  using Result = autoscan::ApplyResult;
  for (BatchMode mode : {BatchMode::native, BatchMode::fail, BatchMode::invalidLast, BatchMode::wrongProtection}) {
    Fixture fixture;
    check(fixture.apply(mode) == Result::applied && fixture.bytesMatch(true) && fixture.protectedAgain(),
          "native protection query and every fallback preserve application", fixture.reason);
    check(batchCalls == 1 && batchEntries == 2, "one bounded batch covers both decision pages");
    check(fallbackCalls == (mode == BatchMode::native ? 0u : mode == BatchMode::fail ? 2u : 1u),
          "only a complete valid RX result bypasses the original page query");
    check(fixture.apply() == Result::alreadyApplied && !batchCalls && !protectCalls,
          "complete already-applied state remains idempotent");
  }
  for (BatchMode mode : {BatchMode::native, BatchMode::fail, BatchMode::invalidLast}) {
    Fixture fixture; fixture.writableLastPage();
    check(fixture.apply(mode) == Result::declined && !protectCalls && fixture.bytesMatch(false),
          "non-RX page declines before any decision write on every query path");
    check(fallbackCalls == (mode == BatchMode::fail ? 2u : 1u), "non-RX or invalid page uses original protection check");
  }
  {
    Fixture fixture;
    check(fixture.apply(BatchMode::fail, true) == Result::declined && !protectCalls && fixture.bytesMatch(false),
          "failed fallback query declines without changing decisions");
  }
  {
    imageCopyOnWrite();
    Fixture fixture; fixture.privateFirstPage();
    check(fixture.apply() == Result::applied && fixture.bytesMatch(true) && fixture.protectedAgain() && !fallbackCalls,
          "private RX pages pass without treating Shared as content or protection evidence", fixture.reason);
  }
#if !defined(AUTOSCAN_ARM64)
  for (bool writable : {false, true}) {
    Fixture fixture(true); if (writable) fixture.writableLastPage();
    check(fixture.apply() == (writable ? Result::declined : Result::applied) && fixture.bytesMatch(!writable),
          "straddled near decision verifies both pages before writing");
    check(batchEntries == 2 && fallbackCalls == (writable ? 1u : 0u), "straddled site shares its second page with the next decision");
    if (writable) check(!protectCalls, "straddled RW page declines before protection changes");
  }
#endif
  std::printf("PASS: %u page-protection, fallback, copy-on-write and boundary checks\n", checks);
  return 0;
}
