#include "autoscan_runtime.h"
#include "solver.hpp"
#include <cstdio>
#include <cstdlib>
#include <vector>

using Bytes = std::vector<uint8_t>;
using namespace autoscan;
static unsigned checks = 0;
static void check(bool ok, const char* message) {
  ++checks;
  if (!ok) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
static Bytes hex(const char* text) {
  Bytes result;
  auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
  for (; *text; text += 2) result.push_back(static_cast<uint8_t>(digit(text[0]) * 16 + digit(text[1])));
  return result;
}
template<class T> static void put(Bytes& bytes, size_t offset, T value) { std::memcpy(bytes.data() + offset, &value, sizeof value); }
static void replace(Bytes& bytes, const char* before, const char* after) {
  auto a = hex(before), b = hex(after);
  auto at = std::search(bytes.begin(), bytes.end(), a.begin(), a.end());
  check(a.size() == b.size() && at != bytes.end(), "fixture mutation exists and preserves instruction size");
  std::copy(b.begin(), b.end(), at);
}
static Bytes fixture() {
  Bytes bytes(0x2000);
  bool x86 = NativeMachine() == IMAGE_FILE_MACHINE_I386;
  put<uint16_t>(bytes, 0, IMAGE_DOS_SIGNATURE); put<uint32_t>(bytes, 0x3c, 0x80);
  put<uint32_t>(bytes, 0x80, IMAGE_NT_SIGNATURE); put<uint16_t>(bytes, 0x84, NativeMachine());
  put<uint16_t>(bytes, 0x86, 3); put<uint16_t>(bytes, 0x94, x86 ? 0xe0 : 0xf0);
  put<uint16_t>(bytes, 0x98, x86 ? 0x10b : 0x20b);
  if (x86) put<uint32_t>(bytes, 0xb4, 0x400000); else put<uint64_t>(bytes, 0xb0, 0x180000000);
  put<uint32_t>(bytes, 0xd0, 0x5000); put<uint32_t>(bytes, 0xd4, 0x400);
  put<uint32_t>(bytes, x86 ? 0xf4 : 0x104, 16);
  size_t section = x86 ? 0x178 : 0x188;
  for (unsigned n = 0; n < 3; ++n) {
    IMAGE_SECTION_HEADER header{};
    std::memcpy(header.Name, n == 0 ? ".text" : n == 1 ? ".pdata" : ".rdata", n == 0 ? 5 : 6);
    header.Misc.VirtualSize = header.SizeOfRawData = n == 0 ? 0x1000 : n == 1 ? 0x400 : 0x800;
    header.VirtualAddress = n == 0 ? 0x1000 : n == 1 ? 0x3000 : 0x4000;
    header.PointerToRawData = n == 0 ? 0x400 : n == 1 ? 0x1400 : 0x1800;
    header.Characteristics = n == 0 ? 0x60000020 : 0x40000040;
    put(bytes, section + n * sizeof(header), header);
  }
  if (x86) std::fill(bytes.begin() + 0x400, bytes.begin() + 0x1400, 0xcc);
  const std::pair<uint32_t, const char*> functions[] = {
#if defined(AUTOSCAN_X86)
    {0x1000, "c3"},
    {0x1040, "837c2404027f278b44240883f801740a83f803740583f80875148b44240c83f805740b83f80a7406b801000000c331c0c3"},
    {0x1100, "5589e58b4d08837950027f378b916401000080b94c0100000075128b424483f801740a83f803740583f80875168b422883f805740e83f80a7409b8010000005dc2040031c05dc20400"},
    {0x1200, "5589e568804140005dc3"},
    {0x1280, "5589e583ec108b7508f6867c01000008750e894dfc89f1e8a403000084c0740931c083c4105dc208008b550cc70200010000b00183c4105dc20800"},
    {0x1400, "5589e583ec1083b92c010000007407e8ec010000eb16e82502000089c168a0414000e859020000e8140200008d0c24506a00e82902000083c40883c4105dc20400"},
    {0x1500, "5589e583ec28e83501000084c0740e8b442404c7802c010000020000008d44241050e83901000083c40450e8500100008b4c24048d44240850e8c2feffff83c4285dc3"},
    {0x1600, "31c0c3"},
    {0x1640, "b801000000c3"},
    {0x1660, "c3"},
    {0x1680, "c20400"},
#else
    {0x1000, "c0035fd6"},
    {0x1040, "1f0800716d000054e0031f2ac0035fd63f200071a8ffff54482180525f1400710825c11a44184a7ae9079f1a1f01007220119f1ac0035fd6"},
    {0x1100, "285040b91f0900716d000054e0031f2ac0035fd6291441f92a204839285140b90a010037298940b9e0031f2a3f210071e80000544a2180524925c91a890000361f15007104194a7ae0079f1ac0035fd6"},
    {0x1200, "000000f000000691c0035fd6"},
    {0x1280, "ff0301d1e00701a9e80f40f90851493988001837e00301aaea00009480000036e0031f2aff030191c0035fd609208052490000b920008052ff030191c0035fd6"},
    {0x1400, "f30300aa080842b9680000347d000094070000148b000094010000f021800691880000940000001286000094e203002ae0030091e10314aa8a000094c0035fd6"},
    {0x1500, "ff0301d14f00009480000036e80740f949008052090902b9e0830091510000941f2003d5e00740f9e1430091b5ffff97ff030191c0035fd6"},
    {0x1600, "e0031f2ac0035fd6"},
    {0x1640, "20008052c0035fd6"},
    {0x1660, "c0035fd6"},
    {0x1680, "c0035fd6"},
#endif
  };
  unsigned count = 0;
  for (auto [pc, text] : functions) {
    auto code = hex(text); std::copy(code.begin(), code.end(), bytes.begin() + pc - 0x1000 + 0x400);
    if (x86) put<uint32_t>(bytes, 0x1b00 + count++ * 4, pc);
    else if (pc != 0x1040) {
      put<uint32_t>(bytes, 0x1400 + count * 8, pc);
      put<uint32_t>(bytes, 0x1404 + count++ * 8, 1 | static_cast<uint32_t>(code.size() / 4) << 2);
    }
  }
  if (x86) {
    IMAGE_LOAD_CONFIG_DIRECTORY32 config{}; config.Size = sizeof config;
    config.GuardCFFunctionTable = 0x404300; config.GuardCFFunctionCount = count;
    put(bytes, 0x1a00, config); put<uint32_t>(bytes, 0x148, 0x4200); put<uint32_t>(bytes, 0x14c, sizeof config);
  } else { put<uint32_t>(bytes, 0x120, 0x3000); put<uint32_t>(bytes, 0x124, count * 8); }
  put<uintptr_t>(bytes, 0x1800, static_cast<uintptr_t>((x86 ? 0x400000ull : 0x180000000ull) + 0x1200));
  put<uintptr_t>(bytes, 0x1800 + sizeof(uintptr_t), static_cast<uintptr_t>((x86 ? 0x400000ull : 0x180000000ull) + 0x1280));
  std::memcpy(bytes.data() + 0x1980, "InstallVerifier", 16);
  std::memcpy(bytes.data() + 0x19a0, "apps-gallery-url", 17);
  return bytes;
}
static bool has(const Report& report, OptionalGate kind) {
  return std::any_of(report.gates.begin(), report.gates.end(), [&](const auto& g) { return g.optional == kind; });
}
#if defined(AUTOSCAN_ARM64)
static void compareFilter() {
  auto bytes = fixture(); unsigned count = 0, expected = 0;
  auto add = [&](uint32_t word) {
    size_t at = 0x400 + count * 16;
    put(bytes, at, word); put<uint32_t>(bytes, at + 4, 0x5400004c);
    put<uint32_t>(bytes, at + 8, 0xd65f03c0); put<uint32_t>(bytes, at + 12, 0xd503201f);
    auto insn = LiftArm64({bytes.data() + at, 4}, 0x1000 + count * 16);
    expected += insn.op == Op::CmpImm && (insn.imm == 2 || insn.imm == 3);
    if (++count == 256) {
      check(Analyze(bytes).heads == expected, "ARM64 raw compare filter matches complete decoding");
      count = expected = 0;
    }
  };
  for (uint32_t opcode : {0x11u, 0x31u, 0x51u, 0x71u, 0x91u, 0xb1u, 0xd1u, 0xf1u, 0x70u, 0x72u})
    for (uint32_t shift : {0u, 1u}) for (uint32_t imm : {0u, 1u, 2u, 3u, 4u, 4095u})
      for (uint32_t source : {0u, 1u, 30u, 31u}) for (uint32_t dest : {0u, 30u, 31u})
        add((opcode << 24) | (shift << 22) | (imm << 10) | (source << 5) | dest);
  for (unsigned bit = 0; bit < 32; ++bit) add(0x7100083f ^ (1u << bit));
  uint32_t random = 1;
  for (unsigned n = 0; n < 4096; ++n) { random = random * 1664525u + 1013904223u; add(random); }
  while (count) add(0xd503201f);
}
#endif
static unsigned flushes = 0;
static BOOL WINAPI failFirstFlush(HANDLE process, LPCVOID address, SIZE_T size) {
  return ++flushes == 1 ? FALSE : FlushInstructionCache(process, address, size);
}
static void application(const Bytes& bytes) {
  auto plan = MakePlan(Discover(bytes)); check(!plan.status && plan.count == 4, "native plan includes both optional gates automatically");
  auto memory = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x5000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  check(memory != nullptr, "allocate isolated application fixture");
  std::memcpy(memory, bytes.data(), 0x400); std::memcpy(memory + 0x1000, bytes.data() + 0x400, 0x1000);
  DWORD previous = 0; check(VirtualProtect(memory, 0x5000, PAGE_EXECUTE_READ, &previous) != 0, "protect isolated fixture");
  StockImage stock(bytes); std::string_view reason;
  auto apply = [&](const WirePlan& candidate, MemoryOps ops = {}) { return ApplyPlan({memory, 0x5000}, stock, candidate, reason, ops); };
  auto unchanged = [&] { return !std::memcmp(memory + 0x1000, bytes.data() + 0x400, 0x1000); };
  auto wrong = plan; std::swap(wrong.offstoreRva, wrong.crxDownloadRva);
  check(apply(wrong) == ApplyResult::declined && unchanged(), "swapped optional metadata cannot modify code");
  flushes = 0;
  check(apply(plan, {VirtualProtect, failFirstFlush}) == ApplyResult::declined && unchanged(), "failure rolls core and optional edits back together");
  check(apply(plan) == ApplyResult::applied, "verified native branches apply");
  for (const auto& gate : Discover(bytes).gates)
    check(!std::memcmp(memory + gate.rva, gate.patch.data(), gate.width), "every selected branch contains its verified patch");
  check(apply(plan) == ApplyResult::alreadyApplied, "native optional application is idempotent");
  MEMORY_BASIC_INFORMATION info{}; VirtualQuery(memory + 0x1000, &info, sizeof info);
  check(info.Protect == PAGE_EXECUTE_READ, "application restores execute/read protection");
  VirtualFree(memory, 0, MEM_RELEASE);
}
int main() {
  auto bytes = fixture(); auto report = Discover(bytes);
  if (!report.ready() || !has(report, InstallVerifier) || !has(report, CrxDownload))
    std::fprintf(stderr, "ready=%u gates=%zu error=%.*s provider=%.*s download=%.*s\n", report.ready(), report.gates.size(),
      static_cast<int>(report.error.size()), report.error.data(), static_cast<int>(report.installVerifier.size()), report.installVerifier.data(),
      static_cast<int>(report.crxDownload.size()), report.crxDownload.data());
  check(report.ready() && report.gates.size() == 4 && has(report, InstallVerifier) && has(report, CrxDownload), "native discovery recognizes both optional gates");
  for (unsigned test = 0; test < 8; ++test) {
    auto changed = bytes;
    if (test == 0) changed[0x1980] = 'X';
    if (test == 1) changed[0x19a0] = 'X';
#if defined(AUTOSCAN_X86)
    if (test == 2) replace(changed, "f6867c01000008", "f6867c01000010");
    if (test == 3) replace(changed, "84c0740e8b442404", "84c0750e8b442404");
    if (test == 4) replace(changed, "8b4c24048d442408", "8b4c24088d442408");
    if (test == 5) replace(changed, "8d442410", "89442404");
    if (test == 6) replace(changed, "83c40450", "83c40850");
    if (test == 7) replace(changed, "8b7508", "8b750c");
#else
    if (test == 2) replace(changed, "88001837", "88002037");
    if (test == 3) replace(changed, "80000036e80740f9", "80000037e80740f9");
    if (test == 4) replace(changed, "e00740f9e1430091", "e00b40f9e1430091");
    if (test == 5) replace(changed, "1f2003d5", "e00700f9");
    if (test == 6) replace(changed, "1f2003d5", "ff4300d1");
    if (test == 7) replace(changed, "e00701a9", "e00b01a9");
#endif
    auto found = Discover(changed);
    bool provider = test != 0 && test != 2 && test != 7;
    check(found.ready() && has(found, InstallVerifier) == provider && has(found, CrxDownload) != provider,
          "wrong source, polarity, slot or frame leaves core and the independent optional gate usable");
  }
#if defined(AUTOSCAN_ARM64)
  compareFilter();
  for (auto mutation : {std::pair{"48218052", "68218052"}, {"44184a7a", "40184a7a"}, {"20119f1a", "20019f1a"}}) {
    auto changed = bytes; replace(changed, mutation.first, mutation.second);
    check(!Discover(changed).ready(), "changed membership, conditional flags or select cannot satisfy the MV2 predicate");
  }
#endif
  application(bytes);
  std::printf("PASS: %u native optional checks\n", checks);
}
