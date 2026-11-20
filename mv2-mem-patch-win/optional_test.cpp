// Test-only made-up x86/ARM64 browser code checks recognition of extension-source restrictions.
// Patch and failure checks change only this test's allocated memory and then release it.
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
static void application(const Bytes& bytes, unsigned expectedCount = 4) {
  auto plan = MakePlan(Discover(bytes)); check(!plan.status && plan.count == expectedCount, "native plan includes both optional gates automatically");
  auto memory = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x5000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  check(memory != nullptr, "allocate isolated application fixture");
  PeImage pe(bytes); auto text = pe.at(pe.text.rva, pe.text.size);
  check(!text.empty() && pe.text.rva + text.size() <= 0x5000, "fixture code fits its allocated image");
  std::memcpy(memory, bytes.data(), 0x400); std::memcpy(memory + pe.text.rva, text.data(), text.size());
  DWORD previous = 0; check(VirtualProtect(memory, 0x5000, PAGE_EXECUTE_READ, &previous) != 0, "protect isolated fixture");
  StockImage stock(bytes); std::string_view reason;
  auto apply = [&](const WirePlan& candidate, MemoryOps ops = {}) { return ApplyPlan({memory, 0x5000}, stock, candidate, reason, ops); };
  auto unchanged = [&] { return !std::memcmp(memory + pe.text.rva, text.data(), text.size()); };
  auto wrong = plan;
  if (!pe.isEdge()) {
    std::swap(wrong.offstoreRva, wrong.crxDownloadRva);
    check(apply(wrong) == ApplyResult::declined && unchanged(), "swapped optional metadata cannot modify code");
  }
  wrong = plan; wrong.offstoreRva = wrong.crxDownloadRva;
  check(apply(wrong) == ApplyResult::declined && unchanged(), "overlapping optional metadata cannot modify code");
#if defined(AUTOSCAN_ARM64)
  wrong = plan;
  for (unsigned n = 0; n < wrong.count; ++n) if (wrong.sites[n].rva == wrong.offstoreRva) {
    auto& site = wrong.sites[n]; auto jump = Lift(pe.code(site.rva), site.rva);
    uint32_t opposite = ReadInsn<uint32_t>(site.patch.data()) == 0xd503201f ?
      0x14000000 | ((static_cast<int64_t>(jump.target()) - site.rva) / 4 & 0x03ffffff) : 0xd503201f;
    std::memcpy(site.patch.data(), &opposite, sizeof opposite);
  }
  check(apply(wrong) == ApplyResult::declined && unchanged(), "reversed ARM64 source outcome cannot modify code");
#endif
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
#if defined(AUTOSCAN_ARM64)
static void edgeProviderResult() {
  for (bool nonzero : {false, true}) {
    auto bytes = fixture();
    IMAGE_EXPORT_DIRECTORY exports{}; exports.Name = 0x4480;
    put(bytes, 0x1c00, exports); std::memcpy(bytes.data() + 0x1c80, "msedge.dll", sizeof("msedge.dll"));
    put<uint32_t>(bytes, 0x108, 0x4400); put<uint32_t>(bytes, 0x10c, sizeof exports);
    // The provider tests its private helper result; its shared source classifier stays intact.
    const uint32_t provider[] = {
      0xa9bf7bf3, 0xaa0203f3, 0xaa0103e0, 0x9400011d,
      nonzero ? 0x370000c0u : 0x36000080u,
      nonzero ? 0x52802008u : 0x2a1f03e0u,
      nonzero ? 0xb9000268u : 0xa8c17bf3u,
      nonzero ? 0x52800020u : 0xd65f03c0u,
      nonzero ? 0xa8c17bf3u : 0x52802008u,
      nonzero ? 0xd65f03c0u : 0xb9000268u,
      nonzero ? 0x2a1f03e0u : 0x52800020u,
      0xa8c17bf3, 0xd65f03c0,
    };
    const uint32_t helper[] = {0x39495008, 0x37180068, 0x2a1f03e0, 0xd65f03c0, 0x52800020, 0xd65f03c0};
    std::fill(bytes.begin() + 0x680, bytes.begin() + 0x800, 0);
    std::memcpy(bytes.data() + 0x680, provider, sizeof provider);
    std::memcpy(bytes.data() + 0xb00, helper, sizeof helper);
    put<uint32_t>(bytes, 0x141c, 1 | (sizeof provider / 4) << 2);
    uint32_t count = ReadInsn<uint32_t>(bytes.data() + 0x124) / 8;
    put<uint32_t>(bytes, 0x1400 + count * 8, 0x1700);
    put<uint32_t>(bytes, 0x1404 + count * 8, 1 | (sizeof helper / 4) << 2);
    put<uint32_t>(bytes, 0x124, (count + 1) * 8);
    auto report = Discover(bytes); auto plan = MakePlan(report);
    check(report.ready() && plan.count == 2 && plan.offstoreRva == 0x1290 && plan.crxDownloadRva == 0x1508,
          "Edge recognizes both installer decisions through its private ARM64 provider result");
    auto source = std::find_if(report.gates.begin(), report.gates.end(), [](const auto& gate) { return gate.optional == InstallVerifier; });
    check(source != report.gates.end() && ReadInsn<uint32_t>(source->patch.data()) == (nonzero ? 0x14000006 : 0xd503201f) &&
          source->unaffected == (nonzero ? 0x12a8u : 0x1294u),
          "TBZ selects the verified fall-through with NOP and TBNZ selects its original target with B");
    application(bytes, 2);
  }
}
static void unsupportedBitField() {
  auto bytes = fixture();
  auto predicate = hex("1f0800716d000054e0031f2ac0035fd63f200071a8ffff54482180525f1400710825c11a44184a7ae9079f1a1f01007220119f1ac0035fd6");
  put<uint32_t>(bytes, 0xc00, 0x53072800); // UBFX W0,W0,#7,#4: a packed tag, not an integer manifest version.
  put<uint32_t>(bytes, 0xc04, 0xaa0403fb); // An unrelated register move can be interleaved.
  std::copy(predicate.begin(), predicate.end(), bytes.begin() + 0xc08);
  uint32_t count = ReadInsn<uint32_t>(bytes.data() + 0x124) / 8;
  put<uint32_t>(bytes, 0x1400 + count * 8, 0x1800);
  put<uint32_t>(bytes, 0x1404 + count * 8, 1 | (static_cast<uint32_t>(predicate.size() / 4) + 2) << 2);
  put<uint32_t>(bytes, 0x124, (count + 1) * 8);
  auto report = Discover(bytes);
  check(!report.ready() && !report.unresolved.empty(),
        "a generic packed input remains unsupported without reviewed AST provenance");
  put<uint32_t>(bytes, 0xc00, 0xd503201f);
  report = Discover(bytes);
  check(report.ready() && report.gates.size() == 5,
        "the same predicate on an unmodified full-width integer remains recognized");
  for (uint32_t word : {0x53007c00u, 0x533f2800u}) {
    put<uint32_t>(bytes, 0xc00, word);
    report = Discover(bytes);
    check(!report.ready() && !report.unresolved.empty(),
          "full-width or invalid bitfield encodings retain rejection of an unsupported candidate");
  }
  put<uint32_t>(bytes, 0xc00, 0x53072800);
  for (uint32_t word : {0x97ffff7fu, 0x14000001u, 0x34000020u, 0xd65f03c0u, 0xd4200000u, 0xffffffffu}) {
    put<uint32_t>(bytes, 0xc04, word);
    report = Discover(bytes);
    check(!report.ready() && !report.unresolved.empty(),
          "calls, control flow and unknown writes cannot prove the packed comparison input");
  }
  put<uint32_t>(bytes, 0xc00, 0x14000002);
  put<uint32_t>(bytes, 0xc04, 0x53072800);
  report = Discover(bytes);
  check(report.ready() && report.gates.size() == 5,
        "a branch bypassing a packed extraction preserves a genuine full-width predicate");
  put<uint32_t>(bytes, 0xc00, 0x53072800);
  put<uint32_t>(bytes, 0xc04, 0xaa0403fb);
  put<uint32_t>(bytes, 0x1400 + count * 8, 0x1808);
  put<uint32_t>(bytes, 0x1404 + count * 8, 1 | static_cast<uint32_t>(predicate.size() / 4) << 2);
  report = Discover(bytes);
  check(report.ready() && report.gates.size() == 5,
        "an earlier function's extraction cannot hide a full-width predicate entry");
}
static Bytes astFixture() {
  auto bytes = fixture();
  auto instruction = [&](uint32_t pc, uint32_t word) { put<uint32_t>(bytes, pc - 0x1000 + 0x400, word); };
  auto conditional = [](uint32_t pc, uint32_t target, unsigned condition) {
    return 0x54000000u | ((static_cast<uint32_t>((int64_t{target} - pc) / 4) & 0x7ffff) << 5) | condition;
  };
  auto branch = [](uint32_t pc, uint32_t target) {
    return 0x14000000u | (static_cast<uint32_t>((int64_t{target} - pc) / 4) & 0x3ffffff);
  };
  const uint32_t dispatch[] = {
    0xf0000014, 0x91140294, 0xb9400497, 0x120016e8, 0x7100ed1f,
    conditional(0x1814, 0x19e0, 8), 0x924016e8, 0x10000009,
    0xb8a87a8a, 0x8b0a0129, 0xd61f0120,
  };
  for (unsigned n = 0; n < std::size(dispatch); ++n) instruction(0x1800 + n * 4, dispatch[n]);
  instruction(0x183c, branch(0x183c, 0x19e0));
  const uint32_t loop[] = {0xaa0103e4, 0x36000040, 0xd503201f, 0x97ffff6d,
                          0xd503201f, 0xf9400484, 0x7100001f, conditional(0x185c, 0x1808, 2), 0xd65f03c0};
  for (unsigned n = 0; n < std::size(loop); ++n) instruction(0x1840 + n * 4, loop[n]);
  const uint32_t origin[] = {0xf9400482, 0xb940044f, 0x120015e8, 0x7100b51f,
                            conditional(0x1890, 0x1900, 0), 0xd65f03c0};
  for (unsigned n = 0; n < std::size(origin); ++n) instruction(0x1880 + n * 4, origin[n]);
  instruction(0x18fc, branch(0x18fc, 0x19e0));
  instruction(0x1900, 0x530729e0); instruction(0x1904, 0xaa0403fb);
  auto predicate = hex("1f0800716d000054e0031f2ac0035fd63f200071a8ffff54482180525f1400710825c11a44184a7ae9079f1a1f01007220119f1ac0035fd6");
  std::copy(predicate.begin(), predicate.end(), bytes.begin() + 0xd08);
  instruction(0x19e0, 0xd65f03c0);
  for (unsigned n = 0; n < 60; ++n)
    put<int32_t>(bytes, 0x1d00 + n * 4, (n == 11 || n == 49 ? 0x1840 : 0x1880) - 0x181c);
  uint32_t count = ReadInsn<uint32_t>(bytes.data() + 0x124) / 8;
  put<uint32_t>(bytes, 0x1400 + count * 8, 0x1800);
  put<uint32_t>(bytes, 0x1404 + count * 8, 1 | ((0x19e4 - 0x1800) / 4) << 2);
  put<uint32_t>(bytes, 0x124, (count + 1) * 8);
  return bytes;
}
static void astExclusion() {
  auto bytes = astFixture(); auto report = Discover(bytes);
  if (!report.ready()) std::fprintf(stderr, "AST fixture: error=%.*s unresolved=%zu gates=%zu\n",
    static_cast<int>(report.error.size()), report.error.data(), report.unresolved.size(), report.gates.size());
  check(report.ready() && report.gates.size() == 4 && report.unresolved.empty(),
        "reviewed AST literal origin and preserving dispatch loop cannot masquerade as MV2");
  for (auto [at, word] : {
    std::pair<size_t, uint32_t>{0xc10, 0x7100f11f}, // Incorrect dispatch bound.
    {0xc18, 0x92401ae8},                        // Incorrect dispatch mask.
    {0xc48, 0xaa0403f4},                        // X20 is overwritten in the loop.
    {0xc48, 0x11000694},                        // A W20 write also destroys X20.
    {0xc48, 0xffffffff},                        // Unknown loop effects.
    {0xc3c, 0xd503201f},                        // An unproven fall-through enters the loop.
    {0xc5c, 0x54fffda2},                        // Reentry skips the complete tag load.
    {0xc8c, 0x7100b91f},                        // Non-literal node type.
    {0xc88, 0x120015ef},                        // The guard overwrites the packed flags.
    {0xc80, 0xd503201f},                        // No AST node pointer origin.
    {0xcfc, 0xd503201f},                        // An unproven fall-through enters the extraction.
    {0xd00, 0x530009e0},                        // An identity-on-valid-versions extraction.
    {0xde0, 0xd65f0120},                        // RET X9 is not a proved ABI return.
    {0xdd0, 0xd61f0120},                        // A second indirect branch.
    {0x1d00, 0x1908 - 0x181c},                 // An indirect entry skips the extraction.
    {0x1d00, 0x1884 - 0x181c},                 // An indirect entry skips the origin.
    {0x1d00, 0x1848 - 0x181c},                 // An indirect entry skips part of the loop.
    {0x1d00, 0x7fffffff},                       // Target outside the owned function.
    {0x1d00, 0x80000000},                       // Signed target underflow.
    {0x1fc, 0xc0000040},                        // Writable table section.
    {0x1fc, 0x00000040},                        // Unreadable table section.
  }) {
    auto changed = bytes; put<uint32_t>(changed, at, word);
    auto declined = Discover(changed);
    check(!declined.ready() && !declined.unresolved.empty(), "unproven AST data or control flow keeps the candidate unresolved");
  }
  for (uint32_t target : {0x1900u, 0x1908u, 0x1884u, 0x1848u, 0x1810u}) {
    auto changed = bytes;
    put<uint32_t>(changed, 0xb00, 0x14000000 | (static_cast<uint32_t>((int64_t{target} - 0x1700) / 4) & 0x3ffffff));
    auto declined = Discover(changed);
    check(!declined.ready() && !declined.unresolved.empty(), "outside direct entries cannot bypass the AST proof");
  }
  for (uint32_t opcode : {0x5400000eu, 0x54000010u}) {
    auto changed = bytes;
    put<uint32_t>(changed, 0xb00, opcode | (((0x1908 - 0x1700) / 4) << 5));
    check(!Discover(changed).ready(), "always-taken and newer conditional branches cannot bypass the AST proof");
  }
  auto relocated = bytes;
  put<uint32_t>(relocated, 0x130, 0x4700); put<uint32_t>(relocated, 0x134, 12);
  put<uint32_t>(relocated, 0x1f00, 0x4000); put<uint32_t>(relocated, 0x1f04, 12);
  put<uint16_t>(relocated, 0x1f08, 0xa500);
  check(!Discover(relocated).ready(), "loader relocations cannot alter authenticated switch data");
  put<uint32_t>(relocated, 0x1f04, 11);
  check(!Discover(relocated).ready(), "malformed loader relocation blocks preserve rejection");
  for (uint16_t entry : {uint16_t{0x3700}, uint16_t{0x383c}, uint16_t{0x38fc}}) {
    relocated = bytes;
    put<uint32_t>(relocated, 0x130, 0x4700); put<uint32_t>(relocated, 0x134, 12);
    put<uint32_t>(relocated, 0x1f00, 0x1000); put<uint32_t>(relocated, 0x1f04, 12);
    put<uint16_t>(relocated, 0x1f08, entry);
    check(!Discover(relocated).ready(), "executable relocations cannot change outside entries or preceding terminators");
  }
  auto otherCode = bytes;
  put<uint32_t>(otherCode, 0x1fc, 0x60000040);
  put<uint32_t>(otherCode, 0x1e00, 0x14000000 | (static_cast<uint32_t>((int64_t{0x1908} - 0x4600) / 4) & 0x3ffffff));
  check(!Discover(otherCode).ready(), "entries from another executable section cannot bypass the AST proof");
  auto padding = bytes;
  put<uint32_t>(padding, 0x190, 0xfff);
  put<uint32_t>(padding, 0x13fc, 0x14000000 | (static_cast<uint32_t>((int64_t{0x1908} - 0x1ffc) / 4) & 0x3ffffff));
  check(!Discover(padding).ready(), "backed executable padding cannot bypass the AST proof");
}

#endif
#if defined(AUTOSCAN_X86)
static Bytes downloadCalleeFixture(size_t nops, const char* tail) {
  auto bytes = fixture();
  // Keep the original RVAs and grow the raw .text area before the two data
  // sections, so the final CFG-listed helper can contain a larger body.
  bytes.insert(bytes.begin() + 0x1400, 0x1000, 0xcc);
  for (unsigned n = 0; n < 3; ++n) {
    IMAGE_SECTION_HEADER header{};
    std::memcpy(&header, bytes.data() + 0x178 + n * sizeof(header), sizeof(header));
    if (!n) header.Misc.VirtualSize = header.SizeOfRawData = 0x2000;
    else header.PointerToRawData += 0x1000;
    put(bytes, 0x178 + n * sizeof(header), header);
  }
  auto ending = hex(tail);
  check(0xa80 + nops + ending.size() < 0x2400, "large callee stays in the fabricated code section");
  std::fill(bytes.begin() + 0xa80, bytes.begin() + 0x2400, 0xcc);
  std::fill_n(bytes.begin() + 0xa80, nops, 0x90);
  std::copy(ending.begin(), ending.end(), bytes.begin() + 0xa80 + nops);
  return bytes;
}
static void largeDownloadCallee() {
  auto control = Discover(downloadCalleeFixture(0, "c20400"));
  check(control.ready() && control.gates.size() == 4 && has(control, CrxDownload),
        "expanded fixture keeps its known installer and helper cleanup");
  auto bytes = downloadCalleeFixture(2600, "c20400");
  auto report = Discover(bytes);
  check(report.ready() && report.gates.size() == 4 && has(report, InstallVerifier) && has(report, CrxDownload),
        "a larger returning helper can still prove the unchanged download slot");
  for (auto tail : {"85c07503c20400c20800", "c20800"}) {
    auto refused = Discover(downloadCalleeFixture(2600, tail));
    check(refused.ready() && refused.gates.size() == 3 && has(refused, InstallVerifier) && !has(refused, CrxDownload),
          "larger helpers with conflicting returns or changed stack cleanup remain rejected");
  }
  auto excessive = Discover(downloadCalleeFixture(4300, "c20400"));
  check(excessive.ready() && excessive.gates.size() == 3 && has(excessive, InstallVerifier) && !has(excessive, CrxDownload),
        "callee analysis still declines when the bounded instruction budget is exhausted");
  application(bytes);
}
static Bytes downloadArithmeticFixture(const char* arithmetic) {
  auto bytes = fixture();
  auto code = hex("5589e583ec28e83501000084c0740e8b442404c7802c01000002000000"
                  "8d44241050e83901000083c40450e850010000");
  for (auto part : {arithmetic, "8b4c24048d44240850"}) {
    auto instructions = hex(part); code.insert(code.end(), instructions.begin(), instructions.end());
  }
  uint32_t relative = 0x1400 - (0x1500 + static_cast<uint32_t>(code.size()) + 5);
  code.push_back(0xe8);
  for (unsigned byte = 0; byte < 4; ++byte) code.push_back(static_cast<uint8_t>(relative >> (byte * 8)));
  auto tail = hex("83c4285dc3"); code.insert(code.end(), tail.begin(), tail.end());
  check(code.size() <= 0x100, "arithmetic caller stays within its fixture entry");
  std::fill(bytes.begin() + 0x900, bytes.begin() + 0xa00, 0xcc);
  std::copy(code.begin(), code.end(), bytes.begin() + 0x900);
  return bytes;
}
static void downloadArithmetic() {
  // Model unrelated register SUB/SHL/SAR between helper calls and the reload.
  auto bytes = downloadArithmeticFixture("c1e00229cac1fa02");
  auto report = Discover(bytes);
  check(report.ready() && report.gates.size() == 4 && has(report, InstallVerifier) && has(report, CrxDownload),
        "unrelated register shifts preserve the verified download decision");
  for (auto mutation : {std::pair{"c1e002", "c1e402"}, {"c1fa02", "c1fc02"}, {"29ca", "29cc"},
                       {"c1e002", "c12002"}, {"29ca", "290a"}, {"c1fa02", "c1c002"}, {"c1fa02", "c0fa02"}}) {
    auto changed = bytes;
    replace(changed, mutation.first, mutation.second);
    auto refused = Discover(changed);
    check(refused.ready() && refused.gates.size() == 3 && has(refused, InstallVerifier) && !has(refused, CrxDownload),
          "stack-pointer shifts and unmodeled arithmetic cannot prove a download slot");
  }
  for (auto arithmetic : {"8d442404c1e000c70000000000", "8d442404c1f800c70000000000",
                          "8d44240431c929c8c70000000000", "89e131c029c8", "29e0"}) {
    auto refused = Discover(downloadArithmeticFixture(arithmetic));
    check(refused.ready() && refused.gates.size() == 3 && has(refused, InstallVerifier) && !has(refused, CrxDownload),
          "unmodeled arithmetic cannot discard a stack-derived address and hide an overlapping write");
  }
  application(bytes);
}
static Bytes downloadReceiverFixture(const char* arithmetic = "") {
  auto bytes = fixture(); Bytes code;
  auto emit = [&](const char* text) { auto part = hex(text); code.insert(code.end(), part.begin(), part.end()); };
  auto call = [&](uint32_t target) {
    int32_t displacement = target - (0x1500 + static_cast<uint32_t>(code.size()) + 5);
    code.push_back(0xe8);
    for (unsigned n = 0; n < 4; ++n) code.push_back(static_cast<uint8_t>(displacement >> (n * 8)));
  };
  emit("5589e583ec28"); call(0x1640);
  emit("84c089ce740e8b442404c7802c010000020000008d44241050"); call(0x1660);
  emit("83c40450"); call(0x1680); emit(arithmetic);
  emit("8b742404"); call(0x1660);
  emit("89f789f98d44240850"); call(0x1400); emit("83c4285dc3");
  check(code.size() <= 0x100, "saved-receiver caller fits its fabricated function");
  std::fill(bytes.begin() + 0x900, bytes.begin() + 0xa00, 0xcc);
  std::copy(code.begin(), code.end(), bytes.begin() + 0x900);
  return bytes;
}
static void downloadReceiver() {
  auto bytes = downloadReceiverFixture("8d542408ff4200");
  auto report = Discover(bytes);
  check(report.ready() && report.gates.size() == 4 && has(report, CrxDownload),
        "TEST/MOV/JE and a receiver copied through preserved registers retain the download decision");
  for (auto arithmetic : {"8d542404ff4200", "8d54240266ff4202", "194c2404", "83c404"}) {
    auto found = Discover(downloadReceiverFixture(arithmetic));
    check(found.ready() && found.gates.size() == 3 && has(found, InstallVerifier) && !has(found, CrxDownload),
          "aliased INC/SBB writes, partial overlaps and stack adjustments cannot preserve the installer slot");
  }
  for (auto mutation : {std::pair{"84c089ce", "84c089c8"}, {"84c089ce", "84c001ce"},
                       {"89f789f9", "89d789f9"}, {"8b742404", "8b742408"}}) {
    auto changed = bytes;
    replace(changed, mutation.first, mutation.second);
    auto found = Discover(changed);
    check(found.ready() && found.gates.size() == 3 && has(found, InstallVerifier) && !has(found, CrxDownload),
          "result/flag clobbers and unrelated receiver copies cannot produce a download patch");
  }
  application(bytes);
}
static Bytes inlineFormatFixture() {
  auto bytes = downloadReceiverFixture();
  IMAGE_EXPORT_DIRECTORY exports{}; exports.Name = 0x4480;
  put(bytes, 0x1c00, exports);
  std::memcpy(bytes.data() + 0x1c80, "msedge.dll", sizeof("msedge.dll"));
  put<uint32_t>(bytes, 0xf8, 0x4400); put<uint32_t>(bytes, 0xfc, sizeof exports);
  Bytes code;
  auto emit = [&](const char* text) { auto part = hex(text); code.insert(code.end(), part.begin(), part.end()); };
  auto call = [&](uint32_t target) {
    int32_t displacement = target - (0x1400 + static_cast<uint32_t>(code.size()) + 5);
    code.push_back(0xe8);
    for (unsigned n = 0; n < 4; ++n) code.push_back(static_cast<uint8_t>(displacement >> (n * 8)));
  };
  emit("5589e583ec2089cf31f683b92c010000007514"); call(0x1640);
  emit("68a0414000"); call(0x1680); emit("be01000000");
  emit("8d55e08972089090909089f952"); call(0x1680); emit("83c4205dc20400");
  check(code.size() <= 0x100, "inline-format installer fits its fabricated function");
  std::fill(bytes.begin() + 0x800, bytes.begin() + 0x900, 0xcc);
  std::copy(code.begin(), code.end(), bytes.begin() + 0x800);
  return bytes;
}
static void inlineFormat() {
  auto bytes = inlineFormatFixture(); auto report = Discover(bytes);
  if (!report.ready()) std::fprintf(stderr, "inline format: provider=%.*s download=%.*s\n",
    static_cast<int>(report.installVerifier.size()), report.installVerifier.data(),
    static_cast<int>(report.crxDownload.size()), report.crxDownload.data());
  check(report.ready() && report.gates.size() == 2 && has(report, InstallVerifier) && has(report, CrxDownload),
        "Edge's inlined zero external format and named webstore format reach the same private request");
  auto formatTwo = bytes; replace(formatTwo, "be01000000", "be02000000");
  check(Discover(formatTwo).ready(), "both reviewed webstore verifier formats retain the external zero path");
  auto otherField = bytes; replace(otherField, "90909090", "ff420090");
  check(Discover(otherField).ready(), "a disjoint request-field update preserves the verified format field");
  auto inputRequest = bytes;
  replace(inputRequest, "8d55e0", "8d5508"); replace(inputRequest, "897208", "8972b0");
  check(!Discover(inputRequest).ready(), "a local format field cannot prove a request based in caller input slots");
  for (auto mutation : {std::pair{"be01000000", "be03000000"}, {"31f6", "31ff"},
                       {"8d55e0", "8d55fc"}, {"89f952", "89d952"},
                       {"90909090", "ff420890"}, {"90909090", "66ff420a"}, {"90909090", "83c40490"}}) {
    auto changed = bytes;
    replace(changed, mutation.first, mutation.second);
    auto found = Discover(changed);
    check(!found.ready() && has(found, InstallVerifier) && !has(found, CrxDownload),
          "unsupported formats, unproved zero, control-slot overlap and constructor alias changes decline Edge support");
  }
}
static void framedExternalVerifier() {
  auto bytes = fixture();
  auto body = hex("5589e531c05dc3");
  std::fill(bytes.begin() + 0xa00, bytes.begin() + 0xa40, 0xcc);
  std::copy(body.begin(), body.end(), bytes.begin() + 0xa00);
  auto report = Discover(bytes);
  check(report.ready() && report.gates.size() == 4 && has(report, InstallVerifier) && has(report, CrxDownload),
        "framed constant external verifier retains both optional decisions");
  for (auto text : {"5389e531c05dc3", "5589c531c05dc3", "5589e531c95dc3", "5589e531c05bc3",
                    "5589e531c0505dc3", "5589e531c083c0015dc3", "5589e5b0015dc3",
                    "5589e531c05dc20400"}) {
    auto changed = bytes, invalid = hex(text);
    std::fill(changed.begin() + 0xa00, changed.begin() + 0xa40, 0xcc);
    std::copy(invalid.begin(), invalid.end(), changed.begin() + 0xa00);
    auto found = Discover(changed);
    check(found.ready() && found.gates.size() == 3 && has(found, InstallVerifier) && !has(found, CrxDownload),
          "wrong frame, result or cleanup does not identify an external verifier");
  }
  // A terminal failure path can sit exactly at a trimmed callee's end. It
  // contributes no returning cleanup; conflicting returns and changed argument
  // cleanup must still decline the download decision.
  auto terminal = bytes, cleanup = hex("5589e585c075045dc20400cc");
  std::fill(terminal.begin() + 0xa80, terminal.begin() + 0xac0, 0xcc);
  std::copy(cleanup.begin(), cleanup.end(), terminal.begin() + 0xa80);
  auto found = Discover(terminal);
  check(found.ready() && found.gates.size() == 4 && has(found, InstallVerifier) && has(found, CrxDownload),
        "terminal trap at a callee boundary preserves the agreed stack cleanup");
  for (auto mutation : {std::pair{"0400cc", "0400c3"}, {"0400cc", "0800cc"}}) {
    auto changed = terminal, modified = cleanup;
    replace(modified, mutation.first, mutation.second);
    std::copy(modified.begin(), modified.end(), changed.begin() + 0xa80);
    auto refused = Discover(changed);
    check(refused.ready() && refused.gates.size() == 3 && has(refused, InstallVerifier) && !has(refused, CrxDownload),
          "conflicting or changed return cleanup cannot prove the download slot");
  }
  application(terminal);
  application(bytes);
}
static void providerReload() {
  auto bytes = fixture();
  // Model Canary's fixed frame, security cookie, private local addresses and
  // high-byte diagnostic flags before reloading Extension* after a call.
  auto code = hex("5589e583ec208b15c041400031ea8955fc8d55e08955e4894ddce8c1030000"
                  "85c00f95c30f95c784fb751a8b4508f6807c010000087520894de889c1e87f030000"
                  "84c075128b550cc70200010000b00183c4205dc2080031c083c4205dc20800");
  std::fill(bytes.begin() + 0x680, bytes.begin() + 0x800, 0xcc);
  std::copy(code.begin(), code.end(), bytes.begin() + 0x680);
  put<uint32_t>(bytes, 0x1a00 + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SecurityCookie), 0x4041c0);
  put<uint32_t>(bytes, 0x19c0, 0x12345678);
  auto report = Discover(bytes);
  check(report.ready() && report.gates.size() == 4 && has(report, InstallVerifier) && has(report, CrxDownload),
        "Canary provider reload survives diagnostic calls and high-byte flags");
  check(MakePlan(report).offstoreRva == 0x12b5,
        "provider patch selects the existing verified branch and retains diagnostic checks");
  for (auto mutation : {
      std::pair{"8b4508f680", "8b450cf680"}, // A different incoming argument.
      {"894ddc", "894d08"},                 // Overwrite the incoming argument.
      {"894ddc", "894a28"},                 // Overwrite it through a local-address alias.
      {"894ddc", "894dfe"},                 // A store overlaps the saved frame pointer.
      {"8d55e0", "8d5508"},                 // Expose an incoming slot's address.
      {"894ddc", "890890"},                 // A store through an unbounded pointer.
      {"8b15c0414000", "8b15c4414000"},     // An XOR unrelated to the configured cookie.
      {"31ea", "31e2"},                     // Arithmetic with the stack pointer.
      {"5589e5", "5589e4"}}) {             // No fixed EBP frame.
    auto changed = bytes, modified = code;
    replace(modified, mutation.first, mutation.second);
    std::copy(modified.begin(), modified.end(), changed.begin() + 0x680);
    auto found = Discover(changed);
    if (!found.ready() || found.gates.size() != 3 || has(found, InstallVerifier) || !has(found, CrxDownload))
      std::fprintf(stderr, "provider mutation %s -> %s: ready=%u gates=%zu provider=%.*s download=%.*s\n",
                   mutation.first, mutation.second, found.ready(), found.gates.size(),
                   static_cast<int>(found.installVerifier.size()), found.installVerifier.data(),
                   static_cast<int>(found.crxDownload.size()), found.crxDownload.data());
    check(found.ready() && found.gates.size() == 3 && !has(found, InstallVerifier) && has(found, CrxDownload),
          "unsafe or unrelated provider reload declines without losing independent decisions");
  }
  application(bytes);
}
#endif
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
  edgeProviderResult();
  unsupportedBitField();
  astExclusion();
  for (auto mutation : {std::pair{"48218052", "68218052"}, {"44184a7a", "40184a7a"}, {"20119f1a", "20019f1a"}}) {
    auto changed = bytes; replace(changed, mutation.first, mutation.second);
    check(!Discover(changed).ready(), "changed membership, conditional flags or select cannot satisfy the MV2 predicate");
  }
#endif
  application(bytes);
#if defined(AUTOSCAN_X86)
  framedExternalVerifier();
  providerReload();
  largeDownloadCallee();
  downloadArithmetic();
  downloadReceiver();
  inlineFormat();
#endif
  std::printf("PASS: %u native optional checks\n", checks);
}
