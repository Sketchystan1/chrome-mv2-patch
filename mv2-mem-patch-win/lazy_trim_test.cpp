// Test the production raw-bound prescreen against its original trimmed path.
#include "autoscan.cpp"
#include <cstdio>
#include <cstdlib>

#if !defined(AUTOSCAN_X64)
#error The raw-bound prescreen is enabled only on native x64.
#endif

namespace {
unsigned checks = 0;
void check(bool value, const char* message) {
  ++checks;
  if (!value) { std::fprintf(stderr, "FAIL %u: %s\n", checks, message); std::exit(1); }
}
using Bytes = std::array<uint8_t, 0x1800>;
template<class T> void put(Bytes& bytes, size_t at, T value) { std::memcpy(bytes.data() + at, &value, sizeof(value)); }
Bytes fixture(std::span<const uint8_t> code, unsigned padding, bool traps, uint16_t machine = IMAGE_FILE_MACHINE_AMD64) {
  Bytes bytes{}; bool x86 = machine == IMAGE_FILE_MACHINE_I386;
  put<uint16_t>(bytes, 0, 0x5a4d); put<uint32_t>(bytes, 0x3c, 0x80); put<uint32_t>(bytes, 0x80, 0x4550);
  put<uint16_t>(bytes, 0x84, machine); put<uint16_t>(bytes, 0x86, 2); put<uint16_t>(bytes, 0x94, x86 ? 0xe0 : 0xf0);
  put<uint16_t>(bytes, 0x98, x86 ? 0x10b : 0x20b);
  if (x86) put<uint32_t>(bytes, 0xb4, 0x400000); else put<uint64_t>(bytes, 0xb0, 0x180000000);
  put<uint32_t>(bytes, 0xd0, 0x4000); put<uint32_t>(bytes, 0xd4, 0x400); put<uint32_t>(bytes, x86 ? 0xf4 : 0x104, 16);
  if (!x86) { put<uint32_t>(bytes, 0x120, 0x3000); put<uint32_t>(bytes, 0x124, 12); }
  IMAGE_SECTION_HEADER text{}, pdata{};
  std::memcpy(text.Name, ".text", 5); text.Misc.VirtualSize = text.SizeOfRawData = 0x1000;
  text.VirtualAddress = 0x1000; text.PointerToRawData = 0x400; text.Characteristics = 0x60000020;
  std::memcpy(pdata.Name, ".pdata", 6); pdata.Misc.VirtualSize = pdata.SizeOfRawData = 0x100;
  pdata.VirtualAddress = 0x3000; pdata.PointerToRawData = 0x1400; pdata.Characteristics = 0x40000040;
  size_t section = x86 ? 0x178 : 0x188; put(bytes, section, text); put(bytes, section + 40, pdata);
  put<uint32_t>(bytes, 0x1400, 0x1000); put<uint32_t>(bytes, 0x1404, 0x1000 + static_cast<uint32_t>(code.size()) + padding);
  put<uint32_t>(bytes, 0x1408, 0x300c); bytes[0x140c] = 1;
  std::fill_n(bytes.begin() + 0x400, 0x1000, uint8_t{0xcc});
  std::copy(code.begin(), code.end(), bytes.begin() + 0x400);
  std::fill_n(bytes.begin() + 0x400 + code.size(), padding, traps ? 0xcc : 0x90);
  return bytes;
}
void fallbackTests() {
  constexpr std::array<uint8_t, 1> ret{0xc3};
  auto bytes = fixture(ret, 4, true);
  put<uint32_t>(bytes, 0x120, 0); put<uint32_t>(bytes, 0x124, 0);
  std::memcpy(bytes.data() + 0x1b0, ".rdata\0", 7);
  autoscan::PeImage leafPe(bytes); autoscan::Boundaries leaf(leafPe);
  check(leafPe.valid() && !leaf.error && !leaf.find(0x1000, true) && leaf.find(0x1000).end == 0x1001,
        "raw hints do not bypass ordinary leaf recovery");
  bytes = fixture(ret, 4, true);
  put<uint32_t>(bytes, 0x1400, 0x1100); put<uint32_t>(bytes, 0x1404, 0x1101);
  autoscan::PeImage gapPe(bytes); autoscan::Boundaries gap(gapPe);
  check(!gap.error && !gap.find(0x1000, true) && gap.find(0x1000).end == 0x1001,
        "runtime-table gaps retain original leaf recovery");
  constexpr std::array<uint8_t, 4> prologue{0x55,0x89,0xe5,0xc3};
  bytes = fixture(prologue, 4, true, IMAGE_FILE_MACHINE_I386);
  autoscan::PeImage x86Pe(bytes); autoscan::Boundaries x86(x86Pe);
  check(x86Pe.valid() && !x86.error && !x86.find(0x1000, true) && x86.find(0x1000).end == 0x1004,
        "x86 prologue recovery has no raw-bound shortcut");
  bytes = fixture(ret, 4, true, IMAGE_FILE_MACHINE_ARM64);
  put<uint32_t>(bytes, 0x124, 8); put<uint32_t>(bytes, 0x1404, (2u << 2) | 1);
  put<uint32_t>(bytes, 0x400, 0xd65f03c0); put<uint32_t>(bytes, 0x404, 0xd4200000);
  autoscan::PeImage armPe(bytes); autoscan::Boundaries arm(armPe);
  check(armPe.valid() && !arm.error && !arm.find(0x1000, true) && arm.find(0x1000).end == 0x1004,
        "ARM64 table padding retains its original trimming");
}
}
int main() {
  constexpr std::array<uint8_t, 15> yes{0x83,0xf8,1,0x83,0xf8,3,0x83,0xf8,8,0x83,0xf8,5,0x83,0xf8,10};
  constexpr std::array<uint8_t, 9> no{0x83,0xf8,8,0x83,0xf8,5,0x83,0xf8,10};
  constexpr std::array<uint8_t, 3> bad{0xc5,0xf8,0x77};
  std::array<uint8_t, 20> immediate{}; std::copy(yes.begin(), yes.end(), immediate.begin());
  constexpr std::array<uint8_t, 5> move{0xb8,0x90,0xcc,0,0}; std::copy(move.begin(), move.end(), immediate.begin() + 15);
  std::array<uint8_t, 17> jump{}; std::copy(yes.begin(), yes.end(), jump.begin()); jump[15] = 0xeb;
  for (auto code : {std::span<const uint8_t>(yes), std::span<const uint8_t>(no), std::span<const uint8_t>(bad),
                    std::span<const uint8_t>(immediate), std::span<const uint8_t>(jump)})
    for (unsigned padding : {0u,1u,32u,240u,255u,256u,300u}) for (bool traps : {false,true}) {
      auto bytes = fixture(code, padding, traps); autoscan::PeImage pe(bytes); autoscan::Boundaries boundaries(pe);
      check(pe.valid() && !boundaries.error, "bounded PE/runtime-function fixture");
      auto raw = boundaries.find(0x1000, true), trimmed = boundaries.find(0x1000);
      check(raw.end == 0x1000 + code.size() + padding, "authoritative raw table range retains padding");
      bool complete = false; autoscan::Head head{0x1000,0x1000,0x1000,0xffffffff};
      bool preliminary = autoscan::prefilter(pe, head, raw, &complete), original = autoscan::prefilter(pe, head, trimmed);
      check(preliminary || !complete || !original, "complete raw rejection cannot discard an original accepted head");
      if (code.data() == yes.data() && padding == 300 && !traps)
        check(!preliminary && !complete && original, "padding traversal exhaustion falls back to original trimming");
      if (code.data() == bad.data()) check(!preliminary && !complete, "unsupported decoding is inconclusive");
      if (code.data() == immediate.data()) check(trimmed.end == 0x1000 + code.size(), "90/CC immediate bytes are preserved");
    }
  fallbackTests();
  std::printf("PASS: %u lazy-trim padding, overflow, immediate, decode and fallback checks\n", checks);
}
