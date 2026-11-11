// Directly test the production bounded reference collector/search on native encodings.
#include "autoscan.cpp"
#include <cstdio>
#include <cstdlib>

namespace {
unsigned checks = 0;
void check(bool ok) { ++checks; if (!ok) { std::fprintf(stderr, "Reference fixture failed at check %u\n", checks); std::exit(1); } }
using Bytes = std::array<uint8_t, 0x4400>;
template<class T> void put(Bytes& bytes, size_t at, T value) { memcpy(bytes.data() + at, &value, sizeof(value)); }
Bytes fixture(unsigned textSize) {
  Bytes bytes{}; bool x86 = autoscan::NativeMachine() == IMAGE_FILE_MACHINE_I386;
  put<uint16_t>(bytes, 0, 0x5a4d); put<uint32_t>(bytes, 0x3c, 0x80); put<uint32_t>(bytes, 0x80, 0x4550);
  put<uint16_t>(bytes, 0x84, autoscan::NativeMachine()); put<uint16_t>(bytes, 0x86, 2); put<uint16_t>(bytes, 0x94, x86 ? 0xe0 : 0xf0);
  put<uint16_t>(bytes, 0x98, x86 ? 0x10b : 0x20b);
  if (x86) put<uint32_t>(bytes, 0xb4, 0x400000); else put<uint64_t>(bytes, 0xb0, 0x180000000);
  put<uint32_t>(bytes, 0xd0, 0x6000); put<uint32_t>(bytes, 0xd4, 0x400); put<uint32_t>(bytes, x86 ? 0xf4 : 0x104, 16);
  IMAGE_SECTION_HEADER text{}, data{};
  memcpy(text.Name, ".text", 5); text.Misc.VirtualSize = textSize; text.VirtualAddress = 0x1000;
  text.SizeOfRawData = 0x3000; text.PointerToRawData = 0x400; text.Characteristics = 0x60000020;
  memcpy(data.Name, ".rdata", 6); data.Misc.VirtualSize = 0x1000; data.VirtualAddress = 0x5000;
  data.SizeOfRawData = 0x1000; data.PointerToRawData = 0x3400; data.Characteristics = 0x40000040;
  size_t table = x86 ? 0x178 : 0x188; put(bytes, table, text); put(bytes, table + 40, data);
  std::fill(bytes.begin() + 0x400, bytes.begin() + 0x3400, uint8_t{0xcc});
  memcpy(bytes.data() + 0x3400, "InstallVerifier", 16); memcpy(bytes.data() + 0x3440, "apps-gallery-url", 17);
  return bytes;
}
void reference(Bytes& bytes, unsigned offset, uint32_t literal) {
#if defined(AUTOSCAN_ARM64)
  uint32_t pc = 0x1000 + offset, pages = (literal >> 12) - (pc >> 12);
  put<uint32_t>(bytes, 0x400 + offset, 0x90000000 | ((pages & 3) << 29) | ((pages >> 2) << 5));
  put<uint32_t>(bytes, 0x404 + offset, 0x91000000 | ((literal & 0xfff) << 10));
#elif defined(AUTOSCAN_X86)
  bytes[0x400 + offset] = 0x68; put<uint32_t>(bytes, 0x401 + offset, 0x400000 + literal);
#else
  bytes[0x400 + offset] = 0x48; bytes[0x401 + offset] = 0x8d; bytes[0x402 + offset] = 5;
  put<int32_t>(bytes, 0x403 + offset, static_cast<int32_t>(literal - (0x1000 + offset + 7)));
#endif
}
void verify(Bytes& bytes, uint32_t literal, unsigned expected) {
  autoscan::PeImage pe(bytes); check(pe.valid()); autoscan::RefBatch batch(pe);
  autoscan::FixedList<uint32_t, 64> found;
  check(autoscan::references(pe, literal, found, batch) == (expected <= 64));
  check(found.size() == std::min(expected, 64u));
}
}
int main() {
  constexpr unsigned length = autoscan::NativeMachine() == IMAGE_FILE_MACHINE_ARM64 ? 8 : autoscan::NativeMachine() == IMAGE_FILE_MACHINE_I386 ? 5 : 7;
  for (unsigned size : {7u, 8u, 18u, 19u, 20u, 31u, 32u, 33u, 63u, 64u, 65u, 128u})
    for (unsigned offset : {0u, 1u, 2u, 15u, 16u, 31u, 32u}) {
      if (offset + length > size || (length == 8 && (offset & 3)) || (length == 5 && !offset)) continue;
      auto bytes = fixture(size); reference(bytes, offset, 0x5000); verify(bytes, 0x5000, 1);
    }
  for (unsigned count : {0u, 1u, 63u, 64u, 65u, 80u}) {
    auto bytes = fixture(0x3000);
    for (unsigned n = 0; n < count; ++n) reference(bytes, n * 16 + (length == 5 ? 1 : 0), 0x5000);
    reference(bytes, 0x2000 + (length == 5 ? 1 : 0), 0x5040);
    autoscan::PeImage pe(bytes); autoscan::RefBatch batch(pe); autoscan::FixedList<uint32_t, 64> a, b;
    check(autoscan::references(pe, 0x5000, a, batch) == (count <= 64)); check(a.size() == std::min(count, 64u));
    check(autoscan::references(pe, 0x5040, b, batch) && b.size() == 1);
  }
  auto bytes = fixture(64); reference(bytes, length == 5 ? 1 : 0, 0x5800);
  verify(bytes, 0x5800, 1);
  std::fill(bytes.begin() + 0x3400, bytes.end(), uint8_t{0}); verify(bytes, 0x5800, 1);
  for (unsigned n = 0; n < 17; ++n) memcpy(bytes.data() + 0x3400 + n * 16, "InstallVerifier", 16);
  autoscan::PeImage crowded(bytes); autoscan::RefBatch ambiguous(crowded); check(ambiguous.providerAmbiguous && !ambiguous.providerCount);
  bytes = fixture(64); memcpy(bytes.data() + 0x3480, "apps-gallery-url", 17);
  autoscan::PeImage duplicate(bytes); autoscan::RefBatch gallery(duplicate); check(gallery.galleryAmbiguous && !gallery.gallery && gallery.providerCount == 1);
  std::printf("PASS: %u native reference tail, overflow, fallback and ambiguous-name checks\n", checks);
}
